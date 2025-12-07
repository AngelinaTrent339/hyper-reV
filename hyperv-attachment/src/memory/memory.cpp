#include "memory.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../process/process.h"
#include "../slat/cr3/cr3.h"
#include "../slat/slat.h"

namespace memory_analysis {
// ========================================================================
// VAD ENUMERATION
// Walk the VAD AVL tree to enumerate all memory regions
// ========================================================================

// Helper to read guest virtual memory
static bool read_guest_virt(std::uint64_t target_cr3, std::uint64_t va,
                            void *buffer, std::uint64_t size) {
  const cr3 slat_cr3 = slat::hyperv_cr3();
  std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
      {.flags = target_cr3}, slat_cr3, {.address = va});
  if (gpa == 0)
    return false;

  std::uint64_t size_left = 0;
  void *mapped = memory_manager::map_guest_physical(slat_cr3, gpa, &size_left);
  if (!mapped || size_left < size)
    return false;

  crt::copy_memory(buffer, mapped, size);
  return true;
}

// Helper to walk VAD tree recursively
static void walk_vad_tree(std::uint64_t target_cr3, std::uint64_t vad_node,
                          vad_info_t *buffer, std::uint64_t max_count,
                          std::uint64_t &current_index) {
  if (vad_node == 0 || current_index >= max_count)
    return;

  const auto &offsets = process::g_offsets;

  // Read VAD node data
  // MMVAD_SHORT at vad_node:
  // - Left child at offset 0 (RTL_BALANCED_NODE.Left)
  // - Right child at offset 8 (RTL_BALANCED_NODE.Right)
  // - StartingVpn at 0x18
  // - EndingVpn at 0x1c
  // - StartingVpnHigh at 0x20
  // - EndingVpnHigh at 0x21
  // - VadFlags (u.LongFlags) at 0x30

  std::uint64_t left_child = 0;
  std::uint64_t right_child = 0;
  std::uint32_t starting_vpn = 0;
  std::uint32_t ending_vpn = 0;
  std::uint8_t starting_vpn_high = 0;
  std::uint8_t ending_vpn_high = 0;
  std::uint32_t vad_flags = 0;

  // Read left/right children
  read_guest_virt(target_cr3, vad_node + offsets.vad_Left, &left_child,
                  sizeof(left_child));
  read_guest_virt(target_cr3, vad_node + offsets.vad_Right, &right_child,
                  sizeof(right_child));

  // Read VPN info
  read_guest_virt(target_cr3, vad_node + offsets.vad_StartingVpn, &starting_vpn,
                  sizeof(starting_vpn));
  read_guest_virt(target_cr3, vad_node + offsets.vad_EndingVpn, &ending_vpn,
                  sizeof(ending_vpn));
  read_guest_virt(target_cr3, vad_node + offsets.vad_StartingVpnHigh,
                  &starting_vpn_high, sizeof(starting_vpn_high));
  read_guest_virt(target_cr3, vad_node + offsets.vad_EndingVpnHigh,
                  &ending_vpn_high, sizeof(ending_vpn_high));
  read_guest_virt(target_cr3, vad_node + offsets.vad_VadFlags, &vad_flags,
                  sizeof(vad_flags));

  // Calculate full virtual addresses (VPN * 4KB)
  std::uint64_t start_addr =
      (static_cast<std::uint64_t>(starting_vpn_high) << 32 | starting_vpn)
      << 12;
  std::uint64_t end_addr =
      ((static_cast<std::uint64_t>(ending_vpn_high) << 32 | ending_vpn) << 12) +
      0xFFF;

  // Fill buffer entry
  buffer[current_index].start_address = start_addr;
  buffer[current_index].end_address = end_addr;
  buffer[current_index].protection =
      (vad_flags >> 3) & 0x1F; // VadFlags.Protection
  buffer[current_index].vad_type = (vad_flags >> 8) & 0x7; // VadFlags.VadType
  buffer[current_index].is_private =
      (vad_flags >> 11) & 1; // VadFlags.PrivateMemory
  buffer[current_index].commit_charge =
      vad_flags & 0x7; // VadFlags.CommitCharge (low bits)
  current_index++;

  // Walk left subtree
  if (left_child != 0)
    walk_vad_tree(target_cr3, left_child, buffer, max_count, current_index);

  // Walk right subtree
  if (right_child != 0)
    walk_vad_tree(target_cr3, right_child, buffer, max_count, current_index);
}

std::uint64_t enumerate_vad(std::uint64_t target_cr3, std::uint64_t vad_root,
                            vad_info_t *buffer, std::uint64_t max_count) {
  if (vad_root == 0 || buffer == nullptr || max_count == 0)
    return 0;

  std::uint64_t count = 0;

  // VAD root is RTL_AVL_TREE which just contains a pointer to root node
  std::uint64_t root_node = 0;
  read_guest_virt(target_cr3, vad_root, &root_node, sizeof(root_node));

  if (root_node != 0) {
    walk_vad_tree(target_cr3, root_node, buffer, max_count, count);
  }

  return count;
}

// ========================================================================
// MEMORY READING
// ========================================================================

std::uint64_t read_memory(std::uint64_t target_cr3,
                          std::uint64_t virtual_address, void *buffer,
                          std::uint64_t size) {
  const cr3 slat_cr3 = slat::hyperv_cr3();
  std::uint64_t bytes_read = 0;
  std::uint8_t *dst = static_cast<std::uint8_t *>(buffer);

  while (bytes_read < size) {
    std::uint64_t remaining = size - bytes_read;
    std::uint64_t current_va = virtual_address + bytes_read;

    // Translate to guest physical
    std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
        {.flags = target_cr3}, slat_cr3, {.address = current_va});

    if (gpa == 0)
      break;

    // Calculate how much we can read from this page
    std::uint64_t page_offset = current_va & 0xFFF;
    std::uint64_t page_remaining = 0x1000 - page_offset;
    std::uint64_t to_read =
        (remaining < page_remaining) ? remaining : page_remaining;

    // Map and copy
    std::uint64_t size_left = 0;
    void *mapped =
        memory_manager::map_guest_physical(slat_cr3, gpa, &size_left);
    if (!mapped || size_left < to_read)
      break;

    crt::copy_memory(dst + bytes_read, mapped, to_read);
    bytes_read += to_read;
  }

  return bytes_read;
}

// ========================================================================
// PATTERN COMPARISON
// ========================================================================

bool compare_pattern(std::uint64_t target_cr3, std::uint64_t virtual_address,
                     const std::uint8_t *pattern, const std::uint8_t *mask,
                     std::uint64_t pattern_length) {
  std::uint8_t buffer[256];
  if (pattern_length > sizeof(buffer))
    return false;

  if (read_memory(target_cr3, virtual_address, buffer, pattern_length) !=
      pattern_length)
    return false;

  for (std::uint64_t i = 0; i < pattern_length; i++) {
    if (mask != nullptr && mask[i] == '?')
      continue; // Wildcard
    if (buffer[i] != pattern[i])
      return false;
  }

  return true;
}

// ========================================================================
// PATTERN SCANNING
// ========================================================================

std::uint64_t
scan_pattern(std::uint64_t target_cr3, std::uint64_t start_address,
             std::uint64_t size, const std::uint8_t *pattern,
             const std::uint8_t *mask, std::uint64_t pattern_length,
             pattern_result_t *results, std::uint64_t max_results) {
  if (pattern == nullptr || pattern_length == 0 || results == nullptr ||
      max_results == 0)
    return 0;

  std::uint64_t found = 0;
  std::uint8_t page_buffer[0x1000];

  // Scan page by page for efficiency
  for (std::uint64_t offset = 0; offset < size && found < max_results;
       offset += 0x1000) {
    std::uint64_t current_addr = start_address + offset;
    std::uint64_t remaining = size - offset;
    std::uint64_t to_scan = (remaining < 0x1000) ? remaining : 0x1000;

    // Read the page
    if (read_memory(target_cr3, current_addr, page_buffer, to_scan) != to_scan)
      continue; // Skip unreadable pages

    // Scan within this page
    for (std::uint64_t i = 0;
         i + pattern_length <= to_scan && found < max_results; i++) {
      bool match = true;
      for (std::uint64_t j = 0; j < pattern_length; j++) {
        if (mask != nullptr && mask[j] == '?')
          continue;
        if (page_buffer[i + j] != pattern[j]) {
          match = false;
          break;
        }
      }

      if (match) {
        results[found].address = current_addr + i;
        results[found].offset_from_start = offset + i;
        found++;
      }
    }
  }

  return found;
}

// Helper to parse hex string like "48 8B ? ? 90"
static std::uint64_t parse_pattern_string(const char *str,
                                          std::uint8_t *pattern,
                                          std::uint8_t *mask,
                                          std::uint64_t max_len) {
  std::uint64_t len = 0;
  const char *p = str;

  while (*p && len < max_len) {
    // Skip spaces
    while (*p == ' ')
      p++;
    if (!*p)
      break;

    if (*p == '?') {
      pattern[len] = 0;
      mask[len] = '?';
      p++;
      if (*p == '?')
        p++; // Handle "??" as single wildcard
    } else {
      // Parse hex byte
      std::uint8_t byte = 0;
      for (int i = 0; i < 2 && *p; i++) {
        byte <<= 4;
        if (*p >= '0' && *p <= '9')
          byte |= (*p - '0');
        else if (*p >= 'A' && *p <= 'F')
          byte |= (*p - 'A' + 10);
        else if (*p >= 'a' && *p <= 'f')
          byte |= (*p - 'a' + 10);
        p++;
      }
      pattern[len] = byte;
      mask[len] = 'x';
    }
    len++;
  }

  return len;
}

std::uint64_t
scan_pattern_string(std::uint64_t target_cr3, std::uint64_t start_address,
                    std::uint64_t size, const char *pattern_string,
                    pattern_result_t *results, std::uint64_t max_results) {
  std::uint8_t pattern[256];
  std::uint8_t mask[256];

  std::uint64_t len =
      parse_pattern_string(pattern_string, pattern, mask, sizeof(pattern));
  if (len == 0)
    return 0;

  return scan_pattern(target_cr3, start_address, size, pattern, mask, len,
                      results, max_results);
}

// ========================================================================
// MODULE DUMPING
// ========================================================================

std::uint64_t dump_module(std::uint64_t target_cr3, std::uint64_t module_base,
                          std::uint64_t module_size, void *buffer,
                          std::uint64_t buffer_size) {
  std::uint64_t to_dump =
      (module_size < buffer_size) ? module_size : buffer_size;
  return read_memory(target_cr3, module_base, buffer, to_dump);
}

bool get_pe_headers(std::uint64_t target_cr3, std::uint64_t module_base,
                    void *header_buffer, std::uint64_t buffer_size) {
  // Read DOS header first (64 bytes minimum)
  if (buffer_size < 64)
    return false;

  if (read_memory(target_cr3, module_base, header_buffer, buffer_size) == 0)
    return false;

  std::uint8_t *buf = static_cast<std::uint8_t *>(header_buffer);

  // Check DOS signature "MZ"
  if (buf[0] != 'M' || buf[1] != 'Z')
    return false;

  // Get e_lfanew (offset to PE header) at offset 0x3C
  std::uint32_t e_lfanew = *reinterpret_cast<std::uint32_t *>(buf + 0x3C);

  // Check PE signature at e_lfanew
  if (e_lfanew + 4 > buffer_size)
    return false;

  if (buf[e_lfanew] != 'P' || buf[e_lfanew + 1] != 'E' ||
      buf[e_lfanew + 2] != 0 || buf[e_lfanew + 3] != 0)
    return false;

  return true;
}
} // namespace memory_analysis
