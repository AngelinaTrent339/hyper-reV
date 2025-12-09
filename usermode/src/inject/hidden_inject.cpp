#include "hidden_inject.h"
#include "../hypercall/hypercall.h"
#include "../util/console.h"

#include <TlHelp32.h>
#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <print>
#include <thread>


namespace hidden_inject {

// Storage for injected DLLs
static std::vector<injection_info_t> g_injected_dlls;

// =============================================================================
// PE PARSING HELPERS
// =============================================================================

struct pe_headers_t {
  PIMAGE_DOS_HEADER dos;
  PIMAGE_NT_HEADERS64 nt;
  PIMAGE_SECTION_HEADER sections;
  uint32_t section_count;
};

bool parse_pe_headers(const std::vector<uint8_t> &dll_data,
                      pe_headers_t *headers) {
  if (dll_data.size() < sizeof(IMAGE_DOS_HEADER)) {
    return false;
  }

  headers->dos = (PIMAGE_DOS_HEADER)dll_data.data();

  // Check DOS signature
  if (headers->dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return false;
  }

  // Check NT headers offset
  if (headers->dos->e_lfanew <= 0 ||
      static_cast<size_t>(headers->dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
          dll_data.size()) {
    return false;
  }

  headers->nt = (PIMAGE_NT_HEADERS64)(dll_data.data() + headers->dos->e_lfanew);

  // Check NT signature
  if (headers->nt->Signature != IMAGE_NT_SIGNATURE) {
    return false;
  }

  // Check if x64
  if (headers->nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
    return false;
  }

  // Must be a DLL
  if (!(headers->nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
    return false;
  }

  headers->section_count = headers->nt->FileHeader.NumberOfSections;
  headers->sections = IMAGE_FIRST_SECTION(headers->nt);

  return true;
}

// =============================================================================
// PUBLIC API IMPLEMENTATION
// =============================================================================

std::vector<uint8_t> load_dll_file(const std::string &path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);

  if (!file.is_open()) {
    return {};
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(static_cast<size_t>(size));

  if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
    return {};
  }

  return buffer;
}

bool validate_dll(const std::vector<uint8_t> &dll_data) {
  pe_headers_t headers = {};
  return parse_pe_headers(dll_data, &headers);
}

uint64_t get_required_size(const std::vector<uint8_t> &dll_data) {
  pe_headers_t headers = {};
  if (!parse_pe_headers(dll_data, &headers)) {
    return 0;
  }

  return headers.nt->OptionalHeader.SizeOfImage;
}

uint64_t get_preferred_base(const std::vector<uint8_t> &dll_data) {
  pe_headers_t headers = {};
  if (!parse_pe_headers(dll_data, &headers)) {
    return 0;
  }

  return headers.nt->OptionalHeader.ImageBase;
}

inject_result_t inject_hidden_dll(const std::vector<uint8_t> &dll_data,
                                  uint64_t target_cr3, uint64_t preferred_base,
                                  bool call_entry, injection_info_t *info) {
  // Parse PE headers
  pe_headers_t pe = {};
  if (!parse_pe_headers(dll_data, &pe)) {
    return inject_result_t::invalid_dll;
  }

  // Get image size and calculate pages needed
  uint64_t image_size = pe.nt->OptionalHeader.SizeOfImage;
  uint32_t pages_needed = static_cast<uint32_t>((image_size + 0xFFF) / 0x1000);

  // Use preferred base or DLL's ImageBase
  uint64_t image_base =
      (preferred_base != 0) ? preferred_base : pe.nt->OptionalHeader.ImageBase;

  console::info(std::format("Injecting DLL: {} pages ({} KB) at base 0x{:X}",
                            pages_needed, (pages_needed * 4), image_base));

  // Step 1: Allocate hidden region
  uint64_t region_id = hypercall::hidden_alloc_region(pages_needed);
  if (region_id == 0) {
    console::error("Failed to allocate hidden region");
    return inject_result_t::allocation_failed;
  }

  console::success(std::format("Allocated hidden region ID: {}", region_id));

  // Step 2: Map PE sections into hidden memory
  // First, copy headers
  uint64_t headers_size = pe.nt->OptionalHeader.SizeOfHeaders;

  std::vector<uint8_t> mapped_image(image_size, 0);

  // Copy headers
  memcpy(mapped_image.data(), dll_data.data(), headers_size);

  // Copy each section
  for (uint32_t i = 0; i < pe.section_count; i++) {
    PIMAGE_SECTION_HEADER section = &pe.sections[i];

    if (section->SizeOfRawData == 0)
      continue;

    // Source: file offset
    uint32_t file_offset = section->PointerToRawData;
    uint32_t file_size = section->SizeOfRawData;

    // Destination: virtual address (relative to image base)
    uint32_t va = section->VirtualAddress;

    if (file_offset + file_size > dll_data.size()) {
      console::error(std::format("Section {} has invalid file offset", i));
      hypercall::hidden_free_region(region_id);
      return inject_result_t::mapping_failed;
    }

    if (va + file_size > image_size) {
      console::error(std::format("Section {} has invalid virtual address", i));
      hypercall::hidden_free_region(region_id);
      return inject_result_t::mapping_failed;
    }

    memcpy(mapped_image.data() + va, dll_data.data() + file_offset, file_size);

    char section_name[9] = {};
    memcpy(section_name, section->Name, 8);
    console::info(std::format("  Mapped section: {} -> RVA 0x{:X} ({} bytes)",
                              section_name, va, file_size));
  }

  // Step 3: Process relocations (if base address changed)
  uint64_t original_base = pe.nt->OptionalHeader.ImageBase;
  int64_t delta =
      static_cast<int64_t>(image_base) - static_cast<int64_t>(original_base);

  if (delta != 0) {
    console::info(
        std::format("Processing relocations (delta = 0x{:X})", delta));

    // Get relocation directory
    auto &reloc_dir =
        pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0) {
      uint8_t *reloc_ptr = mapped_image.data() + reloc_dir.VirtualAddress;
      uint8_t *reloc_end = reloc_ptr + reloc_dir.Size;

      while (reloc_ptr < reloc_end) {
        auto *block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reloc_ptr);

        if (block->SizeOfBlock == 0)
          break;

        uint32_t entry_count =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
            sizeof(uint16_t);
        uint16_t *entries = reinterpret_cast<uint16_t *>(
            reloc_ptr + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < entry_count; i++) {
          uint16_t type = entries[i] >> 12;
          uint16_t offset = entries[i] & 0xFFF;

          if (type == IMAGE_REL_BASED_DIR64) {
            uint64_t *addr = reinterpret_cast<uint64_t *>(
                mapped_image.data() + block->VirtualAddress + offset);
            *addr += delta;
          }
        }

        reloc_ptr += block->SizeOfBlock;
      }
    }
  }

  // Step 4: Write mapped image to hidden region
  uint64_t written = hypercall::hidden_write_region(
      region_id, 0, mapped_image.data(), mapped_image.size());

  if (written != mapped_image.size()) {
    console::error(std::format("Failed to write image: {} of {} bytes", written,
                               mapped_image.size()));
    hypercall::hidden_free_region(region_id);
    return inject_result_t::mapping_failed;
  }

  console::success(std::format("Wrote {} bytes to hidden region", written));

  // Step 5: Expose region to target process
  uint64_t expose_result =
      hypercall::hidden_expose_region(region_id, image_base, target_cr3, true);

  if (expose_result != 1) {
    console::error("Failed to expose region to target process");
    hypercall::hidden_free_region(region_id);
    return inject_result_t::execution_failed;
  }

  console::success(std::format("Region exposed to CR3=0x{:X} at VA=0x{:X}",
                               target_cr3, image_base));

  // Calculate entry point
  uint64_t entry_point = image_base + pe.nt->OptionalHeader.AddressOfEntryPoint;

  // Fill info structure
  if (info != nullptr) {
    info->region_id = region_id;
    info->image_base = image_base;
    info->entry_point = entry_point;
    info->size_of_image = image_size;
    info->target_cr3 = target_cr3;
    info->is_exposed = true;
  }

  // Store in our list
  injection_info_t stored_info = {.region_id = region_id,
                                  .image_base = image_base,
                                  .entry_point = entry_point,
                                  .size_of_image = image_size,
                                  .target_cr3 = target_cr3,
                                  .is_exposed = true};
  g_injected_dlls.push_back(stored_info);

  console::separator("Injection Complete");
  std::println("  Region ID:    {}", region_id);
  std::println("  Image Base:   0x{:016X}", image_base);
  std::println("  Entry Point:  0x{:016X}", entry_point);
  std::println("  Size:         {} bytes ({} pages)", image_size, pages_needed);
  std::println("  Target CR3:   0x{:X}", target_cr3);
  console::separator();

  // Note: Calling DllMain requires additional work:
  // - Resolving imports (ntdll, kernel32, etc)
  // - Creating a thread in target process to call entry point
  // - This is complex and left to the user for now

  if (call_entry) {
    console::warn("Note: Automatic DllMain call not implemented");
    console::info("To execute, create a remote thread at entry point");
    console::info(std::format("  Entry: 0x{:X}", entry_point));
  }

  return inject_result_t::success;
}

inject_result_t hide_dll(uint64_t region_id) {
  uint64_t result = hypercall::hidden_hide_region(region_id);

  if (result != 1) {
    return inject_result_t::execution_failed;
  }

  // Update our tracking
  for (auto &dll : g_injected_dlls) {
    if (dll.region_id == region_id) {
      dll.is_exposed = false;
      break;
    }
  }

  return inject_result_t::success;
}

inject_result_t expose_dll(uint64_t region_id, uint64_t target_cr3) {
  // Find the DLL info
  injection_info_t *dll_info = nullptr;
  for (auto &dll : g_injected_dlls) {
    if (dll.region_id == region_id) {
      dll_info = &dll;
      break;
    }
  }

  if (dll_info == nullptr) {
    return inject_result_t::invalid_dll;
  }

  uint64_t result = hypercall::hidden_expose_region(
      region_id, dll_info->image_base, target_cr3, true);

  if (result != 1) {
    return inject_result_t::execution_failed;
  }

  dll_info->is_exposed = true;
  dll_info->target_cr3 = target_cr3;

  return inject_result_t::success;
}

inject_result_t eject_dll(uint64_t region_id) {
  uint64_t result = hypercall::hidden_free_region(region_id);

  if (result != 1) {
    return inject_result_t::execution_failed;
  }

  // Remove from our tracking
  g_injected_dlls.erase(
      std::remove_if(g_injected_dlls.begin(), g_injected_dlls.end(),
                     [region_id](const injection_info_t &dll) {
                       return dll.region_id == region_id;
                     }),
      g_injected_dlls.end());

  return inject_result_t::success;
}

std::vector<injection_info_t> get_injected_dlls() { return g_injected_dlls; }

uint64_t find_process_cr3(const std::string &process_name,
                          uint32_t timeout_ms) {
  // Try to find process ID first
  uint64_t pid = 0;

  // Use Windows API to find process
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return 0;
  }

  PROCESSENTRY32W pe = {};
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(snapshot, &pe)) {
    do {
      // Convert wide string to narrow for comparison
      std::wstring wide_name(pe.szExeFile);
      std::string narrow_name(wide_name.begin(), wide_name.end());

      // Case-insensitive comparison
      if (_stricmp(narrow_name.c_str(), process_name.c_str()) == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &pe));
  }

  CloseHandle(snapshot);

  if (pid == 0) {
    console::error(std::format("Process '{}' not found", process_name));
    return 0;
  }

  console::info(
      std::format("Found process '{}' with PID {}", process_name, pid));

  // Set up tracking for this PID
  hypercall::set_tracked_pid(pid);

  // Wait for CR3 capture
  auto start = std::chrono::steady_clock::now();
  uint64_t cr3 = 0;

  while (true) {
    cr3 = hypercall::get_tracked_cr3();

    if (cr3 != 0) {
      console::success(std::format("Captured CR3: 0x{:X}", cr3));
      break;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    if (elapsed.count() >= timeout_ms) {
      console::error("Timeout waiting for process CR3");
      hypercall::clear_tracked_pid();
      return 0;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  hypercall::clear_tracked_pid();
  return cr3;
}

} // namespace hidden_inject
