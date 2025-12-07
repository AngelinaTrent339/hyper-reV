#include "process.h"
#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../slat/cr3/cr3.h"
#include "../slat/slat.h"


namespace process {
// Global state
std::uint64_t g_target_cr3 = 0;
windows_offsets_t g_offsets = {};
bool g_offsets_initialized = false;

// ========================================================================
// PROCESS TARGETING
// ========================================================================

void attach(std::uint64_t cr3) { g_target_cr3 = cr3; }

void detach() { g_target_cr3 = 0; }

bool is_target_context() {
  if (g_target_cr3 == 0)
    return true; // No target = all processes match

  const cr3 guest_cr3 = arch::get_guest_cr3();
  return guest_cr3.flags == g_target_cr3;
}

std::uint64_t get_target_cr3() { return g_target_cr3; }

// ========================================================================
// PROCESS ENUMERATION
// ========================================================================

void set_offsets(const windows_offsets_t &offsets) {
  crt::copy_memory(&g_offsets, &offsets, sizeof(windows_offsets_t));
  g_offsets_initialized = true;
}

// Helper: Read guest physical memory
template <typename T> bool read_guest_physical(std::uint64_t gpa, T *out) {
  const cr3 slat_cr3 = slat::hyperv_cr3();
  std::uint64_t size_left = 0;

  void *mapped = memory_manager::map_guest_physical(slat_cr3, gpa, &size_left);
  if (!mapped || size_left < sizeof(T))
    return false;

  crt::copy_memory(out, mapped, sizeof(T));
  return true;
}

// Helper: Read guest virtual memory
template <typename T>
bool read_guest_virtual(std::uint64_t cr3_val, std::uint64_t gva, T *out) {
  const cr3 guest_cr3 = {.flags = cr3_val};
  const cr3 slat_cr3 = slat::hyperv_cr3();

  std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
      guest_cr3, slat_cr3, {.address = gva});

  if (gpa == 0)
    return false;

  return read_guest_physical(gpa, out);
}

// Helper: Read string from guest memory
bool read_guest_string(std::uint64_t cr3_val, std::uint64_t gva, char *buffer,
                       std::uint64_t max_len) {
  const cr3 guest_cr3 = {.flags = cr3_val};
  const cr3 slat_cr3 = slat::hyperv_cr3();

  for (std::uint64_t i = 0; i < max_len - 1; i++) {
    char c;
    std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = gva + i});

    if (gpa == 0) {
      buffer[i] = 0;
      return i > 0;
    }

    if (!read_guest_physical(gpa, &c)) {
      buffer[i] = 0;
      return i > 0;
    }

    buffer[i] = c;
    if (c == 0)
      return true;
  }

  buffer[max_len - 1] = 0;
  return true;
}

std::uint64_t find_by_name(const char *name) {
  if (!g_offsets_initialized || g_offsets.PsInitialSystemProcess == 0)
    return 0;

  // Read PsInitialSystemProcess to get first EPROCESS
  std::uint64_t first_eprocess = 0;
  const cr3 slat_cr3 = slat::hyperv_cr3();
  const cr3 kernel_cr3 = {.address_of_page_directory =
                              0x1AD000 >> 12}; // System CR3

  std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
      kernel_cr3, slat_cr3, {.address = g_offsets.PsInitialSystemProcess});

  if (gpa == 0 || !read_guest_physical(gpa, &first_eprocess))
    return 0;

  // Walk ActiveProcessLinks
  std::uint64_t current = first_eprocess;
  std::uint64_t list_head =
      first_eprocess + g_offsets.eprocess_ActiveProcessLinks;

  do {
    // Read ImageFileName
    char image_name[16] = {};
    std::uint64_t name_addr = current + g_offsets.eprocess_ImageFileName;

    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3, {.address = name_addr});

    if (gpa != 0) {
      read_guest_physical(gpa, &image_name);

      // Compare names (case insensitive)
      bool match = true;
      for (int i = 0; i < 15 && name[i] != 0; i++) {
        char c1 = image_name[i];
        char c2 = name[i];

        // Simple tolower
        if (c1 >= 'A' && c1 <= 'Z')
          c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z')
          c2 += 32;

        if (c1 != c2) {
          match = false;
          break;
        }
      }

      if (match) {
        // Found it - return DirectoryTableBase (CR3)
        std::uint64_t cr3_val = 0;
        std::uint64_t cr3_addr =
            current + g_offsets.eprocess_DirectoryTableBase;

        gpa = memory_manager::translate_guest_virtual_address(
            kernel_cr3, slat_cr3, {.address = cr3_addr});

        if (gpa != 0)
          read_guest_physical(gpa, &cr3_val);

        return cr3_val;
      }
    }

    // Move to next process
    std::uint64_t flink = 0;
    std::uint64_t flink_addr = current + g_offsets.eprocess_ActiveProcessLinks;

    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3, {.address = flink_addr});

    if (gpa == 0 || !read_guest_physical(gpa, &flink))
      break;

    // flink points to next EPROCESS.ActiveProcessLinks, convert to EPROCESS
    // base
    current = flink - g_offsets.eprocess_ActiveProcessLinks;

  } while (current != first_eprocess && current != 0);

  return 0; // Not found
}

std::uint64_t enumerate(process_info_t *buffer, std::uint64_t max_count) {
  if (!g_offsets_initialized || g_offsets.PsInitialSystemProcess == 0 ||
      max_count == 0)
    return 0;

  const cr3 slat_cr3 = slat::hyperv_cr3();
  const cr3 kernel_cr3 = {.address_of_page_directory = 0x1AD000 >> 12};

  // Read PsInitialSystemProcess
  std::uint64_t first_eprocess = 0;
  std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
      kernel_cr3, slat_cr3, {.address = g_offsets.PsInitialSystemProcess});

  if (gpa == 0 || !read_guest_physical(gpa, &first_eprocess))
    return 0;

  std::uint64_t count = 0;
  std::uint64_t current = first_eprocess;

  do {
    if (count >= max_count)
      break;

    process_info_t *info = &buffer[count];
    crt::set_memory(info, 0, sizeof(process_info_t));

    info->eprocess = current;

    // Read DirectoryTableBase (CR3)
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3,
        {.address = current + g_offsets.eprocess_DirectoryTableBase});
    if (gpa != 0)
      read_guest_physical(gpa, &info->cr3);

    // Read UniqueProcessId
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3,
        {.address = current + g_offsets.eprocess_UniqueProcessId});
    if (gpa != 0)
      read_guest_physical(gpa, &info->pid);

    // Read Peb
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3, {.address = current + g_offsets.eprocess_Peb});
    if (gpa != 0)
      read_guest_physical(gpa, &info->peb);

    // Read ImageFileName
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3,
        {.address = current + g_offsets.eprocess_ImageFileName});
    if (gpa != 0)
      read_guest_physical(gpa, &info->image_name);

    count++;

    // Move to next process
    std::uint64_t flink = 0;
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3,
        {.address = current + g_offsets.eprocess_ActiveProcessLinks});

    if (gpa == 0 || !read_guest_physical(gpa, &flink))
      break;

    current = flink - g_offsets.eprocess_ActiveProcessLinks;

  } while (current != first_eprocess && current != 0);

  return count;
}

bool get_info(std::uint64_t cr3_val, process_info_t *info) {
  if (!g_offsets_initialized || g_offsets.PsInitialSystemProcess == 0)
    return false;

  // Walk process list and find matching CR3
  constexpr std::uint64_t max_processes = 1024;
  // This is inefficient but safe - in production we'd cache this

  const cr3 slat_cr3 = slat::hyperv_cr3();
  const cr3 kernel_cr3 = {.address_of_page_directory = 0x1AD000 >> 12};

  std::uint64_t first_eprocess = 0;
  std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
      kernel_cr3, slat_cr3, {.address = g_offsets.PsInitialSystemProcess});

  if (gpa == 0 || !read_guest_physical(gpa, &first_eprocess))
    return false;

  std::uint64_t current = first_eprocess;
  std::uint64_t iterations = 0;

  do {
    if (++iterations > max_processes)
      break;

    // Read DirectoryTableBase
    std::uint64_t proc_cr3 = 0;
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3,
        {.address = current + g_offsets.eprocess_DirectoryTableBase});

    if (gpa != 0)
      read_guest_physical(gpa, &proc_cr3);

    if (proc_cr3 == cr3_val) {
      // Found it - fill info
      info->eprocess = current;
      info->cr3 = proc_cr3;

      gpa = memory_manager::translate_guest_virtual_address(
          kernel_cr3, slat_cr3,
          {.address = current + g_offsets.eprocess_UniqueProcessId});
      if (gpa != 0)
        read_guest_physical(gpa, &info->pid);

      gpa = memory_manager::translate_guest_virtual_address(
          kernel_cr3, slat_cr3, {.address = current + g_offsets.eprocess_Peb});
      if (gpa != 0)
        read_guest_physical(gpa, &info->peb);

      gpa = memory_manager::translate_guest_virtual_address(
          kernel_cr3, slat_cr3,
          {.address = current + g_offsets.eprocess_ImageFileName});
      if (gpa != 0)
        read_guest_physical(gpa, &info->image_name);

      return true;
    }

    // Next process
    std::uint64_t flink = 0;
    gpa = memory_manager::translate_guest_virtual_address(
        kernel_cr3, slat_cr3,
        {.address = current + g_offsets.eprocess_ActiveProcessLinks});

    if (gpa == 0 || !read_guest_physical(gpa, &flink))
      break;

    current = flink - g_offsets.eprocess_ActiveProcessLinks;

  } while (current != first_eprocess && current != 0);

  return false;
}

// ========================================================================
// MODULE ENUMERATION
// ========================================================================

std::uint64_t enumerate_modules(std::uint64_t cr3_val, std::uint64_t peb,
                                module_info_t *buffer,
                                std::uint64_t max_count) {
  if (!g_offsets_initialized || peb == 0 || max_count == 0)
    return 0;

  // Read PEB->Ldr
  std::uint64_t ldr = 0;
  if (!read_guest_virtual(cr3_val, peb + g_offsets.peb_Ldr, &ldr) || ldr == 0)
    return 0;

  // Read InLoadOrderModuleList.Flink
  std::uint64_t list_head = ldr + g_offsets.ldr_InLoadOrderModuleList;
  std::uint64_t flink = 0;

  if (!read_guest_virtual(cr3_val, list_head, &flink) || flink == 0)
    return 0;

  std::uint64_t count = 0;
  std::uint64_t current = flink;

  while (current != list_head && count < max_count) {
    // current points to LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
    std::uint64_t entry = current - g_offsets.ldr_entry_InLoadOrderLinks;

    module_info_t *mod = &buffer[count];
    crt::set_memory(mod, 0, sizeof(module_info_t));

    // Read DllBase
    read_guest_virtual(cr3_val, entry + g_offsets.ldr_entry_DllBase,
                       &mod->dll_base);

    // Read SizeOfImage
    read_guest_virtual(cr3_val, entry + g_offsets.ldr_entry_SizeOfImage,
                       &mod->size_of_image);

    // Read EntryPoint
    read_guest_virtual(cr3_val, entry + g_offsets.ldr_entry_EntryPoint,
                       &mod->entry_point);

    // Read BaseDllName (UNICODE_STRING)
    struct unicode_string_t {
      std::uint16_t Length;
      std::uint16_t MaximumLength;
      std::uint32_t pad;
      std::uint64_t Buffer;
    };

    unicode_string_t name_str = {};
    if (read_guest_virtual(cr3_val, entry + g_offsets.ldr_entry_BaseDllName,
                           &name_str)) {
      if (name_str.Buffer != 0 && name_str.Length > 0) {
        std::uint64_t chars_to_read = name_str.Length / 2;
        if (chars_to_read > 63)
          chars_to_read = 63;

        for (std::uint64_t i = 0; i < chars_to_read; i++) {
          wchar_t wc = 0;
          read_guest_virtual(cr3_val, name_str.Buffer + i * 2, &wc);
          mod->name[i] = wc;
        }
        mod->name[chars_to_read] = 0;
      }
    }

    if (mod->dll_base != 0)
      count++;

    // Next module
    if (!read_guest_virtual(cr3_val, current, &flink) || flink == 0)
      break;

    current = flink;
  }

  return count;
}

bool find_module(std::uint64_t cr3_val, std::uint64_t peb, const wchar_t *name,
                 module_info_t *info) {
  constexpr std::uint64_t max_modules = 256;
  module_info_t modules[max_modules];

  std::uint64_t count = enumerate_modules(cr3_val, peb, modules, max_modules);

  for (std::uint64_t i = 0; i < count; i++) {
    // Case-insensitive wide string compare
    bool match = true;
    for (int j = 0; j < 63; j++) {
      wchar_t c1 = modules[i].name[j];
      wchar_t c2 = name[j];

      if (c1 >= L'A' && c1 <= L'Z')
        c1 += 32;
      if (c2 >= L'A' && c2 <= L'Z')
        c2 += 32;

      if (c1 != c2) {
        match = false;
        break;
      }

      if (c1 == 0)
        break;
    }

    if (match) {
      crt::copy_memory(info, &modules[i], sizeof(module_info_t));
      return true;
    }
  }

  return false;
}

} // namespace process
