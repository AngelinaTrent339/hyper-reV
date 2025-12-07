#include "system.h"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "../commands/commands.h"
#include "../hook/hook.h"
#include "../hypercall/hypercall.h"


#include <portable_executable/image.hpp>

#include <Windows.h>
#include <intrin.h>
#include <print>
#include <vector>
#include <winternl.h>

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(
    std::uint32_t privilege, std::uint8_t enable, std::uint8_t current_thread,
    std::uint8_t *previous_enabled_state);

std::vector<std::uint8_t>
dump_kernel_module(std::uint64_t module_base_address) {
  constexpr std::uint64_t headers_size = 0x1000;

  std::vector<std::uint8_t> headers(headers_size);

  std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
      headers.data(), module_base_address, sys::current_cr3, headers_size);

  if (bytes_read != headers_size) {
    return {};
  }

  std::uint16_t magic = *reinterpret_cast<std::uint16_t *>(headers.data());

  if (magic != 0x5a4d) {
    return {};
  }

  const portable_executable::image_t *image =
      reinterpret_cast<portable_executable::image_t *>(headers.data());

  std::vector<std::uint8_t> image_buffer(
      image->nt_headers()->optional_header.size_of_image);

  memcpy(image_buffer.data(), headers.data(), 0x1000);

  for (const auto &current_section : image->sections()) {
    std::uint64_t read_offset = current_section.virtual_address;
    std::uint64_t read_size = current_section.virtual_size;

    hypercall::read_guest_virtual_memory(image_buffer.data() + read_offset,
                                         module_base_address + read_offset,
                                         sys::current_cr3, read_size);
  }

  return image_buffer;
}

std::uint64_t
find_kernel_detour_holder_base_address(portable_executable::image_t *ntoskrnl,
                                       std::uint64_t ntoskrnl_base_address) {
  for (const auto &current_section : ntoskrnl->sections()) {
    std::string_view current_section_name(current_section.name);

    if (current_section_name.contains("Pad") == true &&
        current_section.characteristics.mem_execute == 1) {
      return ntoskrnl_base_address + current_section.virtual_address;
    }
  }

  return 0;
}

std::unordered_map<std::string, std::uint64_t>
parse_module_exports(const portable_executable::image_t *image,
                     const std::string &module_name,
                     const std::uint64_t module_base_address) {
  std::unordered_map<std::string, std::uint64_t> exports = {};

  for (const auto &current_export : image->exports()) {
    std::string prefixed_export_name = module_name + "!" + current_export.name;
    std::string plain_export_name = current_export.name;

    std::uint64_t delta =
        reinterpret_cast<std::uint64_t>(current_export.address) -
        image->as<std::uint64_t>();
    std::uint64_t export_address = module_base_address + delta;

    exports[prefixed_export_name] = export_address;
    // Also add plain name for convenience (last one wins if duplicates across
    // modules)
    exports[plain_export_name] = export_address;
  }

  return exports;
}

void add_module_to_list(const std::string &module_name,
                        const std::vector<std::uint8_t> &module_dump,
                        const std::uint64_t module_base_address,
                        const std::uint32_t module_size) {
  sys::kernel_module_t kernel_module = {};

  const portable_executable::image_t *image =
      reinterpret_cast<const portable_executable::image_t *>(
          module_dump.data());

  kernel_module.exports =
      parse_module_exports(image, module_name, module_base_address);
  kernel_module.base_address = module_base_address;
  kernel_module.size = module_size;

  sys::kernel::modules_list[module_name] = kernel_module;
}

// Windows 11 24H2 syscall table - maps Nt* function names to syscall numbers
// This allows resolving internal syscall addresses without touching
// PG-protected structures
static const std::unordered_map<std::string, std::uint32_t>
    syscall_numbers_24h2 = {
        {"NtAccessCheck", 0},
        {"NtWorkerFactoryWorkerReady", 1},
        {"NtAcceptConnectPort", 2},
        {"NtMapUserPhysicalPagesScatter", 3},
        {"NtWaitForSingleObject", 4},
        {"NtCallbackReturn", 5},
        {"NtReadFile", 6},
        {"NtDeviceIoControlFile", 7},
        {"NtWriteFile", 8},
        {"NtRemoveIoCompletion", 9},
        {"NtReleaseSemaphore", 10},
        {"NtReplyWaitReceivePort", 11},
        {"NtReplyPort", 12},
        {"NtSetInformationThread", 13},
        {"NtSetEvent", 14},
        {"NtClose", 15},
        {"NtQueryObject", 16},
        {"NtQueryInformationFile", 17},
        {"NtOpenKey", 18},
        {"NtEnumerateValueKey", 19},
        {"NtFindAtom", 20},
        {"NtQueryDefaultLocale", 21},
        {"NtQueryKey", 22},
        {"NtQueryValueKey", 23},
        {"NtAllocateVirtualMemory", 24},
        {"NtQueryInformationProcess", 25},
        {"NtWaitForMultipleObjects32", 26},
        {"NtWriteFileGather", 27},
        {"NtSetInformationProcess", 28},
        {"NtCreateKey", 29},
        {"NtFreeVirtualMemory", 30},
        {"NtImpersonateClientOfPort", 31},
        {"NtReleaseMutant", 32},
        {"NtQueryInformationToken", 33},
        {"NtRequestWaitReplyPort", 34},
        {"NtQueryVirtualMemory", 35},
        {"NtOpenThreadToken", 36},
        {"NtQueryInformationThread", 37},
        {"NtOpenProcess", 38},
        {"NtSetInformationFile", 39},
        {"NtMapViewOfSection", 40},
        {"NtAccessCheckAndAuditAlarm", 41},
        {"NtUnmapViewOfSection", 42},
        {"NtReplyWaitReceivePortEx", 43},
        {"NtTerminateProcess", 44},
        {"NtSetEventBoostPriority", 45},
        {"NtReadFileScatter", 46},
        {"NtOpenThreadTokenEx", 47},
        {"NtOpenProcessTokenEx", 48},
        {"NtQueryPerformanceCounter", 49},
        {"NtEnumerateKey", 50},
        {"NtOpenFile", 51},
        {"NtDelayExecution", 52},
        {"NtQueryDirectoryFile", 53},
        {"NtQuerySystemInformation", 54},
        {"NtOpenSection", 55},
        {"NtQueryTimer", 56},
        {"NtFsControlFile", 57},
        {"NtWriteVirtualMemory", 58},
        {"NtCloseObjectAuditAlarm", 59},
        {"NtDuplicateObject", 60},
        {"NtQueryAttributesFile", 61},
        {"NtClearEvent", 62},
        {"NtReadVirtualMemory", 63},
        {"NtOpenEvent", 64},
        {"NtAdjustPrivilegesToken", 65},
        {"NtDuplicateToken", 66},
        {"NtContinue", 67},
        {"NtQueryDefaultUILanguage", 68},
        {"NtQueueApcThread", 69},
        {"NtYieldExecution", 70},
        {"NtAddAtom", 71},
        {"NtCreateEvent", 72},
        {"NtQueryVolumeInformationFile", 73},
        {"NtCreateSection", 74},
        {"NtFlushBuffersFile", 75},
        {"NtApphelpCacheControl", 76},
        {"NtCreateProcessEx", 77},
        {"NtCreateThread", 78},
        {"NtIsProcessInJob", 79},
        {"NtProtectVirtualMemory", 80},
        {"NtQuerySection", 81},
        {"NtResumeThread", 82},
        {"NtTerminateThread", 83},
        {"NtReadRequestData", 84},
        {"NtCreateFile", 85},
        {"NtQueryEvent", 86},
        {"NtWriteRequestData", 87},
        {"NtOpenDirectoryObject", 88},
        {"NtAccessCheckByTypeAndAuditAlarm", 89},
        {"NtQuerySystemTime", 90},
        {"NtWaitForMultipleObjects", 91},
        {"NtSetInformationObject", 92},
        {"NtCancelIoFile", 93},
        {"NtTraceEvent", 94},
        {"NtPowerInformation", 95},
        {"NtSetValueKey", 96},
        {"NtCancelTimer", 97},
        {"NtSetTimer", 98},
        // High-value syscalls for reversing
        {"NtRaiseHardError", 373},
        {"NtRaiseException", 372},
        {"NtSystemDebugControl", 464},
        {"NtCreateThreadEx", 201},
        {"NtCreateUserProcess", 209},
        {"NtLoadDriver", 270},
        {"NtUnloadDriver", 473},
        {"NtSuspendProcess", 462},
        {"NtResumeProcess", 394},
        {"NtSuspendThread", 463},
        {"NtGetContextThread", 251},
        {"NtSetContextThread", 410},
        {"NtDebugActiveProcess", 214},
        {"NtDebugContinue", 215},
        {"NtRemoveProcessDebug", 384},
        {"NtCreateDebugObject", 171},
        {"NtWaitForDebugEvent", 484},
};

// Validate that a resolved syscall address looks like valid kernel code
static bool validate_syscall_address(std::uint64_t addr,
                                     const sys::kernel_module_t &ntoskrnl) {
  // Must be a canonical kernel address
  if ((addr >> 48) != 0xFFFF) {
    return false;
  }

  // Must be within ntoskrnl bounds
  if (addr < ntoskrnl.base_address ||
      addr >= ntoskrnl.base_address + ntoskrnl.size) {
    return false;
  }

  // Read first bytes and check for valid function prologue
  // Common prologues: mov edi, edi (8B FF), push rbp (55), sub rsp (48 83 EC),
  // etc.
  std::uint8_t prologue[8] = {0};
  std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
      prologue, addr, sys::current_cr3, sizeof(prologue));

  if (bytes_read != sizeof(prologue)) {
    return false;
  }

  // Check for common valid opcodes at function start
  // 0x48 = REX.W prefix (common in x64)
  // 0x40-0x4F = REX prefixes
  // 0x55 = push rbp
  // 0x56 = push rsi
  // 0x57 = push rdi
  // 0x41 = REX.B prefix
  // 0x65 = GS segment override (TEB access)
  // 0xB8-0xBF = mov r32, imm32
  // 0x8B = mov
  // 0x33 = xor
  // 0xE9 = jmp (for forwarded functions)
  // 0xCC = int3 (debug)
  std::uint8_t first_byte = prologue[0];

  // Allow REX prefixes, common instruction prefixes, and typical function
  // starts
  if ((first_byte >= 0x40 && first_byte <= 0x4F) || // REX
      first_byte == 0x55 || first_byte == 0x56 ||
      first_byte == 0x57 || // push rbp/rsi/rdi
      first_byte == 0x65 || // GS segment (common in syscalls for TEB)
      (first_byte >= 0xB8 && first_byte <= 0xBF) || // mov r32, imm
      first_byte == 0x8B || first_byte == 0x33 ||   // mov, xor
      first_byte == 0xE9 || first_byte == 0xEB ||   // jmp
      first_byte == 0xCC || // int3 (not uncommon at function boundaries)
      first_byte == 0x90) { // nop
    return true;
  }

  return false;
}

// Try to find KiServiceTable using multiple pattern scanning strategies
static std::uint64_t
find_ki_service_table(const sys::kernel_module_t &ntoskrnl) {
  // Strategy 1: Scan for LEA instructions referencing KeServiceDescriptorTable
  // Pattern: 4C 8D 1D XX XX XX XX (lea r11, [rip+XXX]) in KiSystemServiceRepeat
  // Pattern: 4C 8D 15 XX XX XX XX (lea r10, [rip+XXX]) shadow SSDT

  constexpr std::uint64_t scan_size = 0x800000; // 8MB should cover .text
  std::vector<std::uint8_t> ntoskrnl_bytes(scan_size);

  std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
      ntoskrnl_bytes.data(), ntoskrnl.base_address, sys::current_cr3,
      scan_size);

  if (bytes_read < scan_size / 2) {
    std::println("    [-] Failed to read ntoskrnl memory for pattern scan");
    return 0;
  }

  // Patterns to search for (in order of reliability)
  struct pattern_info {
    std::uint8_t bytes[4];
    std::uint8_t len;
    const char *name;
    bool reads_pointer; // If true, target points to a pointer to KiServiceTable
  };

  pattern_info patterns[] = {
      // LEA r11, [rip+XXX] - Direct reference to KeServiceDescriptorTable
      {{0x4C, 0x8D, 0x1D, 0x00},
       3,
       "lea r11, [KeServiceDescriptorTable]",
       true},
      // LEA r10, [rip+XXX] - Shadow SSDT reference
      {{0x4C, 0x8D, 0x15, 0x00}, 3, "lea r10, [rip+XXX]", true},
      // MOV rax, [rip+XXX] - Sometimes used
      {{0x48, 0x8B, 0x05, 0x00}, 3, "mov rax, [rip+XXX]", true},
  };

  std::uint64_t ki_service_table = 0;

  for (const auto &pattern : patterns) {
    if (ki_service_table != 0)
      break;

    for (std::uint64_t i = 0; i < bytes_read - 16; i++) {
      bool match = true;
      for (std::uint8_t j = 0; j < pattern.len; j++) {
        if (ntoskrnl_bytes[i + j] != pattern.bytes[j]) {
          match = false;
          break;
        }
      }

      if (!match)
        continue;

      // Extract RIP-relative offset (4 bytes after pattern)
      std::int32_t rip_offset =
          *reinterpret_cast<std::int32_t *>(&ntoskrnl_bytes[i + pattern.len]);

      // Calculate target address: current_rip + instruction_length + offset
      std::uint64_t instruction_addr = ntoskrnl.base_address + i;
      std::uint64_t instruction_len =
          pattern.len + 4; // pattern + 4-byte offset
      std::uint64_t target_addr =
          instruction_addr + instruction_len + rip_offset;

      // Validate target is within ntoskrnl
      if ((target_addr >> 48) != 0xFFFF)
        continue;
      if (target_addr < ntoskrnl.base_address)
        continue;
      if (target_addr > ntoskrnl.base_address + ntoskrnl.size + 0x100000)
        continue;

      std::uint64_t potential_table = target_addr;

      // If pattern reads a pointer, dereference it
      if (pattern.reads_pointer) {
        std::uint64_t ptr_value = 0;
        hypercall::read_guest_virtual_memory(
            &ptr_value, target_addr, sys::current_cr3, sizeof(std::uint64_t));

        // The pointer should point to KiServiceTable within ntoskrnl
        if ((ptr_value >> 48) != 0xFFFF)
          continue;
        if (ptr_value < ntoskrnl.base_address)
          continue;
        if (ptr_value > ntoskrnl.base_address + ntoskrnl.size)
          continue;

        potential_table = ptr_value;
      }

      // Validate: Read first few SSDT entries and check format
      // SSDT entries are 4-byte signed offsets with arg count in low 4 bits
      std::int32_t test_entries[8] = {0};
      hypercall::read_guest_virtual_memory(test_entries, potential_table,
                                           sys::current_cr3,
                                           sizeof(test_entries));

      // Validation: entries should be non-zero and offsets should be in
      // reasonable range
      int valid_entries = 0;
      for (int j = 0; j < 8; j++) {
        if (test_entries[j] == 0)
          continue;

        // Extract the offset (signed, upper 28 bits)
        std::int32_t offset = test_entries[j] >> 4;

        // Offset should be reasonable (within ~16MB range from table base)
        // Note: offset can be negative (for entries before table)
        if (offset > -0x1000000 && offset < 0x1000000) {
          // Calculate the target address and verify it's in ntoskrnl
          std::uint64_t func_addr = potential_table + offset;
          if (func_addr >= ntoskrnl.base_address &&
              func_addr < ntoskrnl.base_address + ntoskrnl.size) {
            valid_entries++;
          }
        }
      }

      // Need at least 6 valid entries out of 8
      if (valid_entries >= 6) {
        ki_service_table = potential_table;
        std::println("    [+] Found KiServiceTable at 0x{:X} via pattern '{}'",
                     ki_service_table, pattern.name);
        break;
      }
    }
  }

  return ki_service_table;
}

// Resolve syscall addresses using hypervisor read (invisible to PG)
std::uint64_t resolve_syscalls_to_exports(sys::kernel_module_t &ntoskrnl) {
  std::println("    [*] Resolving syscall addresses...");

  std::uint64_t ki_service_table = find_ki_service_table(ntoskrnl);

  if (ki_service_table == 0) {
    std::println("    [-] Failed to locate KiServiceTable");
    return 0;
  }

  std::uint64_t syscalls_resolved = 0;
  std::uint64_t syscalls_failed = 0;

  // For each syscall in our table, calculate the kernel address
  for (const auto &[name, syscall_num] : syscall_numbers_24h2) {
    // Read the 4-byte SSDT entry from KiServiceTable
    std::int32_t ssdt_entry = 0;
    std::uint64_t entry_addr =
        ki_service_table + (static_cast<std::uint64_t>(syscall_num) * 4);

    hypercall::read_guest_virtual_memory(
        &ssdt_entry, entry_addr, sys::current_cr3, sizeof(std::int32_t));

    if (ssdt_entry == 0) {
      syscalls_failed++;
      continue;
    }

    // On x64, SSDT entry format:
    // Bits [31:4] = Signed offset from KiServiceTable to function
    // Bits [3:0]  = Number of arguments (for stack cleanup)
    // Formula: function_address = KiServiceTable + (ssdt_entry >> 4)

    // The right shift of a signed integer preserves the sign (arithmetic shift)
    std::int32_t offset = ssdt_entry >> 4;

    // Calculate the kernel function address
    // Note: offset is signed, so we need to handle negative offsets
    std::int64_t signed_offset = static_cast<std::int64_t>(offset);
    std::uint64_t kernel_address = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(ki_service_table) + signed_offset);

    // Validate the resolved address
    if (!validate_syscall_address(kernel_address, ntoskrnl)) {
      syscalls_failed++;
      continue;
    }

    // Add to exports with both plain name and prefixed name
    ntoskrnl.exports[name] = kernel_address;
    ntoskrnl.exports["ntoskrnl.exe!" + name] = kernel_address;

    // Also add Zw* variant (they point to same address in kernel)
    if (name.size() >= 2 && name.compare(0, 2, "Nt") == 0) {
      std::string zw_name = "Zw" + name.substr(2);
      ntoskrnl.exports[zw_name] = kernel_address;
      ntoskrnl.exports["ntoskrnl.exe!" + zw_name] = kernel_address;
    }

    syscalls_resolved++;
  }

  if (syscalls_failed > 0) {
    std::println("    [!] {} syscalls failed validation (may be system version "
                 "mismatch)",
                 syscalls_failed);
  }

  return syscalls_resolved;
}

void erase_unused_modules(
    const std::unordered_map<std::string, sys::kernel_module_t>
        &modules_not_found) {
  for (const auto &[module_name, module_info] : modules_not_found) {
    sys::kernel::modules_list.erase(module_name);
  }
}

// requires SeDebugPriviledge, use PsLoadedModulesList instead unless if using
// before ntoskrnl.exe is parsed
std::vector<rtl_process_module_information_t> get_loaded_modules_priviledged() {
  std::uint32_t size_of_information = 0;

  sys::user::query_system_information(11, nullptr, 0, &size_of_information);

  if (size_of_information == 0) {
    return {};
  }

  std::vector<std::uint8_t> buffer(size_of_information);

  std::uint32_t status = sys::user::query_system_information(
      11, buffer.data(), size_of_information, &size_of_information);

  if (NT_SUCCESS(status) == false) {
    return {};
  }

  rtl_process_modules_t *process_modules =
      reinterpret_cast<rtl_process_modules_t *>(buffer.data());

  rtl_process_module_information_t *start = &process_modules->modules[0];
  rtl_process_module_information_t *end = start + process_modules->module_count;

  return {start, end};
}

template <class t> t read_kernel_virtual_memory(std::uint64_t address) {
  t buffer = t();

  hypercall::read_guest_virtual_memory(&buffer, address, sys::current_cr3,
                                       sizeof(t));

  return buffer;
}

std::wstring read_unicode_string(std::uint64_t address) {
  std::uint16_t length = read_kernel_virtual_memory<std::uint16_t>(address);

  if (length == 0) {
    return {};
  }

  std::uint64_t buffer_address =
      read_kernel_virtual_memory<std::uint64_t>(address + 8);

  std::wstring string(length / 2, L'\0');

  hypercall::read_guest_virtual_memory(string.data(), buffer_address,
                                       sys::current_cr3, length);

  return string;
}

std::uint64_t get_ps_loaded_module_list() {
  const std::string ntoskrnl_name = "ntoskrnl.exe";

  if (sys::kernel::modules_list.contains(ntoskrnl_name) == 0) {
    return 0;
  }

  sys::kernel_module_t &ntoskrnl = sys::kernel::modules_list[ntoskrnl_name];

  const std::string ps_loaded_module_list_name =
      "ntoskrnl.exe!PsLoadedModuleList";

  return ntoskrnl.exports[ps_loaded_module_list_name];
}

std::uint8_t sys::kernel::parse_modules() {
  const std::uint64_t ps_loaded_module_list = get_ps_loaded_module_list();

  if (ps_loaded_module_list == 0) {
    std::println("can't locate PsLoadedModuleList");

    return 0;
  }

  std::unordered_map<std::string, kernel_module_t> modules_not_found =
      modules_list;

  const std::uint64_t start_entry = ps_loaded_module_list;

  std::uint64_t current_entry =
      read_kernel_virtual_memory<std::uint64_t>(start_entry); // flink

  while (current_entry != start_entry) {
    kernel_module_t kernel_module = {};

    std::uint64_t module_base_address =
        read_kernel_virtual_memory<std::uint64_t>(current_entry +
                                                  0x30); // DllBase
    std::uint32_t module_size = read_kernel_virtual_memory<std::uint32_t>(
        current_entry + 0x40); // SizeOfImage
    std::string module_name = user::to_string(
        read_unicode_string(current_entry + 0x58)); // BaseDllName

    // current_entry must not be accessed after this point in this iteration
    current_entry =
        read_kernel_virtual_memory<std::uint64_t>(current_entry); // flink

    if (modules_list.contains(module_name) == true) {
      modules_not_found.erase(module_name);

      const kernel_module_t already_present_module = modules_list[module_name];

      if (already_present_module.base_address == module_base_address &&
          already_present_module.size == module_size) {
        continue;
      }
    }

    std::vector<std::uint8_t> module_dump =
        dump_kernel_module(module_base_address);

    if (module_dump.empty() == true) {
      continue;
    }

    add_module_to_list(module_name, module_dump, module_base_address,
                       module_size);
  }

  erase_unused_modules(modules_not_found);

  return 1;
}

void fix_dump(std::vector<std::uint8_t> &buffer) {
  portable_executable::image_t *image =
      reinterpret_cast<portable_executable::image_t *>(buffer.data());

  for (auto &current_section : image->sections()) {
    current_section.pointer_to_raw_data = current_section.virtual_address;
    current_section.size_of_raw_data = current_section.virtual_size;
  }
}

std::uint8_t
sys::kernel::dump_module_to_disk(const std::string_view target_module_name,
                                 const std::string_view output_directory) {
  const auto module_info = modules_list[target_module_name.data()];

  const std::uint64_t module_base_address = module_info.base_address;

  if (module_base_address == 0) {
    return 0;
  }

  std::vector<std::uint8_t> buffer = dump_kernel_module(module_base_address);

  if (buffer.empty() == 1) {
    return 0;
  }

  fix_dump(buffer);

  std::string output_path = std::string(output_directory) + "\\" + "dump_" +
                            std::string(target_module_name);

  return fs::write_to_disk(output_path, buffer);
}

struct ntoskrnl_information_t {
  std::uint64_t base_address;
  std::uint32_t size;

  std::vector<std::uint8_t> dump;
};

std::optional<ntoskrnl_information_t> load_ntoskrnl_information() {
  std::uint8_t desired_privilege_state = 1;
  std::uint8_t previous_privilege_state = 0;

  if (sys::user::set_debug_privilege(desired_privilege_state,
                                     &previous_privilege_state) == 0) {
    std::println("unable to acquire necessary privilege");

    return std::nullopt;
  }

  const std::vector<rtl_process_module_information_t> loaded_modules =
      get_loaded_modules_priviledged();

  sys::user::set_debug_privilege(previous_privilege_state,
                                 &desired_privilege_state);

  for (const rtl_process_module_information_t &current_module :
       loaded_modules) {
    std::string_view current_module_name = reinterpret_cast<const char *>(
        current_module.full_path_name + current_module.offset_to_file_name);

    if (current_module_name == "ntoskrnl.exe") {
      std::vector<std::uint8_t> ntoskrnl_dump =
          dump_kernel_module(current_module.image_base);

      if (ntoskrnl_dump.empty() == true) {
        std::println("unable to dump ntoskrnl.exe");

        return std::nullopt;
      }

      ntoskrnl_information_t ntoskrnl_info = {};

      ntoskrnl_info.base_address = current_module.image_base;
      ntoskrnl_info.size = current_module.image_size;
      ntoskrnl_info.dump = ntoskrnl_dump;

      return ntoskrnl_info;
    }
  }

  return std::nullopt;
}

std::uint8_t parse_ntoskrnl() {
  std::optional<ntoskrnl_information_t> ntoskrnl_info =
      load_ntoskrnl_information();

  if (ntoskrnl_info.has_value() == 0) {
    std::println("unable to load ntoskrnl.exe's information");

    return 0;
  }

  std::vector<std::uint8_t> &ntoskrnl_dump = ntoskrnl_info->dump;

  portable_executable::image_t *ntoskrnl_image =
      reinterpret_cast<portable_executable::image_t *>(ntoskrnl_dump.data());

  add_module_to_list("ntoskrnl.exe", ntoskrnl_dump, ntoskrnl_info->base_address,
                     ntoskrnl_info->size);

  hook::kernel_detour_holder_base = find_kernel_detour_holder_base_address(
      ntoskrnl_image, ntoskrnl_info->base_address);

  if (hook::kernel_detour_holder_base == 0) {
    std::println("unable to locate kernel hook holder");

    return 0;
  }

  // Resolve syscall addresses using hypervisor (invisible to PG)
  sys::kernel_module_t &ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];
  std::uint64_t syscalls_resolved = resolve_syscalls_to_exports(ntoskrnl);
  if (syscalls_resolved > 0) {
    std::println("[+] Resolved {} syscall addresses (Nt*/Zw* functions)",
                 syscalls_resolved);
  }

  return 1;
}

std::uint8_t sys::set_up() {
  current_cr3 = hypercall::read_guest_cr3();

  if (current_cr3 == 0) {
    std::println("hyperv-attachment doesn't seem to be loaded");

    return 0;
  }

  if (parse_ntoskrnl() == 0) {
    std::println("unable to parse ntoskrnl.exe");

    return 0;
  }

  if (kernel::parse_modules() == 0) {
    std::println("unable to parse kernel modules");

    return 0;
  }

  if (hook::set_up() == 0) {
    std::println("unable to set up kernel hook helper");

    return 0;
  }

  return 1;
}

void sys::clean_up() {
  commands::syscall_intercept_cleanup();
  hook::clean_up();
}

std::uint32_t sys::user::query_system_information(
    std::int32_t information_class, void *information_out,
    std::uint32_t information_size, std::uint32_t *returned_size) {
  return NtQuerySystemInformation(
      static_cast<SYSTEM_INFORMATION_CLASS>(information_class), information_out,
      information_size, reinterpret_cast<ULONG *>(returned_size));
}

std::uint32_t
sys::user::adjust_privilege(std::uint32_t privilege, std::uint8_t enable,
                            std::uint8_t current_thread_only,
                            std::uint8_t *previous_enabled_state) {
  return RtlAdjustPrivilege(privilege, enable, current_thread_only,
                            previous_enabled_state);
}

std::uint8_t sys::user::set_debug_privilege(const std::uint8_t state,
                                            std::uint8_t *previous_state) {
  constexpr std::uint32_t debug_privilege_id = 20;

  std::uint32_t status =
      adjust_privilege(debug_privilege_id, state, 0, previous_state);

  return NT_SUCCESS(status);
}

void *sys::user::allocate_locked_memory(std::uint64_t size,
                                        std::uint32_t protection) {
  void *allocation_base =
      VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);

  if (allocation_base == nullptr) {
    return nullptr;
  }

  std::int32_t lock_status = VirtualLock(allocation_base, size);

  if (lock_status == 0) {
    free_memory(allocation_base);

    return nullptr;
  }

  return allocation_base;
}

std::uint8_t sys::user::free_memory(void *address) {
  std::int32_t free_status = VirtualFree(address, 0, MEM_RELEASE);

  return free_status != 0;
}

std::string sys::user::to_string(const std::wstring &wstring) {
  if (wstring.empty() == 1) {
    return {};
  }

  std::string converted_string = {};

  std::ranges::transform(
      wstring, std::back_inserter(converted_string),
      [](wchar_t character) { return static_cast<char>(character); });

  return converted_string;
}

std::uint8_t sys::fs::exists(std::string_view path) {
  return std::filesystem::exists(path);
}

std::uint8_t sys::fs::write_to_disk(const std::string_view full_path,
                                    const std::vector<std::uint8_t> &buffer) {
  std::ofstream file(full_path.data(), std::ios::binary);

  if (file.is_open() == 0) {
    return 0;
  }

  file.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());

  return file.good();
}
