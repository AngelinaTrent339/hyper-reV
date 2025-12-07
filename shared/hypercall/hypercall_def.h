#pragma once
#include <cstdint>
#include <structures/memory_operation.h>

enum class hypercall_type_t : std::uint64_t {
  // === EXISTING HYPERCALLS (0-9) ===
  guest_physical_memory_operation,
  guest_virtual_memory_operation,
  translate_guest_virtual_address,
  read_guest_cr3,
  add_slat_code_hook,
  remove_slat_code_hook,
  hide_guest_physical_page,
  log_current_state,
  flush_logs,
  get_heap_free_page_count,

  // === PHASE 2: PROCESS TARGETING (10-13) ===
  attach_to_process,   // Set target CR3 for filtering
  detach_from_process, // Clear target, operate on all
  get_process_by_name, // Find CR3 by process name
  get_process_list,    // Enumerate all processes

  // === PHASE 3: INVISIBLE BREAKPOINTS (14-19) ===
  add_breakpoint,             // NPT-based R/W/X breakpoint
  remove_breakpoint,          // Remove breakpoint
  list_breakpoints,           // Get active breakpoints
  add_conditional_breakpoint, // Break when [addr] == value
  get_breakpoint_hits,        // Get BP hit log
  clear_breakpoint_hits,      // Clear hit log

  // === PHASE 4: SYSCALL TRACING (20-24) ===
  enable_syscall_trace,  // Hook IA32_LSTAR
  disable_syscall_trace, // Unhook IA32_LSTAR
  set_syscall_filter,    // Filter by syscall ID
  get_syscall_log,       // Retrieve syscall log
  clear_syscall_log,     // Clear log

  // === PHASE 5: MEMORY ANALYSIS (25-30) ===
  enumerate_modules,     // Walk PEB->Ldr
  enumerate_vad,         // Walk VAD tree
  query_address_info,    // Get VAD info for address
  search_memory_pattern, // AOB scan
  dump_memory_region,    // Dump bypassing AC
  set_windows_offsets,   // Set kernel structure offsets

  // === PHASE 6: MEMORY CLOAKING (31-33) ===
  cloak_memory_region,   // Hide from guest reads
  uncloak_memory_region, // Restore normal access
  list_cloaked_regions,  // Get cloaked regions

  // === PHASE 7: INSTRUCTION TRACING (34-36) ===
  start_instruction_trace, // TF-based single step
  stop_instruction_trace,  // Stop tracing
  get_instruction_trace,   // Get trace log

  // === PHASE 8: CODE EXECUTION (37-39) ===
  execute_shellcode,      // Run shellcode in guest
  call_guest_function,    // Call function with args
  allocate_hidden_memory, // Allocate hidden executable memory
};

#pragma warning(push)
#pragma warning(disable : 4201)

constexpr std::uint64_t hypercall_primary_key = 0x4E47;
constexpr std::uint64_t hypercall_secondary_key = 0x7F;

union hypercall_info_t {
  std::uint64_t value;

  struct {
    std::uint64_t primary_key : 16;
    hypercall_type_t call_type : 4;
    std::uint64_t secondary_key : 7;
    std::uint64_t call_reserved_data : 37;
  };
};

union virt_memory_op_hypercall_info_t {
  std::uint64_t value;

  struct {
    std::uint64_t primary_key : 16;
    hypercall_type_t call_type : 4;
    std::uint64_t secondary_key : 7;
    memory_operation_t memory_operation : 1;
    std::uint64_t address_of_page_directory
        : 36; // we will construct the other cr3 (aside from the caller process)
              // involved in the operation from this
  };
};

#pragma warning(pop)
