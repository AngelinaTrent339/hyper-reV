#pragma once
#include <cstdint>
#include <structures/breakpoint_info.h>
#include <structures/process_info.h>
#include <structures/syscall_info.h>
#include <structures/trap_frame.h>
#include <vector>

namespace hypercall {
// === EXISTING HYPERCALLS ===
std::uint64_t
read_guest_physical_memory(void *guest_destination_buffer,
                           std::uint64_t guest_source_physical_address,
                           std::uint64_t size);
std::uint64_t
write_guest_physical_memory(void *guest_source_buffer,
                            std::uint64_t guest_destination_physical_address,
                            std::uint64_t size);

std::uint64_t
read_guest_virtual_memory(void *guest_destination_buffer,
                          std::uint64_t guest_source_virtual_address,
                          std::uint64_t source_cr3, std::uint64_t size);
std::uint64_t
write_guest_virtual_memory(void *guest_source_buffer,
                           std::uint64_t guest_destination_virtual_address,
                           std::uint64_t destination_cr3, std::uint64_t size);

std::uint64_t
translate_guest_virtual_address(std::uint64_t guest_virtual_address,
                                std::uint64_t guest_cr3);

std::uint64_t read_guest_cr3();

std::uint64_t
add_slat_code_hook(std::uint64_t target_guest_physical_address,
                   std::uint64_t shadow_page_guest_physical_address);
std::uint64_t
remove_slat_code_hook(std::uint64_t target_guest_physical_address);
std::uint64_t
hide_guest_physical_page(std::uint64_t target_guest_physical_address);

std::uint64_t flush_logs(std::vector<trap_frame_log_t> &logs);

std::uint64_t get_heap_free_page_count();

// === PHASE 2: PROCESS TARGETING ===

// Attach to specific process by CR3 (0 = all processes)
std::uint64_t attach_to_process(std::uint64_t target_cr3);

// Detach from current target, operate on all processes
std::uint64_t detach_from_process();

// Find process CR3 by name (returns 0 if not found)
std::uint64_t get_process_by_name(const char *name);

// Enumerate all processes
std::uint64_t get_process_list(std::vector<process_info_t> &processes);

// Set Windows kernel offsets (required before process enumeration)
std::uint64_t set_windows_offsets(const windows_offsets_t &offsets);

// Enumerate modules for a process
std::uint64_t enumerate_modules(std::uint64_t target_cr3, std::uint64_t peb,
                                std::vector<module_info_t> &modules);

// === PHASE 3: INVISIBLE NPT BREAKPOINTS ===

// Add read/write/execute breakpoint (type: 1=R, 2=W, 4=X, or OR them)
std::int64_t add_breakpoint(std::uint64_t gpa, std::uint64_t size,
                            breakpoint_type_t type, breakpoint_action_t action);

// Add conditional breakpoint (triggers when [condition_addr] & mask == value)
std::int64_t add_conditional_breakpoint(std::uint64_t gpa, std::uint64_t size,
                                        breakpoint_type_t type,
                                        breakpoint_action_t action,
                                        std::uint64_t condition_addr,
                                        std::uint64_t value,
                                        std::uint64_t mask);

// Remove breakpoint
std::uint64_t remove_breakpoint(std::uint64_t gpa);

// List all active breakpoints
std::uint64_t list_breakpoints(std::vector<breakpoint_def_t> &breakpoints);

// Get breakpoint hits
std::uint64_t get_breakpoint_hits(std::vector<breakpoint_hit_t> &hits);

// Clear breakpoint hit log
std::uint64_t clear_breakpoint_hits();

// === PHASE 4: SYSCALL TRACING ===

// Enable syscall tracing (target_cr3 = 0 for all processes)
std::uint64_t enable_syscall_trace(std::uint64_t target_cr3 = 0);

// Disable syscall tracing
std::uint64_t disable_syscall_trace();

// Set syscall filter (action: 0=clear, 1=add, 2=remove, 3=set_mode)
std::uint64_t set_syscall_filter(std::uint64_t action, std::uint64_t value);

// Get syscall log
std::uint64_t get_syscall_log(std::vector<syscall_log_t> &logs);

// Clear syscall log
std::uint64_t clear_syscall_log();

// === PHASE 5: MEMORY ANALYSIS ===

// Enumerate VAD (Virtual Address Descriptors) for process
std::uint64_t enumerate_vad(std::uint64_t target_cr3, std::uint64_t vad_root,
                            std::vector<vad_info_t> &vads);

// Pattern scan result
struct pattern_result_t {
  std::uint64_t address;
  std::uint64_t offset;
};

// Search for byte pattern in memory
std::uint64_t search_pattern(std::uint64_t target_cr3, std::uint64_t start,
                             std::uint64_t size, const std::uint8_t *pattern,
                             std::uint64_t pattern_len,
                             std::vector<pattern_result_t> &results);

// Dump module memory
std::uint64_t dump_module(std::uint64_t target_cr3, std::uint64_t module_base,
                          void *buffer, std::uint64_t size);

// === PHASE 6: MEMORY CLOAKING ===

// Cloak memory (show shadow page to AC, real page to game)
std::uint64_t cloak_memory(std::uint64_t page_gpa, std::uint64_t shadow_va,
                           bool enable);

// === PHASE 7: INSTRUCTION TRACING ===

// Trace entry
struct trace_entry_t {
  std::uint64_t timestamp;
  std::uint64_t rip;
  std::uint64_t rsp;
  std::uint64_t rax;
  std::uint64_t rbx;
  std::uint64_t rcx;
  std::uint64_t rdx;
  std::uint64_t cr3;
  std::uint8_t instruction_bytes[16];
  std::uint8_t instruction_length;
  std::uint8_t padding[7];
};

// Start instruction tracing
std::uint64_t start_instruction_trace(std::uint64_t target_cr3,
                                      std::uint64_t start_rip = 0,
                                      std::uint64_t end_rip = 0,
                                      std::uint64_t max_count = 0);

// Stop instruction tracing
std::uint64_t stop_instruction_trace();

// Get instruction trace log
std::uint64_t get_instruction_trace(std::vector<trace_entry_t> &trace);

// Clear instruction trace log
std::uint64_t clear_instruction_trace();

// === PHASE 8: CODE EXECUTION ===

// Write shellcode to target process (via NPT, invisible to AC)
std::uint64_t write_shellcode(std::uint64_t target_cr3, std::uint64_t target_va,
                              const void *shellcode, std::uint64_t size,
                              bool cloak = true);

// Execute shellcode at address
std::uint64_t execute_in_guest(std::uint64_t target_cr3,
                               std::uint64_t shellcode_va,
                               std::uint64_t parameter = 0);

// Call function in guest process
std::uint64_t call_function(std::uint64_t target_cr3,
                            std::uint64_t function_addr, std::uint64_t arg1 = 0,
                            std::uint64_t arg2 = 0, std::uint64_t arg3 = 0,
                            std::uint64_t arg4 = 0);

// Find code cave in module
std::uint64_t find_code_cave(std::uint64_t target_cr3,
                             std::uint64_t module_base,
                             std::uint64_t module_size,
                             std::uint64_t required_size);

// Check if execution completed and get result
bool get_execution_result(std::uint64_t &result);

} // namespace hypercall
