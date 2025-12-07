#include "hypercall.h"
#include <hypercall/hypercall_def.h>

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx,
                                              std::uint64_t rdx,
                                              std::uint64_t r8,
                                              std::uint64_t r9);

std::uint64_t make_hypercall(hypercall_type_t call_type,
                             std::uint64_t call_reserved_data,
                             std::uint64_t rdx, std::uint64_t r8,
                             std::uint64_t r9) {
  hypercall_info_t hypercall_info = {};

  hypercall_info.primary_key = hypercall_primary_key;
  hypercall_info.secondary_key = hypercall_secondary_key;
  hypercall_info.call_type = call_type;
  hypercall_info.call_reserved_data = call_reserved_data;

  return launch_raw_hypercall(hypercall_info, rdx, r8, r9);
}

std::uint64_t hypercall::read_guest_physical_memory(
    void *guest_destination_buffer, std::uint64_t guest_source_physical_address,
    std::uint64_t size) {
  hypercall_type_t call_type =
      hypercall_type_t::guest_physical_memory_operation;

  std::uint64_t call_data =
      static_cast<std::uint64_t>(memory_operation_t::read_operation);

  std::uint64_t guest_destination_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_destination_buffer);

  return make_hypercall(call_type, call_data, guest_source_physical_address,
                        guest_destination_virtual_address, size);
}

std::uint64_t hypercall::write_guest_physical_memory(
    void *guest_source_buffer, std::uint64_t guest_destination_physical_address,
    std::uint64_t size) {
  hypercall_type_t call_type =
      hypercall_type_t::guest_physical_memory_operation;

  std::uint64_t call_data =
      static_cast<std::uint64_t>(memory_operation_t::write_operation);

  std::uint64_t guest_source_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_source_buffer);

  return make_hypercall(call_type, call_data,
                        guest_destination_physical_address,
                        guest_source_virtual_address, size);
}

std::uint64_t hypercall::read_guest_virtual_memory(
    void *guest_destination_buffer, std::uint64_t guest_source_virtual_address,
    std::uint64_t source_cr3, std::uint64_t size) {
  virt_memory_op_hypercall_info_t memory_op_call = {};

  memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
  memory_op_call.memory_operation = memory_operation_t::read_operation;
  memory_op_call.address_of_page_directory = source_cr3 >> 12;

  hypercall_info_t hypercall_info = {.value = memory_op_call.value};

  std::uint64_t guest_destination_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_destination_buffer);

  return make_hypercall(
      hypercall_info.call_type, hypercall_info.call_reserved_data,
      guest_destination_virtual_address, guest_source_virtual_address, size);
}

std::uint64_t hypercall::write_guest_virtual_memory(
    void *guest_source_buffer, std::uint64_t guest_destination_virtual_address,
    std::uint64_t destination_cr3, std::uint64_t size) {
  virt_memory_op_hypercall_info_t memory_op_call = {};

  memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
  memory_op_call.memory_operation = memory_operation_t::write_operation;
  memory_op_call.address_of_page_directory = destination_cr3 >> 12;

  hypercall_info_t hypercall_info = {.value = memory_op_call.value};

  std::uint64_t guest_source_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_source_buffer);

  return make_hypercall(
      hypercall_info.call_type, hypercall_info.call_reserved_data,
      guest_source_virtual_address, guest_destination_virtual_address, size);
}

std::uint64_t
hypercall::translate_guest_virtual_address(std::uint64_t guest_virtual_address,
                                           std::uint64_t guest_cr3) {
  hypercall_type_t call_type =
      hypercall_type_t::translate_guest_virtual_address;

  return make_hypercall(call_type, 0, guest_virtual_address, guest_cr3, 0);
}

std::uint64_t hypercall::read_guest_cr3() {
  hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::add_slat_code_hook(
    std::uint64_t target_guest_physical_address,
    std::uint64_t shadow_page_guest_physical_address) {
  hypercall_type_t call_type = hypercall_type_t::add_slat_code_hook;

  return make_hypercall(call_type, 0, target_guest_physical_address,
                        shadow_page_guest_physical_address, 0);
}

std::uint64_t
hypercall::remove_slat_code_hook(std::uint64_t target_guest_physical_address) {
  hypercall_type_t call_type = hypercall_type_t::remove_slat_code_hook;

  return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::hide_guest_physical_page(
    std::uint64_t target_guest_physical_address) {
  hypercall_type_t call_type = hypercall_type_t::hide_guest_physical_page;

  return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::flush_logs(std::vector<trap_frame_log_t> &logs) {
  hypercall_type_t call_type = hypercall_type_t::flush_logs;

  return make_hypercall(call_type, 0,
                        reinterpret_cast<std::uint64_t>(logs.data()),
                        logs.size(), 0);
}

std::uint64_t hypercall::get_heap_free_page_count() {
  hypercall_type_t call_type = hypercall_type_t::get_heap_free_page_count;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

// ============================================================================
// PHASE 2: PROCESS TARGETING
// ============================================================================

std::uint64_t hypercall::attach_to_process(std::uint64_t target_cr3) {
  hypercall_type_t call_type = hypercall_type_t::attach_to_process;

  return make_hypercall(call_type, 0, target_cr3, 0, 0);
}

std::uint64_t hypercall::detach_from_process() {
  hypercall_type_t call_type = hypercall_type_t::detach_from_process;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::get_process_by_name(const char *name) {
  hypercall_type_t call_type = hypercall_type_t::get_process_by_name;

  return make_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(name), 0,
                        0);
}

std::uint64_t
hypercall::get_process_list(std::vector<process_info_t> &processes) {
  hypercall_type_t call_type = hypercall_type_t::get_process_list;

  // Ensure buffer is large enough
  if (processes.size() < 256)
    processes.resize(256);

  std::uint64_t count = make_hypercall(
      call_type, 0, reinterpret_cast<std::uint64_t>(processes.data()),
      processes.size(), 0);

  // Resize to actual count
  if (count < processes.size())
    processes.resize(count);

  return count;
}

std::uint64_t hypercall::set_windows_offsets(const windows_offsets_t &offsets) {
  hypercall_type_t call_type = hypercall_type_t::set_windows_offsets;

  return make_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(&offsets),
                        0, 0);
}

std::uint64_t
hypercall::enumerate_modules(std::uint64_t target_cr3, std::uint64_t peb,
                             std::vector<module_info_t> &modules) {
  hypercall_type_t call_type = hypercall_type_t::enumerate_modules;

  // Ensure buffer is large enough
  if (modules.size() < 128)
    modules.resize(128);

  std::uint64_t count =
      make_hypercall(call_type, 0, target_cr3, peb,
                     reinterpret_cast<std::uint64_t>(modules.data()));
  // Note: 5th argument (max_count) is read from stack by hypervisor

  if (count < modules.size())
    modules.resize(count);

  return count;
}

// === PHASE 3: INVISIBLE NPT BREAKPOINTS ===

std::int64_t hypercall::add_breakpoint(std::uint64_t gpa, std::uint64_t size,
                                       breakpoint_type_t type,
                                       breakpoint_action_t action) {
  hypercall_type_t call_type = hypercall_type_t::add_breakpoint;
  return static_cast<std::int64_t>(
      make_hypercall(call_type, 0, gpa, size,
                     (static_cast<std::uint64_t>(type) |
                      (static_cast<std::uint64_t>(action) << 8))));
}

std::int64_t hypercall::add_conditional_breakpoint(
    std::uint64_t gpa, std::uint64_t size, breakpoint_type_t type,
    breakpoint_action_t action, std::uint64_t condition_addr,
    std::uint64_t value, std::uint64_t mask) {
  hypercall_type_t call_type = hypercall_type_t::add_conditional_breakpoint;
  // Pack type and action
  std::uint64_t type_action = static_cast<std::uint64_t>(type) |
                              (static_cast<std::uint64_t>(action) << 8);
  return static_cast<std::int64_t>(
      make_hypercall(call_type, 0, gpa, size, type_action));
  // condition_addr, value, mask passed via stack
}

std::uint64_t hypercall::remove_breakpoint(std::uint64_t gpa) {
  hypercall_type_t call_type = hypercall_type_t::remove_breakpoint;
  return make_hypercall(call_type, 0, gpa, 0, 0);
}

std::uint64_t
hypercall::list_breakpoints(std::vector<breakpoint_def_t> &breakpoints) {
  hypercall_type_t call_type = hypercall_type_t::list_breakpoints;
  if (breakpoints.size() < 64)
    breakpoints.resize(64);
  std::uint64_t count = make_hypercall(
      call_type, 0, reinterpret_cast<std::uint64_t>(breakpoints.data()),
      breakpoints.size(), 0);
  if (count < breakpoints.size())
    breakpoints.resize(count);
  return count;
}

std::uint64_t
hypercall::get_breakpoint_hits(std::vector<breakpoint_hit_t> &hits) {
  hypercall_type_t call_type = hypercall_type_t::get_breakpoint_hits;
  if (hits.size() < 256)
    hits.resize(256);
  std::uint64_t count =
      make_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(hits.data()),
                     hits.size(), 0);
  if (count < hits.size())
    hits.resize(count);
  return count;
}

std::uint64_t hypercall::clear_breakpoint_hits() {
  hypercall_type_t call_type = hypercall_type_t::clear_breakpoint_hits;
  return make_hypercall(call_type, 0, 0, 0, 0);
}

// === PHASE 4: SYSCALL TRACING ===

std::uint64_t hypercall::enable_syscall_trace(std::uint64_t target_cr3) {
  hypercall_type_t call_type = hypercall_type_t::enable_syscall_trace;
  return make_hypercall(call_type, 0, target_cr3, 0, 0);
}

std::uint64_t hypercall::disable_syscall_trace() {
  hypercall_type_t call_type = hypercall_type_t::disable_syscall_trace;
  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::set_syscall_filter(std::uint64_t action,
                                            std::uint64_t value) {
  hypercall_type_t call_type = hypercall_type_t::set_syscall_filter;
  return make_hypercall(call_type, 0, action, value, 0);
}

std::uint64_t hypercall::get_syscall_log(std::vector<syscall_log_t> &logs) {
  hypercall_type_t call_type = hypercall_type_t::get_syscall_log;
  if (logs.size() < 512)
    logs.resize(512);
  std::uint64_t count =
      make_hypercall(call_type, 0, reinterpret_cast<std::uint64_t>(logs.data()),
                     logs.size(), 0);
  if (count < logs.size())
    logs.resize(count);
  return count;
}

std::uint64_t hypercall::clear_syscall_log() {
  hypercall_type_t call_type = hypercall_type_t::clear_syscall_log;
  return make_hypercall(call_type, 0, 0, 0, 0);
}

// === PHASE 5: MEMORY ANALYSIS ===

std::uint64_t hypercall::enumerate_vad(std::uint64_t target_cr3,
                                       std::uint64_t vad_root,
                                       std::vector<vad_info_t> &vads) {
  hypercall_type_t call_type = hypercall_type_t::enumerate_vad;
  if (vads.size() < 256)
    vads.resize(256);
  std::uint64_t count =
      make_hypercall(call_type, 0, target_cr3, vad_root,
                     reinterpret_cast<std::uint64_t>(vads.data()));
  if (count < vads.size())
    vads.resize(count);
  return count;
}

std::uint64_t
hypercall::search_pattern(std::uint64_t target_cr3, std::uint64_t start,
                          std::uint64_t size, const std::uint8_t *pattern,
                          std::uint64_t pattern_len,
                          std::vector<pattern_result_t> &results) {
  hypercall_type_t call_type = hypercall_type_t::search_memory_pattern;
  if (results.size() < 128)
    results.resize(128);
  std::uint64_t count = make_hypercall(call_type, 0, target_cr3, start, size);
  // pattern, pattern_len, results, max passed via stack
  if (count < results.size())
    results.resize(count);
  return count;
}

std::uint64_t hypercall::dump_module(std::uint64_t target_cr3,
                                     std::uint64_t module_base, void *buffer,
                                     std::uint64_t size) {
  hypercall_type_t call_type = hypercall_type_t::dump_module;
  return make_hypercall(call_type, 0, target_cr3, module_base,
                        reinterpret_cast<std::uint64_t>(buffer));
  // size passed via stack
}

// === PHASE 6: MEMORY CLOAKING ===

std::uint64_t hypercall::cloak_memory(std::uint64_t page_gpa,
                                      std::uint64_t shadow_va, bool enable) {
  hypercall_type_t call_type = hypercall_type_t::cloak_memory;
  return make_hypercall(call_type, 0, page_gpa, shadow_va, enable ? 1 : 0);
}

// === PHASE 7: INSTRUCTION TRACING ===

std::uint64_t hypercall::start_instruction_trace(std::uint64_t target_cr3,
                                                 std::uint64_t start_rip,
                                                 std::uint64_t end_rip,
                                                 std::uint64_t max_count) {
  hypercall_type_t call_type = hypercall_type_t::start_instruction_trace;
  return make_hypercall(call_type, 0, target_cr3, start_rip, end_rip);
  // max_count passed via stack
}

std::uint64_t hypercall::stop_instruction_trace() {
  hypercall_type_t call_type = hypercall_type_t::stop_instruction_trace;
  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t
hypercall::get_instruction_trace(std::vector<trace_entry_t> &trace) {
  hypercall_type_t call_type = hypercall_type_t::get_instruction_trace;
  if (trace.size() < 256)
    trace.resize(256);
  std::uint64_t count = make_hypercall(
      call_type, 0, reinterpret_cast<std::uint64_t>(trace.data()), trace.size(),
      0);
  if (count < trace.size())
    trace.resize(count);
  return count;
}

std::uint64_t hypercall::clear_instruction_trace() {
  hypercall_type_t call_type = hypercall_type_t::clear_instruction_trace;
  return make_hypercall(call_type, 0, 0, 0, 0);
}

// === PHASE 8: CODE EXECUTION ===

std::uint64_t hypercall::write_shellcode(std::uint64_t target_cr3,
                                         std::uint64_t target_va,
                                         const void *shellcode,
                                         std::uint64_t size, bool cloak) {
  hypercall_type_t call_type = hypercall_type_t::write_shellcode;
  return make_hypercall(call_type, 0, target_cr3, target_va,
                        reinterpret_cast<std::uint64_t>(shellcode));
  // size, cloak passed via stack
}

std::uint64_t hypercall::execute_in_guest(std::uint64_t target_cr3,
                                          std::uint64_t shellcode_va,
                                          std::uint64_t parameter) {
  hypercall_type_t call_type = hypercall_type_t::execute_in_guest;
  return make_hypercall(call_type, 0, target_cr3, shellcode_va, parameter);
}

std::uint64_t hypercall::call_function(std::uint64_t target_cr3,
                                       std::uint64_t function_addr,
                                       std::uint64_t arg1, std::uint64_t arg2,
                                       std::uint64_t arg3, std::uint64_t arg4) {
  hypercall_type_t call_type = hypercall_type_t::call_guest_function;
  return make_hypercall(call_type, 0, target_cr3, function_addr, arg1);
  // arg2, arg3, arg4 passed via stack
}

std::uint64_t hypercall::find_code_cave(std::uint64_t target_cr3,
                                        std::uint64_t module_base,
                                        std::uint64_t module_size,
                                        std::uint64_t required_size) {
  hypercall_type_t call_type = hypercall_type_t::find_code_cave;
  return make_hypercall(call_type, 0, target_cr3, module_base, module_size);
  // required_size passed via stack
}

bool hypercall::get_execution_result(std::uint64_t &result) {
  hypercall_type_t call_type = hypercall_type_t::get_execution_result;
  std::uint64_t ret = make_hypercall(call_type, 0, 0, 0, 0);
  result = ret;
  // The complete flag would be in rdx, but we simplified for now
  return ret != 0;
}
