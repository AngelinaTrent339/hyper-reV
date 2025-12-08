#pragma once
#include <cstdint>
#include <structures/memory_operation.h>

enum class hypercall_type_t : std::uint64_t {
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
  // Process CR3 auto-tracking
  set_tracked_pid,    // Set the PID to track - will auto-capture CR3
  get_tracked_cr3,    // Get the captured CR3 for the tracked process
  clear_tracked_pid,  // Clear the tracked PID and CR3
  get_tracking_status // Get tracking status (PID, CR3, and match count)
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
