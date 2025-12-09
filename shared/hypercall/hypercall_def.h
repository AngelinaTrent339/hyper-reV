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
  set_tracked_pid,     // Set the PID to track - will auto-capture CR3
  get_tracked_cr3,     // Get the captured CR3 for the tracked process
  clear_tracked_pid,   // Clear the tracked PID and CR3
  get_tracking_status, // Get tracking status (PID, CR3, and match count)
  // MSR Shadowing (AMD only)
  add_msr_shadow,      // Add/update MSR shadow: rdx=msr_index, r8=shadow_value
  remove_msr_shadow,   // Remove MSR shadow: rdx=msr_index
  get_msr_shadow_list, // Get list of active shadows: r8=output_buffer
  clear_all_msr_shadows, // Clear all MSR shadows
  read_msr_value, // Read MSR value (returns shadow if exists): rdx=msr_index
  get_msr_intercept_count, // Get count of MSR intercepts caught (debug)
  // MSRPM Control (AMD only) - enables actual MSR interception
  set_msr_intercept,     // Enable/disable MSR interception: rdx=msr_index, r8=flags (bit0=read, bit1=write)
  get_msr_intercept_status // Get current intercept status for MSR: rdx=msr_index
};

#pragma warning(push)
#pragma warning(disable : 4201)

constexpr std::uint64_t hypercall_primary_key = 0x4E47;
constexpr std::uint64_t hypercall_secondary_key = 0x7F;

union hypercall_info_t {
  std::uint64_t value;

  struct {
    std::uint64_t primary_key : 16;
    hypercall_type_t call_type : 6;  // Increased from 4 to 6 bits (max 64 types)
    std::uint64_t secondary_key : 7;
    std::uint64_t call_reserved_data : 35;  // Reduced from 37 to 35
  };
};

union virt_memory_op_hypercall_info_t {
  std::uint64_t value;

  struct {
    std::uint64_t primary_key : 16;
    hypercall_type_t call_type : 6;  // Increased from 4 to 6 bits
    std::uint64_t secondary_key : 7;
    memory_operation_t memory_operation : 1;
    std::uint64_t address_of_page_directory
        : 34; // Reduced from 36 to 34
  };
};

#pragma warning(pop)
