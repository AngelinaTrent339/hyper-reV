#pragma once
#include <cstdint>
#include <structures/trap_frame.h>
#include <vector>

namespace hypercall {
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

// ============================================================================
// HYPERVISOR-LEVEL SYSCALL INTERCEPTION (No SSDT needed!)
// ============================================================================

// Syscall log entry from hypervisor
struct syscall_log_entry_t {
  std::uint64_t timestamp;      // TSC timestamp
  std::uint64_t syscall_number; // Syscall number (RAX)
  std::uint64_t arg1;           // Argument 1
  std::uint64_t arg2;           // Argument 2
  std::uint64_t arg3;           // Argument 3
  std::uint64_t arg4;           // Argument 4
  std::uint64_t rip;            // Caller RIP
  std::uint64_t rsp;            // User stack
  std::uint64_t cr3;            // Process CR3
  std::uint32_t cpu_id;         // CPU ID
  std::uint32_t flags;          // Reserved
};

// Enable syscall interception at hypervisor level
// mode: 0 = log_all, 1 = log_filtered
std::uint64_t enable_syscall_intercept(std::uint8_t mode);

// Disable syscall interception
std::uint64_t disable_syscall_intercept();

// Set syscall filter (when mode = log_filtered)
std::uint64_t set_syscall_filter(std::uint64_t syscall_min,
                                 std::uint64_t syscall_max,
                                 std::uint64_t cr3_filter);

// Flush syscall logs from hypervisor to usermode buffer
std::uint64_t flush_syscall_logs(std::vector<syscall_log_entry_t> &logs);

// Get number of pending syscall log entries
std::uint64_t get_syscall_log_count();

// Hook LSTAR directly (KiSystemCall64) - ultimate power!
// This intercepts ALL syscalls at the hypervisor level
std::uint64_t hook_lstar(std::uint64_t lstar_va, std::uint64_t shadow_page_pa);

// Read MSR value from hypervisor level
// Common MSRs: IA32_LSTAR = 0xC0000082, IA32_STAR = 0xC0000081
std::uint64_t read_msr(std::uint32_t msr_index);
} // namespace hypercall
