#pragma once
#include <cstdint>

namespace syscall_intercept {
// Syscall filter mode
enum class filter_mode_t : std::uint8_t {
  disabled = 0,     // No syscall filtering
  log_all = 1,      // Log all syscalls
  log_filtered = 2, // Log only specific syscall numbers
};

// Syscall log entry - stored in hypervisor memory
struct syscall_log_entry_t {
  std::uint64_t timestamp;      // TSC timestamp
  std::uint64_t syscall_number; // RAX - syscall number
  std::uint64_t
      arg1; // RCX - 1st argument (after SYSCALL, this is return address)
  std::uint64_t arg2;   // RDX - 2nd argument
  std::uint64_t arg3;   // R8  - 3rd argument
  std::uint64_t arg4;   // R9  - 4th argument
  std::uint64_t rip;    // Caller RIP (R10 contains original RIP)
  std::uint64_t rsp;    // User stack pointer
  std::uint64_t cr3;    // Process CR3
  std::uint32_t cpu_id; // Which CPU
  std::uint32_t flags;  // Reserved for future use
};

// Configuration for syscall interception
struct config_t {
  filter_mode_t mode;
  std::uint64_t ki_system_call64_address; // LSTAR MSR value
  std::uint64_t ki_system_call64_shadow;  // Our shadow page with logging

  // Filter settings (when mode == log_filtered)
  std::uint64_t filter_syscall_min; // Log syscalls >= this
  std::uint64_t filter_syscall_max; // Log syscalls <= this
  std::uint64_t filter_cr3;         // Only log from this process (0 = all)
};

// Initialize syscall interception (called from hypervisor setup)
void initialize();

// Enable/disable syscall logging
void set_mode(filter_mode_t mode);
filter_mode_t get_mode();

// Set filter parameters
void set_filter(std::uint64_t syscall_min, std::uint64_t syscall_max,
                std::uint64_t cr3_filter);

// Called when LSTAR is being read/written (MSR intercept)
std::uint64_t handle_lstar_read();
void handle_lstar_write(std::uint64_t new_value);

// Log a syscall (called from NPT violation handler when hitting KiSystemCall64)
void log_syscall(std::uint64_t syscall_num, std::uint64_t rcx,
                 std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9,
                 std::uint64_t r10_rip, std::uint64_t rsp, std::uint64_t cr3,
                 std::uint32_t cpu_id);

// Get logged syscalls count
std::uint64_t get_log_count();

// Flush logs to guest buffer (via hypercall)
std::uint64_t flush_logs(void *guest_buffer, std::uint64_t max_entries);
} // namespace syscall_intercept
