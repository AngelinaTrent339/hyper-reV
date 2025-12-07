#include "syscall.h"
#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../process/process.h"
#include <intrin.h>

namespace syscall_trace {
// ========================================================================
// GLOBAL STATE
// ========================================================================

syscall_log_t log_buffer[max_log_entries] = {};
std::uint64_t log_head = 0;
std::uint64_t log_count = 0;

bool tracing_enabled = false;
std::uint64_t target_cr3 = 0;

std::uint64_t filter_syscalls[max_filters] = {};
std::uint64_t filter_count = 0;
bool filter_whitelist = false;

std::uint64_t original_lstar = 0;
std::uint64_t our_handler_address = 0;

// ========================================================================
// INITIALIZATION
// ========================================================================

void init() {
  crt::set_memory(log_buffer, 0, sizeof(log_buffer));
  crt::set_memory(filter_syscalls, 0, sizeof(filter_syscalls));
  log_head = 0;
  log_count = 0;
  filter_count = 0;
  filter_whitelist = false;
  tracing_enabled = false;
  target_cr3 = 0;
  original_lstar = 0;
}

// ========================================================================
// CONTROL FUNCTIONS
// ========================================================================

void enable(std::uint64_t target) {
  target_cr3 = target;
  tracing_enabled = true;

  // Read and save original LSTAR if not already saved
  if (original_lstar == 0) {
    original_lstar = __readmsr(0xC0000082); // IA32_LSTAR
  }

  // Note: Actual MSR interception is set up in VMCB control
  // We just enable our logging pathway here
}

void disable() { tracing_enabled = false; }

bool is_enabled() { return tracing_enabled; }

// ========================================================================
// FILTER FUNCTIONS
// ========================================================================

void add_filter(std::uint64_t syscall_id) {
  if (filter_count >= max_filters)
    return;

  // Check if already in filter
  for (std::uint64_t i = 0; i < filter_count; i++) {
    if (filter_syscalls[i] == syscall_id)
      return;
  }

  filter_syscalls[filter_count++] = syscall_id;
}

void remove_filter(std::uint64_t syscall_id) {
  for (std::uint64_t i = 0; i < filter_count; i++) {
    if (filter_syscalls[i] == syscall_id) {
      // Shift remaining entries
      for (std::uint64_t j = i; j < filter_count - 1; j++) {
        filter_syscalls[j] = filter_syscalls[j + 1];
      }
      filter_count--;
      return;
    }
  }
}

void clear_filters() { filter_count = 0; }

void set_filter_mode(bool whitelist) { filter_whitelist = whitelist; }

// ========================================================================
// LOGGING
// ========================================================================

static bool should_log_syscall(std::uint64_t syscall_id) {
  if (filter_count == 0)
    return true; // No filters = log all

  // Check if syscall is in filter list
  bool in_filter = false;
  for (std::uint64_t i = 0; i < filter_count; i++) {
    if (filter_syscalls[i] == syscall_id) {
      in_filter = true;
      break;
    }
  }

  // Whitelist mode: only log if in filter
  // Blacklist mode: only log if NOT in filter
  return filter_whitelist ? in_filter : !in_filter;
}

void log_syscall(std::uint64_t syscall_id, std::uint64_t arg1,
                 std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4,
                 std::uint64_t caller_rip, std::uint64_t caller_cr3,
                 std::uint64_t return_value) {
  if (!tracing_enabled)
    return;

  // Check if we should log this process
  if (target_cr3 != 0 && caller_cr3 != target_cr3)
    return;

  // Check filter
  if (!should_log_syscall(syscall_id))
    return;

  // Create log entry
  syscall_log_t entry = {};
  entry.timestamp = __rdtsc();
  entry.syscall_id = syscall_id;
  entry.arg1 = arg1;
  entry.arg2 = arg2;
  entry.arg3 = arg3;
  entry.arg4 = arg4;
  entry.caller_rip = caller_rip;
  entry.caller_cr3 = caller_cr3;
  entry.return_value = return_value;

  // Add to circular buffer
  log_buffer[log_head] = entry;
  log_head = (log_head + 1) % max_log_entries;
  if (log_count < max_log_entries)
    log_count++;
}

std::uint64_t get_log(syscall_log_t *buffer, std::uint64_t max_count) {
  std::uint64_t count = (log_count < max_count) ? log_count : max_count;

  // Copy from circular buffer (oldest first)
  for (std::uint64_t i = 0; i < count; i++) {
    std::uint64_t idx =
        (log_head - log_count + i + max_log_entries) % max_log_entries;
    buffer[i] = log_buffer[idx];
  }

  return count;
}

void clear_log() {
  log_head = 0;
  log_count = 0;
}

std::uint64_t get_log_count() { return log_count; }

// ========================================================================
// MSR VIRTUALIZATION
// ========================================================================

std::uint64_t on_msr_read(std::uint32_t msr) {
  // Return original LSTAR to guest so it doesn't know we're tracing
  if (msr == 0xC0000082 && tracing_enabled) // IA32_LSTAR
  {
    return original_lstar;
  }

  // For other MSRs, read the actual value
  return __readmsr(msr);
}

void on_msr_write(std::uint32_t msr, std::uint64_t value) {
  if (msr == 0xC0000082) // IA32_LSTAR
  {
    // Save the new value as "original"
    original_lstar = value;

    // If tracing is enabled, we don't actually write to LSTAR
    // Our VM exit handler will intercept syscalls instead
    if (!tracing_enabled) {
      __writemsr(msr, value);
    }
    return;
  }

  // For other MSRs, write normally
  __writemsr(msr, value);
}

// ========================================================================
// SYSCALL INTERCEPTION
// ========================================================================

void on_syscall(std::uint64_t rax, std::uint64_t rcx, std::uint64_t rdx,
                std::uint64_t r8, std::uint64_t r9, std::uint64_t rip,
                std::uint64_t cr3) {
  // Log the syscall
  // Note: return_value is 0 for now - we'd need to intercept sysret to get it
  log_syscall(rax, rcx, rdx, r8, r9, rip, cr3, 0);
}

} // namespace syscall_trace
