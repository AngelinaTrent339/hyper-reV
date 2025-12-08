#include "syscall_intercept.h"
#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/hook/hook.h"
#include "../slat/slat.h"
#include "../structures/virtual_address.h"

#include <intrin.h>

namespace {
// MSR definitions (prefixed to avoid conflict with ia32.hpp)
constexpr std::uint32_t MSR_LSTAR = 0xC0000082;
constexpr std::uint32_t MSR_STAR = 0xC0000081;
constexpr std::uint32_t MSR_FMASK = 0xC0000084;
constexpr std::uint32_t MSR_EFER = 0xC0000080;

// Syscall interception state
syscall_intercept::config_t g_config = {};

// Circular buffer for syscall logs
constexpr std::uint64_t MAX_SYSCALL_LOGS = 4096;
syscall_intercept::syscall_log_entry_t *g_syscall_logs = nullptr;
volatile std::uint64_t g_log_write_index = 0;
volatile std::uint64_t g_log_read_index = 0;

// Mutex for log access
crt::mutex_t g_log_mutex = {};

// Original LSTAR value (KiSystemCall64 address)
std::uint64_t g_original_lstar = 0;

// Shadow page physical address for KiSystemCall64 hook
std::uint64_t g_syscall_shadow_page_pa = 0;
std::uint64_t g_syscall_original_page_pa = 0;
} // namespace

void syscall_intercept::initialize() {
  // Allocate syscall log buffer
  std::uint64_t pages_needed =
      (MAX_SYSCALL_LOGS * sizeof(syscall_log_entry_t) + 0xFFF) / 0x1000;

  g_syscall_logs =
      static_cast<syscall_log_entry_t *>(heap_manager::allocate_page());
  for (std::uint64_t i = 1; i < pages_needed; i++) {
    heap_manager::allocate_page(); // Allocate contiguous pages
  }

  // Initialize config
  g_config.mode = filter_mode_t::disabled;
  g_config.ki_system_call64_address = 0;
  g_config.ki_system_call64_shadow = 0;
  g_config.filter_syscall_min = 0;
  g_config.filter_syscall_max = 0xFFFFFFFF;
  g_config.filter_cr3 = 0;

  g_log_write_index = 0;
  g_log_read_index = 0;
}

void syscall_intercept::set_mode(filter_mode_t mode) { g_config.mode = mode; }

syscall_intercept::filter_mode_t syscall_intercept::get_mode() {
  return g_config.mode;
}

void syscall_intercept::set_filter(std::uint64_t syscall_min,
                                   std::uint64_t syscall_max,
                                   std::uint64_t cr3_filter) {
  g_config.filter_syscall_min = syscall_min;
  g_config.filter_syscall_max = syscall_max;
  g_config.filter_cr3 = cr3_filter;
}

std::uint64_t syscall_intercept::get_filter_cr3() {
  return g_config.filter_cr3;
}

std::uint64_t syscall_intercept::handle_lstar_read() {
  // Return the original LSTAR value to the guest
  // This hides our hook from usermode detection
  return g_original_lstar;
}

void syscall_intercept::handle_lstar_write(std::uint64_t new_value) {
  // Store the new LSTAR value
  g_original_lstar = new_value;
  g_config.ki_system_call64_address = new_value;

  // If syscall interception is enabled, we need to hook the new address
  if (g_config.mode != filter_mode_t::disabled) {
    // Remove old hook if exists
    if (g_syscall_original_page_pa != 0) {
      virtual_address_t addr;
      addr.address = g_syscall_original_page_pa;
      slat::hook::remove(addr);
    }

    // The new LSTAR value is the virtual address of KiSystemCall64
    // We need to translate it and set up NPT hook
    // This will be done via hypercall from usermode since we need to
    // allocate shadow pages in guest memory
  }
}

void syscall_intercept::log_syscall(std::uint64_t syscall_num,
                                    std::uint64_t rcx, std::uint64_t rdx,
                                    std::uint64_t r8, std::uint64_t r9,
                                    std::uint64_t r10_rip, std::uint64_t rsp,
                                    std::uint64_t cr3, std::uint32_t cpu_id) {
  // Check if logging is enabled
  if (g_config.mode == filter_mode_t::disabled) {
    return;
  }

  // Check filters
  if (g_config.mode == filter_mode_t::log_filtered) {
    // Check syscall number range
    if (syscall_num < g_config.filter_syscall_min ||
        syscall_num > g_config.filter_syscall_max) {
      return;
    }

    // Check CR3 filter
    if (g_config.filter_cr3 != 0 && cr3 != g_config.filter_cr3) {
      return;
    }
  }

  // Check if log buffer is available
  if (g_syscall_logs == nullptr) {
    return;
  }

  g_log_mutex.lock();

  // Get next write slot (circular buffer)
  std::uint64_t write_idx = g_log_write_index % MAX_SYSCALL_LOGS;

  // Fill in log entry
  syscall_log_entry_t *entry = &g_syscall_logs[write_idx];
  entry->timestamp = __rdtsc();
  entry->syscall_number = syscall_num;
  entry->arg1 = rcx;
  entry->arg2 = rdx;
  entry->arg3 = r8;
  entry->arg4 = r9;
  entry->rip = r10_rip;
  entry->rsp = rsp;
  entry->cr3 = cr3;
  entry->cpu_id = cpu_id;
  entry->flags = 0;

  g_log_write_index++;

  // Handle overflow - advance read index if we wrapped
  if (g_log_write_index - g_log_read_index > MAX_SYSCALL_LOGS) {
    g_log_read_index = g_log_write_index - MAX_SYSCALL_LOGS;
  }

  g_log_mutex.release();
}

std::uint64_t syscall_intercept::get_log_count() {
  return g_log_write_index - g_log_read_index;
}

std::uint64_t syscall_intercept::flush_logs(void *guest_buffer,
                                            std::uint64_t max_entries) {
  if (g_syscall_logs == nullptr || guest_buffer == nullptr) {
    return 0;
  }

  g_log_mutex.lock();

  std::uint64_t available = g_log_write_index - g_log_read_index;
  std::uint64_t to_copy = (available < max_entries) ? available : max_entries;

  if (to_copy == 0) {
    g_log_mutex.release();
    return 0;
  }

  // Copy entries to guest buffer
  for (std::uint64_t i = 0; i < to_copy; i++) {
    std::uint64_t read_idx = (g_log_read_index + i) % MAX_SYSCALL_LOGS;

    syscall_log_entry_t *dst =
        static_cast<syscall_log_entry_t *>(guest_buffer) + i;
    syscall_log_entry_t *src = &g_syscall_logs[read_idx];

    crt::copy_memory(dst, src, sizeof(syscall_log_entry_t));
  }

  g_log_read_index += to_copy;

  g_log_mutex.release();

  return to_copy;
}
