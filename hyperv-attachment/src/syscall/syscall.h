#pragma once
#include <cstdint>
#include <structures/syscall_info.h>

namespace syscall_trace {
// ========================================================================
// SYSCALL TRACING VIA IA32_LSTAR INTERCEPTION
//
// On AMD, syscalls go through IA32_LSTAR MSR which points to KiSystemCall64.
// We intercept MSR reads/writes to virtualize LSTAR and redirect syscalls
// through our handler first, logging them before passing to the real handler.
//
// This allows monitoring ALL syscalls made by the target process including:
// - NtReadVirtualMemory (AC memory scans)
// - NtQueryVirtualMemory (AC region enumeration)
// - NtOpenProcess/Thread (AC process access)
// - etc.
// ========================================================================

// Maximum syscall log entries
constexpr std::uint64_t max_log_entries = 4096;

// Log storage
extern syscall_log_t log_buffer[max_log_entries];
extern std::uint64_t log_head;
extern std::uint64_t log_count;

// Tracing state
extern bool tracing_enabled;
extern std::uint64_t target_cr3; // 0 = all processes

// Filter state (0 = log all syscalls)
constexpr std::uint64_t max_filters = 64;
extern std::uint64_t filter_syscalls[max_filters];
extern std::uint64_t filter_count;
extern bool filter_whitelist; // true = only log filtered, false = log all
                              // except filtered

// Original LSTAR value
extern std::uint64_t original_lstar;
extern std::uint64_t our_handler_address;

// ========================================================================
// CONTROL FUNCTIONS
// ========================================================================

// Initialize syscall tracing
void init();

// Enable syscall tracing for all or specific process
// target_cr3 = 0 means all processes
void enable(std::uint64_t target_cr3 = 0);

// Disable syscall tracing
void disable();

// Check if tracing is enabled
bool is_enabled();

// ========================================================================
// FILTER FUNCTIONS
// ========================================================================

// Add syscall to filter list
void add_filter(std::uint64_t syscall_id);

// Remove syscall from filter list
void remove_filter(std::uint64_t syscall_id);

// Clear all filters
void clear_filters();

// Set filter mode (whitelist = true means only log the filtered syscalls)
void set_filter_mode(bool whitelist);

// ========================================================================
// LOGGING
// ========================================================================

// Log a syscall (called from VM exit handler)
void log_syscall(std::uint64_t syscall_id, std::uint64_t arg1,
                 std::uint64_t arg2, std::uint64_t arg3, std::uint64_t arg4,
                 std::uint64_t caller_rip, std::uint64_t caller_cr3,
                 std::uint64_t return_value);

// Get log entries (copies to buffer, returns count)
std::uint64_t get_log(syscall_log_t *buffer, std::uint64_t max_count);

// Clear log
void clear_log();

// Get log count
std::uint64_t get_log_count();

// ========================================================================
// MSR VIRTUALIZATION HANDLER
// Called when guest reads/writes LSTAR MSR
// We virtualize it to intercept syscalls
// ========================================================================

// Handle MSR read - return virtualized value
std::uint64_t on_msr_read(std::uint32_t msr);

// Handle MSR write - intercept LSTAR writes
void on_msr_write(std::uint32_t msr, std::uint64_t value);

// ========================================================================
// SYSCALL INTERCEPTION
// Called at VM exit when syscall instruction is executed
// ========================================================================

// Log current syscall from trap frame
void on_syscall(std::uint64_t rax,  // syscall number
                std::uint64_t rcx,  // arg1 / return address
                std::uint64_t rdx,  // arg2
                std::uint64_t r8,   // arg3
                std::uint64_t r9,   // arg4
                std::uint64_t rip,  // caller RIP
                std::uint64_t cr3); // caller CR3

} // namespace syscall_trace
