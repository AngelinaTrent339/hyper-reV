#pragma once
#include <cstdint>

namespace instruction_trace {
// ========================================================================
// INSTRUCTION TRACING VIA TRAP FLAG (TF) SINGLE-STEPPING
//
// We set TF in RFLAGS to cause a #DB (debug exception) after each
// instruction. By intercepting the #DB in our VM exit handler, we can
// log every instruction executed by the target process.
//
// This is extremely powerful for:
// - Understanding anti-cheat detection logic
// - Finding checks and patches
// - Tracing call flows
// ========================================================================

// Trace log entry
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

// Maximum trace entries
constexpr std::uint64_t max_trace_entries = 8192;

// Trace log storage
extern trace_entry_t trace_log[max_trace_entries];
extern std::uint64_t trace_head;
extern std::uint64_t trace_count;

// Tracing state
extern bool tracing_enabled;
extern std::uint64_t target_cr3; // 0 = all processes
extern std::uint64_t start_rip;  // Start tracing at this RIP
extern std::uint64_t end_rip;    // Stop tracing at this RIP (0 = never)
extern std::uint64_t
    max_instructions; // Max instructions to trace (0 = unlimited)
extern std::uint64_t instruction_count;

// ========================================================================
// CONTROL FUNCTIONS
// ========================================================================

// Initialize tracing
void init();

// Start tracing from specific RIP (or 0 = immediately)
void start(std::uint64_t target_process_cr3, std::uint64_t from_rip = 0,
           std::uint64_t to_rip = 0, std::uint64_t max_count = 0);

// Stop tracing
void stop();

// Check if tracing is enabled
bool is_enabled();

// ========================================================================
// TRACE LOG MANAGEMENT
// ========================================================================

// Get trace entries (copies to buffer, returns count)
std::uint64_t get_log(trace_entry_t *buffer, std::uint64_t max_count);

// Clear trace log
void clear_log();

// Get trace count
std::uint64_t get_trace_count();

// ========================================================================
// DEBUG EXCEPTION HANDLER
// Called when #DB exception occurs in guest (TF single-step)
// ========================================================================

// Handle single-step trap
// Returns true if we handled it (was our trace), false to inject to guest
bool on_debug_exception(std::uint64_t rip, std::uint64_t rsp, std::uint64_t rax,
                        std::uint64_t rbx, std::uint64_t rcx, std::uint64_t rdx,
                        std::uint64_t cr3, std::uint64_t rflags);

// Enable TF in guest RFLAGS for single-stepping
void enable_single_step(std::uint64_t &rflags);

// Disable TF in guest RFLAGS
void disable_single_step(std::uint64_t &rflags);

// Check if we should start tracing (RIP matches start condition)
bool should_start_at_rip(std::uint64_t rip, std::uint64_t cr3);

// Check if we should stop tracing (RIP matches end condition or count exceeded)
bool should_stop(std::uint64_t rip);
} // namespace instruction_trace
