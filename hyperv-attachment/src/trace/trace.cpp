#include "trace.h"
#include "../crt/crt.h"
#include "../memory/memory.h"
#include <intrin.h>

namespace instruction_trace {
// ========================================================================
// GLOBAL STATE
// ========================================================================

trace_entry_t trace_log[max_trace_entries] = {};
std::uint64_t trace_head = 0;
std::uint64_t trace_count = 0;

bool tracing_enabled = false;
std::uint64_t target_cr3 = 0;
std::uint64_t start_rip = 0;
std::uint64_t end_rip = 0;
std::uint64_t max_instructions = 0;
std::uint64_t instruction_count = 0;

// ========================================================================
// INITIALIZATION
// ========================================================================

void init() {
  crt::set_memory(trace_log, 0, sizeof(trace_log));
  trace_head = 0;
  trace_count = 0;
  tracing_enabled = false;
  target_cr3 = 0;
  start_rip = 0;
  end_rip = 0;
  max_instructions = 0;
  instruction_count = 0;
}

// ========================================================================
// CONTROL FUNCTIONS
// ========================================================================

void start(std::uint64_t target_process_cr3, std::uint64_t from_rip,
           std::uint64_t to_rip, std::uint64_t max_count) {
  target_cr3 = target_process_cr3;
  start_rip = from_rip;
  end_rip = to_rip;
  max_instructions = max_count;
  instruction_count = 0;

  // Clear log on new trace
  trace_head = 0;
  trace_count = 0;

  tracing_enabled = true;
}

void stop() { tracing_enabled = false; }

bool is_enabled() { return tracing_enabled; }

// ========================================================================
// TRACE LOG MANAGEMENT
// ========================================================================

std::uint64_t get_log(trace_entry_t *buffer, std::uint64_t max_count) {
  std::uint64_t count = (trace_count < max_count) ? trace_count : max_count;

  // Copy from circular buffer (oldest first)
  for (std::uint64_t i = 0; i < count; i++) {
    std::uint64_t idx =
        (trace_head - trace_count + i + max_trace_entries) % max_trace_entries;
    buffer[i] = trace_log[idx];
  }

  return count;
}

void clear_log() {
  trace_head = 0;
  trace_count = 0;
}

std::uint64_t get_trace_count() { return trace_count; }

// ========================================================================
// HELPER FUNCTIONS
// ========================================================================

void enable_single_step(std::uint64_t &rflags) {
  // Set TF (Trap Flag) bit - bit 8
  rflags |= (1ULL << 8);
}

void disable_single_step(std::uint64_t &rflags) {
  // Clear TF bit
  rflags &= ~(1ULL << 8);
}

bool should_start_at_rip(std::uint64_t rip, std::uint64_t cr3) {
  // Check process match
  if (target_cr3 != 0 && cr3 != target_cr3)
    return false;

  // If start_rip is 0, start immediately
  if (start_rip == 0)
    return true;

  return rip == start_rip;
}

bool should_stop(std::uint64_t rip) {
  // Check instruction count limit
  if (max_instructions > 0 && instruction_count >= max_instructions)
    return true;

  // Check end RIP
  if (end_rip != 0 && rip == end_rip)
    return true;

  return false;
}

// ========================================================================
// DEBUG EXCEPTION HANDLER
// ========================================================================

bool on_debug_exception(std::uint64_t rip, std::uint64_t rsp, std::uint64_t rax,
                        std::uint64_t rbx, std::uint64_t rcx, std::uint64_t rdx,
                        std::uint64_t cr3, std::uint64_t rflags) {
  if (!tracing_enabled)
    return false;

  // Check if this is our target
  if (target_cr3 != 0 && cr3 != target_cr3)
    return false;

  // Check if we should stop
  if (should_stop(rip)) {
    stop();
    return true;
  }

  // Log the instruction
  trace_entry_t entry = {};
  entry.timestamp = __rdtsc();
  entry.rip = rip;
  entry.rsp = rsp;
  entry.rax = rax;
  entry.rbx = rbx;
  entry.rcx = rcx;
  entry.rdx = rdx;
  entry.cr3 = cr3;

  // Try to read instruction bytes
  std::uint64_t read =
      memory_analysis::read_memory(cr3, rip, entry.instruction_bytes, 16);
  entry.instruction_length = static_cast<std::uint8_t>(read);

  // Add to circular buffer
  trace_log[trace_head] = entry;
  trace_head = (trace_head + 1) % max_trace_entries;
  if (trace_count < max_trace_entries)
    trace_count++;

  instruction_count++;

  return true; // We handled it
}
} // namespace instruction_trace
