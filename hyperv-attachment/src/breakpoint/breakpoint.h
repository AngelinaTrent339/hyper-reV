#pragma once
#include <cstdint>
#include <structures/breakpoint_info.h>

namespace npt_breakpoint {
// ========================================================================
// NPT-BASED INVISIBLE BREAKPOINTS
//
// These breakpoints work by modifying NPT page table entries:
// - Remove R bit -> read breakpoint
// - Remove W bit -> write breakpoint
// - Remove X bit -> execute breakpoint
//
// When the protected page is accessed, we get an NPT violation (VM exit).
// DR0-DR7 are NEVER touched - completely invisible to anti-cheats.
// ========================================================================

// Maximum number of breakpoints
constexpr std::uint64_t max_breakpoints = 64;
constexpr std::uint64_t max_bp_hits = 1024;

// Breakpoint storage
extern breakpoint_def_t breakpoints[max_breakpoints];
extern std::uint64_t breakpoint_count;

// Hit log storage
extern breakpoint_hit_t hit_log[max_bp_hits];
extern std::uint64_t hit_log_head;
extern std::uint64_t hit_log_count;

// Saved original page permissions (to restore after BP removed)
struct saved_permissions_t {
  std::uint64_t gpa;
  std::uint64_t original_permissions; // Original R/W/X bits
  bool in_use;
};
extern saved_permissions_t saved_permissions[max_breakpoints];

// ========================================================================
// BREAKPOINT MANAGEMENT
// ========================================================================

// Initialize breakpoint system
void init();

// Add a breakpoint at guest physical address
// Returns breakpoint index or -1 on failure
std::int64_t add(std::uint64_t gpa, std::uint64_t size, breakpoint_type_t type,
                 breakpoint_action_t action);

// Add conditional breakpoint (breaks when [condition_addr] == value & mask)
std::int64_t add_conditional(std::uint64_t gpa, std::uint64_t size,
                             breakpoint_type_t type, breakpoint_action_t action,
                             std::uint64_t condition_addr,
                             std::uint64_t condition_value,
                             std::uint64_t condition_mask);

// Remove breakpoint at address
bool remove(std::uint64_t gpa);

// Remove all breakpoints
void remove_all();

// Find breakpoint by address
breakpoint_def_t *find(std::uint64_t gpa);

// Get breakpoint by index
breakpoint_def_t *get(std::uint64_t index);

// ========================================================================
// NPT VIOLATION HANDLER
// Called when an NPT violation occurs - checks if it's a breakpoint hit
// ========================================================================

// Check if the NPT violation is due to a breakpoint
// If yes, logs the hit and returns true
// gpa = guest physical address of violation
// access_type = R/W/X that caused the violation
// rip = guest instruction pointer
// cr3 = guest CR3
bool on_npt_violation(std::uint64_t gpa, breakpoint_type_t access_type,
                      std::uint64_t rip, std::uint64_t cr3);

// ========================================================================
// HIT LOG MANAGEMENT
// ========================================================================

// Get hit log entries (copies to buffer, returns count)
std::uint64_t get_hits(breakpoint_hit_t *buffer, std::uint64_t max_count);

// Clear hit log
void clear_hits();

// Get current hit count
std::uint64_t get_hit_count();

// ========================================================================
// SINGLE-STEP HANDLING
// After a BP hit, we need to single-step one instruction then re-enable BP
// ========================================================================

struct pending_reenable_t {
  std::uint64_t gpa;
  std::uint64_t bp_index;
  bool pending;
};

// Per-CPU pending re-enable (need to track which BP to re-enable after single
// step)
extern pending_reenable_t pending_reenable[256]; // Max 256 CPUs

// Called after single-step to re-enable the breakpoint
void on_single_step_complete(std::uint64_t cpu_index);

// Set up single-step to execute one instruction then re-enable BP
void setup_single_step(std::uint64_t cpu_index, std::uint64_t bp_index);

} // namespace npt_breakpoint
