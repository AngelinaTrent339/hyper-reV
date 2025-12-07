#pragma once
#include <cstdint>

// ============================================================================
// BREAKPOINT STRUCTURES
// Used for NPT-based invisible hardware breakpoints
// ============================================================================

#pragma pack(push, 1)

// Breakpoint type flags
enum class breakpoint_type_t : std::uint8_t {
  bp_read = 1,       // Break on memory read
  bp_write = 2,      // Break on memory write
  bp_execute = 4,    // Break on code execution
  bp_read_write = 3, // Break on read or write
  bp_any = 7         // Break on any access
};

// What to do when breakpoint hits
enum class breakpoint_action_t : std::uint8_t {
  action_log = 0,     // Just log the hit
  action_break = 1,   // Pause and notify usermode
  action_trace = 2,   // Log + start instruction trace
  action_callback = 3 // Execute callback (future)
};

// Breakpoint definition
struct breakpoint_def_t {
  std::uint64_t address;      // Guest physical address
  std::uint64_t size;         // Size of watched region
  breakpoint_type_t type;     // R/W/X
  breakpoint_action_t action; // What to do on hit
  std::uint8_t enabled;       // Is BP active
  std::uint8_t reserved[5];

  // For conditional breakpoints
  std::uint64_t condition_address; // Address to check
  std::uint64_t condition_value;   // Expected value
  std::uint64_t condition_mask;    // Comparison mask
};

// Breakpoint hit log entry
struct breakpoint_hit_t {
  std::uint64_t timestamp;       // TSC when hit occurred
  std::uint64_t bp_address;      // Which BP was hit
  std::uint64_t access_address;  // Actual address accessed
  std::uint64_t guest_rip;       // Where access came from
  std::uint64_t guest_cr3;       // Which process
  breakpoint_type_t access_type; // R/W/X
  std::uint8_t reserved[7];
  std::uint64_t access_value; // Value read/written (if applicable)
};

#pragma pack(pop)
