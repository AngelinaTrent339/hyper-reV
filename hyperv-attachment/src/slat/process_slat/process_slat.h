#pragma once
#include <cstdint>

// =============================================================================
// PROCESS-AWARE SLAT MANAGER
// =============================================================================
// This module extends SLAT violation handling to be aware of which PROCESS
// is currently executing. This defeats anti-cheat techniques that use
// "trusted" processes (explorer.exe, csrss.exe) to scan game memory.
//
// How it works:
// 1. Register the game process CR3 as "target" (sees modified memory)
// 2. Register scanner processes CR3s as "clean" (sees original memory)
// 3. On every SLAT violation, check guest CR3:
//    - If target_cr3 → use hook_cr3 (modified view)
//    - If scanner_cr3 → use hyperv_cr3 (clean view)
//    - Otherwise → use hyperv_cr3 (safe default)
//
// Result:
// - When game.exe executes hooked code → runs your hooks
// - When AC scans from explorer.exe → sees clean memory
// - When AC kernel driver scans → sees clean memory
//
// Example attack scenario defeated:
//   Anti-Cheat: "I'll open handle to game.exe from explorer.exe"
//   Anti-Cheat: "ReadProcessMemory(game, 0x1234) to check integrity"
//   Hypervisor: "explorer.exe CR3 detected → show clean page"
//   Anti-Cheat: "Memory looks clean! ✓"
//
//   Game.exe: "Call function at 0x1234"
//   Hypervisor: "game.exe CR3 detected → show hooked page"
//   Game: "Executes your hook!"

namespace process_slat {

// Maximum number of scanner processes to track
constexpr uint32_t MAX_SCANNER_PROCESSES = 16;

// Scanner process entry
struct scanner_entry_t {
  uint64_t cr3; // CR3 of scanner process
  uint64_t pid; // PID for debug/management
  bool active;  // Is this entry active?
};

// Target process (the game)
struct target_process_t {
  uint64_t cr3; // Game's CR3
  uint64_t pid; // Game's PID
  bool active;  // Is targeting active?
};

// Initialize the process-aware SLAT system
void init();

// Set the target process (the game that should see modified memory)
void set_target_process(uint64_t cr3, uint64_t pid);

// Clear the target process
void clear_target_process();

// Get the target process CR3
uint64_t get_target_cr3();

// Register a scanner process (will see clean memory)
// Returns: slot index (0 = failure)
uint64_t register_scanner(uint64_t cr3, uint64_t pid);

// Unregister a scanner process
void unregister_scanner(uint64_t cr3);

// Clear all scanner processes
void clear_all_scanners();

// Get count of registered scanners
uint32_t get_scanner_count();

// Check if a CR3 belongs to a registered scanner
bool is_scanner(uint64_t cr3);

// =============================================================================
// SLAT VIEW DECISION
// =============================================================================
// Called from violation handler to decide which SLAT view to use

enum class slat_view_t : uint8_t {
  hyperv = 0, // Clean view (original memory)
  hooked = 1  // Modified view (hooks active)
};

// Decide which SLAT view to use based on current guest CR3
// This is the core decision function called on SLAT violations
slat_view_t get_view_for_cr3(uint64_t guest_cr3);

// =============================================================================
// STATISTICS
// =============================================================================

struct stats_t {
  uint64_t target_accesses;  // How many times target got hooked view
  uint64_t scanner_accesses; // How many times scanner got clean view
  uint64_t other_accesses;   // Other processes (got clean view)
};

const stats_t &get_stats();
void reset_stats();

} // namespace process_slat
