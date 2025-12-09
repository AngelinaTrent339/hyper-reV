#pragma once
#include <cstdint>

// =============================================================================
// STEALTH EXECUTION MODULE
// =============================================================================
// This module provides techniques to bypass modern anti-cheat detection:
//
// 1. SHADOW CODE EXECUTION (Integrity Check Bypass)
//    - Game memory looks clean to AC scanners
//    - But executes your modified code
//    - Uses dual SLAT views with read/execute split
//
// 2. PROCESS-AWARE MEMORY HIDING (Handle Abuse Bypass)
//    - When explorer.exe/AC scanner reads → shows clean memory
//    - When game.exe runs → shows your code
//    - Defeats "scan from trusted process" technique
//
// 3. THREAD HIJACKING (Thread Creation Detection Bypass)
//    - No new threads created
//    - Hijack existing game thread via syscall interception
//    - Inject code into existing execution flow
//
// 4. IMPORT-FREE SHELLCODE (DLL Whitelist Bypass)
//    - No DLL loading, no LDR entries
//    - Pure position-independent shellcode
//    - Self-contained execution
//
// Architecture:
//   ┌─────────────────────────────────────────────────────────────────┐
//   │                    NPT/EPT DUAL VIEW                            │
//   │  ┌─────────────────────┐    ┌─────────────────────┐            │
//   │  │  CLEAN VIEW         │    │  CHEAT VIEW         │            │
//   │  │  (AC sees this)     │    │  (Game runs this)   │            │
//   │  │                     │    │                     │            │
//   │  │  Original code      │    │  Hooked code +      │            │
//   │  │  No modifications   │    │  Your shellcode     │            │
//   │  └─────────────────────┘    └─────────────────────┘            │
//   │           ↑                          ↑                          │
//   │    READ/WRITE access          EXECUTE access                    │
//   └─────────────────────────────────────────────────────────────────┘

namespace stealth {

// =============================================================================
// 1. SHADOW CODE HOOK - Defeats Integrity Checks
// =============================================================================
// Instead of modifying game code directly (which AC can detect by comparing
// bytes), we create a SHADOW page. When AC reads the page, it sees the
// original clean bytes. When CPU executes it, it runs your hooked code.

struct shadow_hook_t {
  uint64_t target_va;         // Virtual address in game to hook
  uint64_t target_pa;         // Physical address of target page
  uint64_t shadow_pa;         // Physical address of shadow (modified) page
  uint64_t original_bytes[2]; // Original instruction bytes (for unhook)
  uint64_t hook_rip;          // Where to redirect execution
  bool active;
};

// Add a shadow code hook at target_va
// When AC reads this address -> sees original bytes
// When game executes this address -> runs your code at hook_destination
// Returns: hook ID (0 = failure)
uint64_t
add_shadow_hook(uint64_t target_cr3,       // Game's CR3
                uint64_t target_va,        // Address to hook
                uint64_t hook_destination, // Where to jump (your shellcode)
                uint8_t hook_size          // Bytes to overwrite (usually 12-14)
);

// Remove a shadow hook and restore original execution
uint64_t remove_shadow_hook(uint64_t hook_id);

// =============================================================================
// 2. PROCESS-AWARE HIDING - Defeats Handle Abuse Scans
// =============================================================================
// Anti-cheats open handles to your game from trusted processes (explorer.exe,
// csrss.exe, etc) and scan memory. We detect which process is accessing
// memory and show different views.

// List of processes that should see "clean" memory
struct scanner_process_t {
  uint64_t cr3;  // CR3 of the scanner process
  char name[16]; // Process name for debug
  bool active;
};

// Register a process as a "scanner" - it will see clean memory
uint64_t register_scanner_process(const char *process_name);

// Register by CR3 directly
uint64_t register_scanner_cr3(uint64_t cr3);

// Clear all scanner processes
void clear_scanner_processes();

// Check if current execution context is a scanner
bool is_scanner_active();

// =============================================================================
// 3. THREAD HIJACK EXECUTION - No Thread Creation
// =============================================================================
// Instead of CreateRemoteThread (which is detected), we:
// 1. Hook a frequently-called function in the game
// 2. When game calls it, redirect to our code
// 3. Execute our payload, then return to original function
//
// This is like "piggy-backing" on existing game threads.

// Set up thread hijack - your shellcode will execute when game calls
// target_func target_func: Game function to hijack (e.g., a render function
// called every frame) shellcode: Your code to execute one_shot: If true, unhook
// after first execution
uint64_t setup_thread_hijack(uint64_t target_cr3, uint64_t target_func,
                             const void *shellcode, uint64_t shellcode_size,
                             bool one_shot);

// =============================================================================
// 4. SHELLCODE GENERATION HELPERS
// =============================================================================
// Anti-cheats check DLL whitelist. Solution: Don't use DLLs!
// Convert your cheat to position-independent shellcode.

// Generate a simple "call function" shellcode
// Returns shellcode that: calls func_addr with up to 4 args, then returns
void generate_call_shellcode(uint8_t *output, uint64_t *output_size,
                             uint64_t func_addr, uint64_t arg1, uint64_t arg2,
                             uint64_t arg3, uint64_t arg4);

// Generate shellcode that writes value to address
void generate_write_shellcode(uint8_t *output, uint64_t *output_size,
                              uint64_t target_addr, const void *value,
                              uint64_t value_size);

// =============================================================================
// 5. COMBINED STEALTH INJECTION
// =============================================================================
// The ultimate stealth injection:
// 1. Allocate hidden memory for shellcode
// 2. Set up shadow hooks to redirect game execution
// 3. Register AC processes as scanners (they see clean memory)
// 4. Execute via thread hijack (no new threads)

struct stealth_injection_t {
  uint64_t hidden_region_id; // Hidden memory for shellcode
  uint64_t shadow_hook_id;   // Shadow hook for execution redirect
  uint64_t hijack_id;        // Thread hijack entry point
  uint64_t target_cr3;       // Game's CR3
  bool active;
};

// Perform stealth injection
// shellcode: Position-independent code to run
// entry_point_va: Where in game to hijack execution
// Returns: injection context for management
stealth_injection_t *
inject_stealth(uint64_t target_cr3,
               uint64_t entry_point_va, // Game function to hijack
               const void *shellcode, uint64_t shellcode_size);

// Remove stealth injection completely
void eject_stealth(stealth_injection_t *injection);

} // namespace stealth
