#pragma once
#include <cstdint>

namespace code_execute {
// ========================================================================
// HYPERVISOR-LEVEL CODE EXECUTION
//
// This bypasses ALL anti-cheat injection detection because:
//
// 1. NO INJECTION APIS USED
//    - No CreateRemoteThread, NtCreateThreadEx, QueueUserAPC
//    - No LoadLibrary, LdrLoadDll, manual mapping
//    - We write directly to guest memory via NPT!
//
// 2. INVISIBLE TO PROCESS SCANS
//    - We can use memory cloaking (Phase 6) to show AC "clean" bytes
//    - Real code runs in shadow pages that AC cannot see
//
// 3. RING -1 PRIVILEGE
//    - Hypervisor runs above kernel
//    - AC's kernel driver cannot detect our modifications
//
// 4. NO THREAD CREATION
//    - We hijack existing threads (exception handler, APC, etc)
//    - Or use CPU interrupt injection
//
// HOW IT WORKS:
// 1. Allocate executable memory in guest (or find code cave)
// 2. Write shellcode via NPT (invisible to AC)
// 3. Enable memory cloaking (AC sees zeros, we see shellcode)
// 4. Hijack execution (ROP, exception handler, or interrupt)
// 5. Shellcode runs with full guest privileges
// ========================================================================

// Execution context
struct exec_context_t {
  std::uint64_t target_cr3;
  std::uint64_t shellcode_va;
  std::uint64_t shellcode_size;
  std::uint64_t parameter;
  std::uint64_t return_address;

  // Return state after execution
  std::uint64_t result;
  std::uint64_t executed;
  std::uint64_t error_code;
};

// Execution method
enum class exec_method_t : std::uint8_t {
  method_code_cave,     // Write to existing code cave
  method_alloc_rwx,     // Allocate RWX memory (more detectable)
  method_hijack_thread, // Hijack suspended thread
  method_exception,     // Trigger exception handler
  method_apc,           // Queue APC to thread
  method_int3,          // INT 3 breakpoint hook
};

// State
extern exec_context_t pending_exec;
extern bool execution_pending;
extern bool execution_complete;

// ========================================================================
// CODE EXECUTION FUNCTIONS
// ========================================================================

// Initialize
void init();

// Write shellcode to guest memory (invisible via NPT)
// Returns virtual address of written shellcode
std::uint64_t write_shellcode(std::uint64_t target_cr3, std::uint64_t target_va,
                              const std::uint8_t *shellcode,
                              std::uint64_t shellcode_size,
                              bool cloak_memory = true);

// Execute shellcode at address
// This sets up hijack and waits for execution
bool execute_at(std::uint64_t target_cr3, std::uint64_t shellcode_va,
                std::uint64_t parameter = 0,
                exec_method_t method = exec_method_t::method_code_cave);

// Call function at address with up to 4 args
std::uint64_t call_function(std::uint64_t target_cr3,
                            std::uint64_t function_address,
                            std::uint64_t arg1 = 0, std::uint64_t arg2 = 0,
                            std::uint64_t arg3 = 0, std::uint64_t arg4 = 0);

// ========================================================================
// CODE CAVE FINDING
// Find suitable code caves in existing modules
// ========================================================================

// Find code cave in module
// Returns VA of suitable cave or 0 if not found
std::uint64_t find_code_cave(std::uint64_t target_cr3,
                             std::uint64_t module_base,
                             std::uint64_t module_size,
                             std::uint64_t required_size);

// ========================================================================
// THREAD HIJACKING
// Hijack thread RIP to execute our code
// ========================================================================

// Get thread context (RIP, RSP, etc)
bool get_thread_context(std::uint64_t target_cr3, std::uint64_t thread_ethread,
                        std::uint64_t &rip, std::uint64_t &rsp);

// Set thread RIP (for hijacking)
bool set_thread_rip(std::uint64_t target_cr3, std::uint64_t thread_ethread,
                    std::uint64_t new_rip);

// ========================================================================
// EXECUTION COMPLETION
// Called when shellcode finishes
// ========================================================================

// Check if execution completed
bool is_complete();

// Get result
std::uint64_t get_result();

// Called from shellcode to signal completion
void on_execution_complete(std::uint64_t result);
} // namespace code_execute
