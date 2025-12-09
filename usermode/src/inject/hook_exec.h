#pragma once
#include <cstdint>
#include <vector>

// =============================================================================
// HOOK-BASED DLL EXECUTION
// =============================================================================
// Execute DLL code WITHOUT creating threads
//
// Instead of CreateRemoteThread (detected), we:
// 1. Hook a game function using SLAT shadow pages
// 2. When game calls that function → your DLL code runs first
// 3. Then original function continues
// 4. No threads created, no API calls traced
//
// Perfect for:
// - Calling DllMain after hidden injection
// - Running any code in game context
// - Periodic execution (hook render loop)

namespace hook_exec {

// Information about a hook-based execution
struct exec_hook_t {
  uint64_t target_va;    // Game function we hooked
  uint64_t target_pa;    // Physical address
  uint64_t shellcode_va; // Where shellcode is mapped
  uint64_t region_id;    // Hidden region ID if using hidden memory
  bool one_shot;         // Remove hook after first execution?
  bool executed;         // Has it executed yet?
};

// =============================================================================
// SHELLCODE TEMPLATES
// =============================================================================

// Generate shellcode to call a function with no args (like
// DllMain(0,DLL_PROCESS_ATTACH,0)) entry_point: Address to call output: Buffer
// for generated shellcode output_size: [in] buffer size, [out] bytes written
void generate_call_dllmain(uint8_t *output, uint64_t *output_size,
                           uint64_t entry_point,
                           uint64_t hModule,  // Usually the image base
                           uint64_t fdwReason // Usually 1 (DLL_PROCESS_ATTACH)
);

// Generate a simple function call shellcode
// Calls: target_func(arg1, arg2, arg3, arg4)
void generate_call_func(uint8_t *output, uint64_t *output_size,
                        uint64_t target_func, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4);

// =============================================================================
// EXECUTION VIA HOOK
// =============================================================================

// Execute shellcode by hooking a game function
// game_func_va: A function the game calls frequently (like Present, or game
// loop) game_cr3: Game's page table shellcode: Code to execute shellcode_size:
// Size in bytes one_shot: If true, unhook after first execution Returns:
// exec_hook_t* for management
exec_hook_t *execute_via_hook(uint64_t game_func_va, uint64_t game_cr3,
                              const uint8_t *shellcode, uint64_t shellcode_size,
                              bool one_shot);

// Execute DllMain for an injected DLL
// This is the easy-to-use function that combines everything:
// 1. Generate DllMain call shellcode
// 2. Hook a game function
// 3. Wait for execution
// 4. Cleanup
//
// dll_entry: Entry point of your DLL (from inject command output)
// dll_base: Base address of your DLL
// game_func_va: Game function to hijack for execution
// game_cr3: Game's CR3
bool call_dll_entry(uint64_t dll_entry, uint64_t dll_base,
                    uint64_t game_func_va, uint64_t game_cr3);

// Check if a hook has executed
bool has_executed(exec_hook_t *hook);

// Remove an execution hook
void remove_exec_hook(exec_hook_t *hook);

// =============================================================================
// HELPER: FIND HOOKABLE GAME FUNCTIONS
// =============================================================================

// Common functions to hook for execution:
// - D3D11 Present (if game uses D3D11)
// - OpenGL SwapBuffers
// - Any function called every frame

// Find D3D11 Present function address
// Returns 0 if not found
uint64_t find_d3d11_present(uint64_t game_cr3);

// Find any exported function in a DLL loaded by the game
uint64_t find_game_export(uint64_t game_cr3, const char *module_name,
                          const char *export_name);

} // namespace hook_exec
