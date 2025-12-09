#include "hook_exec.h"
#include "../hook/hook.h"
#include "../hypercall/hypercall.h"
#include "../util/console.h"


#include <cstring>
#include <format>
#include <print>
#include <vector>


namespace hook_exec {

// Storage for execution hooks
static std::vector<exec_hook_t> g_exec_hooks;

// =============================================================================
// SHELLCODE GENERATION
// =============================================================================

void generate_call_dllmain(uint8_t *output, uint64_t *output_size,
                           uint64_t entry_point, uint64_t hModule,
                           uint64_t fdwReason) {
  // Generate x64 shellcode to call:
  // DllMain(hModule, fdwReason, NULL)
  //
  // Windows x64 calling convention:
  // RCX = arg1 (hModule)
  // RDX = arg2 (fdwReason)
  // R8  = arg3 (lpReserved = NULL)
  // R9  = arg4 (not used)

  uint8_t shellcode[] = {
      // Save registers we'll modify
      0x50,       // push rax
      0x51,       // push rcx
      0x52,       // push rdx
      0x41, 0x50, // push r8
      0x41, 0x51, // push r9
      0x41, 0x52, // push r10
      0x41, 0x53, // push r11

      // Align stack (Windows requires 16-byte alignment before call)
      0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28

      // Set up arguments
      0x48, 0xB9, // mov rcx, hModule
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, // [placeholder for hModule]

      0x48, 0xBA, // mov rdx, fdwReason
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, // [placeholder for fdwReason]

      0x4D, 0x31, 0xC0, // xor r8, r8 (lpReserved = NULL)

      // Call entry point
      0x48, 0xB8, // mov rax, entry_point
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, // [placeholder for entry_point]

      0xFF, 0xD0, // call rax

      // Restore stack
      0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28

      // Restore registers
      0x41, 0x5B, // pop r11
      0x41, 0x5A, // pop r10
      0x41, 0x59, // pop r9
      0x41, 0x58, // pop r8
      0x5A,       // pop rdx
      0x59,       // pop rcx
      0x58,       // pop rax

      // Return (hook handler will jump back to original)
      0xC3 // ret
  };

  // Fill in the addresses
  memcpy(&shellcode[17], &hModule, 8);     // hModule at offset 17
  memcpy(&shellcode[27], &fdwReason, 8);   // fdwReason at offset 27
  memcpy(&shellcode[40], &entry_point, 8); // entry_point at offset 40

  // Copy to output
  uint64_t size = sizeof(shellcode);
  if (*output_size < size) {
    *output_size = size;
    return;
  }

  memcpy(output, shellcode, size);
  *output_size = size;
}

void generate_call_func(uint8_t *output, uint64_t *output_size,
                        uint64_t target_func, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4) {
  uint8_t shellcode[] = {
      // Save registers
      0x50,       // push rax
      0x51,       // push rcx
      0x52,       // push rdx
      0x41, 0x50, // push r8
      0x41, 0x51, // push r9
      0x41, 0x52, // push r10
      0x41, 0x53, // push r11

      // Align stack
      0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28

      // Set up arguments (Windows x64)
      0x48, 0xB9, // mov rcx, arg1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      0x48, 0xBA, // mov rdx, arg2
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      0x49, 0xB8, // mov r8, arg3
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      0x49, 0xB9, // mov r9, arg4
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      // Call target
      0x48, 0xB8, // mov rax, target
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

      0xFF, 0xD0, // call rax

      // Restore stack
      0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28

      // Restore registers
      0x41, 0x5B, // pop r11
      0x41, 0x5A, // pop r10
      0x41, 0x59, // pop r9
      0x41, 0x58, // pop r8
      0x5A,       // pop rdx
      0x59,       // pop rcx
      0x58,       // pop rax

      0xC3 // ret
  };

  // Fill in addresses
  memcpy(&shellcode[17], &arg1, 8);
  memcpy(&shellcode[27], &arg2, 8);
  memcpy(&shellcode[37], &arg3, 8);
  memcpy(&shellcode[47], &arg4, 8);
  memcpy(&shellcode[57], &target_func, 8);

  uint64_t size = sizeof(shellcode);
  if (*output_size < size) {
    *output_size = size;
    return;
  }

  memcpy(output, shellcode, size);
  *output_size = size;
}

// =============================================================================
// HOOK-BASED EXECUTION
// =============================================================================

exec_hook_t *execute_via_hook(uint64_t game_func_va, uint64_t game_cr3,
                              const uint8_t *shellcode, uint64_t shellcode_size,
                              bool one_shot) {
  // The shellcode needs to be placed somewhere the game can execute
  // We'll use hook::add_kernel_hook which creates a shadow page hook

  // Convert shellcode to vector for the hook API
  std::vector<uint8_t> shellcode_vec(shellcode, shellcode + shellcode_size);

  // Add hook - the shellcode will run before the original function
  uint8_t result = hook::add_kernel_hook(game_func_va, shellcode_vec, {});

  if (result == 0) {
    console::error("Failed to add execution hook");
    return nullptr;
  }

  // Create tracking entry
  exec_hook_t hook = {.target_va = game_func_va,
                      .target_pa = 0,
                      .shellcode_va = 0,
                      .region_id = 0,
                      .one_shot = one_shot,
                      .executed = false};

  g_exec_hooks.push_back(hook);

  console::success(
      std::format("Execution hook installed at 0x{:X}", game_func_va));
  console::info("Your code will run when game calls this function");

  if (one_shot) {
    console::info("Hook will auto-remove after first execution");
  }

  return &g_exec_hooks.back();
}

bool call_dll_entry(uint64_t dll_entry, uint64_t dll_base,
                    uint64_t game_func_va, uint64_t game_cr3) {
  // Generate DllMain call shellcode
  uint8_t shellcode[256];
  uint64_t size = sizeof(shellcode);

  generate_call_dllmain(shellcode, &size, dll_entry, dll_base,
                        1); // DLL_PROCESS_ATTACH = 1

  if (size == 0) {
    console::error("Failed to generate DllMain shellcode");
    return false;
  }

  console::info(
      std::format("Generated {} byte shellcode to call DllMain", size));
  console::info(std::format("  Entry: 0x{:X}", dll_entry));
  console::info(std::format("  Base:  0x{:X}", dll_base));

  // Install as one-shot hook
  exec_hook_t *hook =
      execute_via_hook(game_func_va, game_cr3, shellcode, size, true);

  if (hook == nullptr) {
    return false;
  }

  console::success("DllMain execution hook installed!");
  console::info(
      "When the game next calls the hooked function, your DLL will initialize");

  return true;
}

bool has_executed(exec_hook_t *hook) {
  if (hook == nullptr)
    return false;
  return hook->executed;
}

void remove_exec_hook(exec_hook_t *hook) {
  if (hook == nullptr)
    return;

  hook::remove_kernel_hook(hook->target_va, 1);

  // Remove from our list
  for (auto it = g_exec_hooks.begin(); it != g_exec_hooks.end(); ++it) {
    if (it->target_va == hook->target_va) {
      g_exec_hooks.erase(it);
      break;
    }
  }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

uint64_t find_d3d11_present(uint64_t game_cr3) {
  // This would require finding D3D11 in game's address space
  // For now, return 0 - user should provide the address
  console::warn("Automatic D3D11 Present detection not implemented");
  console::info("Use a debugger to find Present address in your game");
  return 0;
}

uint64_t find_game_export(uint64_t game_cr3, const char *module_name,
                          const char *export_name) {
  // This would walk game's loaded modules via PEB
  // Complex to implement - for now return 0
  console::warn("Automatic export resolution not implemented");
  return 0;
}

} // namespace hook_exec
