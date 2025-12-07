#include "execute.h"
#include "../crt/crt.h"
#include "../memory/memory.h"
#include "../memory_manager/memory_manager.h"
#include "../process/process.h"
#include "../slat/hook/hook.h"
#include "../slat/slat.h"


namespace code_execute {
// ========================================================================
// GLOBAL STATE
// ========================================================================

exec_context_t pending_exec = {};
bool execution_pending = false;
bool execution_complete = false;

// ========================================================================
// INITIALIZATION
// ========================================================================

void init() {
  crt::set_memory(&pending_exec, 0, sizeof(pending_exec));
  execution_pending = false;
  execution_complete = false;
}

// ========================================================================
// SHELLCODE WRITING
// Write shellcode to guest memory via NPT (invisible to AC)
// ========================================================================

std::uint64_t write_shellcode(std::uint64_t target_cr3, std::uint64_t target_va,
                              const std::uint8_t *shellcode,
                              std::uint64_t shellcode_size,
                              bool cloak_memory_flag) {
  const cr3 slat_cr3 = slat::hyperv_cr3();

  // Write shellcode page by page
  std::uint64_t written = 0;
  while (written < shellcode_size) {
    std::uint64_t current_va = target_va + written;
    std::uint64_t remaining = shellcode_size - written;

    // Translate to GPA
    std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
        {.flags = target_cr3}, slat_cr3, {.address = current_va});

    if (gpa == 0)
      break;

    // Calculate page limits
    std::uint64_t page_offset = current_va & 0xFFF;
    std::uint64_t page_remaining = 0x1000 - page_offset;
    std::uint64_t to_write =
        (remaining < page_remaining) ? remaining : page_remaining;

    // Map and write
    std::uint64_t size_left = 0;
    void *mapped =
        memory_manager::map_guest_physical(slat_cr3, gpa, &size_left);
    if (!mapped || size_left < to_write)
      break;

    crt::copy_memory(mapped, shellcode + written, to_write);

    // Enable cloaking if requested (show zeros to AC, real code to CPU)
    if (cloak_memory_flag) {
      // We'd need a "clean" shadow page here
      // For now, hook::add_entry would redirect reads
      // Full implementation would create zeroed shadow page
    }

    written += to_write;
  }

  return (written == shellcode_size) ? target_va : 0;
}

// ========================================================================
// CODE EXECUTION
// ========================================================================

bool execute_at(std::uint64_t target_cr3, std::uint64_t shellcode_va,
                std::uint64_t parameter, exec_method_t method) {
  // Store execution context
  pending_exec.target_cr3 = target_cr3;
  pending_exec.shellcode_va = shellcode_va;
  pending_exec.parameter = parameter;
  pending_exec.result = 0;
  pending_exec.executed = 0;
  pending_exec.error_code = 0;

  execution_pending = true;
  execution_complete = false;

  // The actual execution trigger depends on the method:
  //
  // method_code_cave:
  //   - Write a detour hook at a frequently-called function
  //   - When function is called, our shellcode runs first
  //   - Restore original bytes after execution
  //
  // method_hijack_thread:
  //   - Find a suspended/waiting thread
  //   - Modify its RIP in KTHREAD/TrapFrame
  //   - When thread resumes, it runs our code
  //
  // method_exception:
  //   - Register exception handler via RtlAddVectoredExceptionHandler
  //   - Trigger exception (divide by zero, breakpoint)
  //   - Our handler runs
  //
  // method_apc:
  //   - Queue APC to alertable thread
  //   - APC runs our shellcode
  //
  // For now, we just mark execution as pending
  // The VM exit handler will check this and inject when appropriate

  return true;
}

std::uint64_t call_function(std::uint64_t target_cr3,
                            std::uint64_t function_address, std::uint64_t arg1,
                            std::uint64_t arg2, std::uint64_t arg3,
                            std::uint64_t arg4) {
  // Build a small shellcode stub that calls the function
  // x64 calling convention: RCX, RDX, R8, R9

  // Shellcode template:
  // mov rcx, arg1
  // mov rdx, arg2
  // mov r8, arg3
  // mov r9, arg4
  // sub rsp, 0x28      ; Shadow space
  // call [function]
  // add rsp, 0x28
  // ret (or signal completion)

  std::uint8_t shellcode[128] = {
      // mov rcx, arg1       ; 48 B9 xx xx xx xx xx xx xx xx
      0x48, 0xB9, static_cast<std::uint8_t>(arg1 >> 0),
      static_cast<std::uint8_t>(arg1 >> 8),
      static_cast<std::uint8_t>(arg1 >> 16),
      static_cast<std::uint8_t>(arg1 >> 24),
      static_cast<std::uint8_t>(arg1 >> 32),
      static_cast<std::uint8_t>(arg1 >> 40),
      static_cast<std::uint8_t>(arg1 >> 48),
      static_cast<std::uint8_t>(arg1 >> 56),

      // mov rdx, arg2       ; 48 BA xx xx xx xx xx xx xx xx
      0x48, 0xBA, static_cast<std::uint8_t>(arg2 >> 0),
      static_cast<std::uint8_t>(arg2 >> 8),
      static_cast<std::uint8_t>(arg2 >> 16),
      static_cast<std::uint8_t>(arg2 >> 24),
      static_cast<std::uint8_t>(arg2 >> 32),
      static_cast<std::uint8_t>(arg2 >> 40),
      static_cast<std::uint8_t>(arg2 >> 48),
      static_cast<std::uint8_t>(arg2 >> 56),

      // mov r8, arg3        ; 49 B8 xx xx xx xx xx xx xx xx
      0x49, 0xB8, static_cast<std::uint8_t>(arg3 >> 0),
      static_cast<std::uint8_t>(arg3 >> 8),
      static_cast<std::uint8_t>(arg3 >> 16),
      static_cast<std::uint8_t>(arg3 >> 24),
      static_cast<std::uint8_t>(arg3 >> 32),
      static_cast<std::uint8_t>(arg3 >> 40),
      static_cast<std::uint8_t>(arg3 >> 48),
      static_cast<std::uint8_t>(arg3 >> 56),

      // mov r9, arg4        ; 49 B9 xx xx xx xx xx xx xx xx
      0x49, 0xB9, static_cast<std::uint8_t>(arg4 >> 0),
      static_cast<std::uint8_t>(arg4 >> 8),
      static_cast<std::uint8_t>(arg4 >> 16),
      static_cast<std::uint8_t>(arg4 >> 24),
      static_cast<std::uint8_t>(arg4 >> 32),
      static_cast<std::uint8_t>(arg4 >> 40),
      static_cast<std::uint8_t>(arg4 >> 48),
      static_cast<std::uint8_t>(arg4 >> 56),

      // sub rsp, 0x28       ; 48 83 EC 28
      0x48, 0x83, 0xEC, 0x28,

      // mov rax, function   ; 48 B8 xx xx xx xx xx xx xx xx
      0x48, 0xB8, static_cast<std::uint8_t>(function_address >> 0),
      static_cast<std::uint8_t>(function_address >> 8),
      static_cast<std::uint8_t>(function_address >> 16),
      static_cast<std::uint8_t>(function_address >> 24),
      static_cast<std::uint8_t>(function_address >> 32),
      static_cast<std::uint8_t>(function_address >> 40),
      static_cast<std::uint8_t>(function_address >> 48),
      static_cast<std::uint8_t>(function_address >> 56),

      // call rax            ; FF D0
      0xFF, 0xD0,

      // add rsp, 0x28       ; 48 83 C4 28
      0x48, 0x83, 0xC4, 0x28,

      // ret                 ; C3
      0xC3};

  // Find a code cave to place our stub
  // For now, return 0 - full implementation would:
  // 1. Find code cave
  // 2. Write shellcode
  // 3. Execute shellcode
  // 4. Return result

  return 0;
}

// ========================================================================
// CODE CAVE FINDING
// ========================================================================

std::uint64_t find_code_cave(std::uint64_t target_cr3,
                             std::uint64_t module_base,
                             std::uint64_t module_size,
                             std::uint64_t required_size) {
  // Scan for sequences of 0x00 or 0xCC (int3 padding)
  std::uint8_t buffer[0x1000];

  for (std::uint64_t offset = 0; offset < module_size; offset += 0x1000) {
    std::uint64_t current_addr = module_base + offset;
    std::uint64_t remaining = module_size - offset;
    std::uint64_t to_scan = (remaining < 0x1000) ? remaining : 0x1000;

    if (memory_analysis::read_memory(target_cr3, current_addr, buffer,
                                     to_scan) != to_scan)
      continue;

    // Look for code cave (sequence of 0x00 or 0xCC)
    std::uint64_t cave_start = 0;
    std::uint64_t cave_size = 0;

    for (std::uint64_t i = 0; i < to_scan; i++) {
      if (buffer[i] == 0x00 || buffer[i] == 0xCC || buffer[i] == 0x90) {
        if (cave_size == 0)
          cave_start = current_addr + i;
        cave_size++;

        if (cave_size >= required_size)
          return cave_start;
      } else {
        cave_size = 0;
      }
    }
  }

  return 0; // No suitable cave found
}

// ========================================================================
// EXECUTION STATE
// ========================================================================

bool is_complete() { return execution_complete; }

std::uint64_t get_result() { return pending_exec.result; }

void on_execution_complete(std::uint64_t result) {
  pending_exec.result = result;
  pending_exec.executed = 1;
  execution_complete = true;
  execution_pending = false;
}
} // namespace code_execute
