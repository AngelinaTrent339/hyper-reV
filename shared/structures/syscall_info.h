#pragma once
#include <cstdint>

// ============================================================================
// SYSCALL TRACING STRUCTURES
// Used for IA32_LSTAR-based syscall interception
// ============================================================================

#pragma pack(push, 1)

// Syscall log entry
struct syscall_log_t {
  std::uint64_t timestamp;    // TSC when syscall occurred
  std::uint64_t syscall_id;   // Syscall number (from rax)
  std::uint64_t arg1;         // rcx
  std::uint64_t arg2;         // rdx
  std::uint64_t arg3;         // r8
  std::uint64_t arg4;         // r9
  std::uint64_t caller_rip;   // Return address (where syscall was called)
  std::uint64_t caller_cr3;   // Which process made the call
  std::uint64_t return_value; // Return value (rax after syscall)
  std::uint64_t stack_arg5;   // 5th argument from stack
  std::uint64_t stack_arg6;   // 6th argument from stack
};

// Common syscall IDs for Windows (useful for filtering)
namespace syscall_ids {
// Memory operations (what Hyperion uses to scan)
constexpr std::uint64_t NtReadVirtualMemory = 0x3F;
constexpr std::uint64_t NtWriteVirtualMemory = 0x3A;
constexpr std::uint64_t NtQueryVirtualMemory = 0x23;
constexpr std::uint64_t NtProtectVirtualMemory = 0x50;
constexpr std::uint64_t NtAllocateVirtualMemory = 0x18;
constexpr std::uint64_t NtFreeVirtualMemory = 0x1E;

// Process/Thread operations
constexpr std::uint64_t NtOpenProcess = 0x26;
constexpr std::uint64_t NtOpenThread = 0x127;
constexpr std::uint64_t NtQueryInformationProcess = 0x19;
constexpr std::uint64_t NtQueryInformationThread = 0x25;
constexpr std::uint64_t NtSetInformationThread = 0x0D;
constexpr std::uint64_t NtCreateThreadEx = 0xBD;

// System information
constexpr std::uint64_t NtQuerySystemInformation = 0x36;

// Debug detection
constexpr std::uint64_t NtSetInformationProcess = 0x1C;
constexpr std::uint64_t NtDebugActiveProcess = 0x32;
} // namespace syscall_ids

#pragma pack(pop)
