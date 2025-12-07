#pragma once
#include <cstdint>
#include <structures/process_info.h>

// ============================================================================
// WINDOWS 11 24H2 KERNEL OFFSETS
// Extracted from PDB symbols - use set_windows_offsets() hypercall to apply
// ============================================================================

namespace windows_24h2 {
// Pre-configured offsets for Windows 11 24H2
inline windows_offsets_t get_offsets() {
  windows_offsets_t offsets = {};

  // _EPROCESS offsets
  offsets.eprocess_ActiveProcessLinks = 0x1D8; // struct _LIST_ENTRY
  offsets.eprocess_ImageFileName = 0x338;      // UCHAR[15]
  offsets.eprocess_UniqueProcessId = 0x1D0;    // VOID*
  offsets.eprocess_DirectoryTableBase = 0x28;  // In KPROCESS (Pcb at 0x0)
  offsets.eprocess_Peb = 0x2E0;                // struct _PEB*
  offsets.eprocess_VadRoot = 0x558;            // struct _RTL_AVL_TREE
  offsets.eprocess_ThreadListHead = 0x370;     // struct _LIST_ENTRY

  // _PEB offsets (64-bit)
  offsets.peb_Ldr = 0x18;               // ULONGLONG (PEB_LDR_DATA*)
  offsets.peb_BeingDebugged = 0x2;      // UCHAR
  offsets.peb_ProcessParameters = 0x20; // ULONGLONG

  // _PEB_LDR_DATA offsets
  offsets.ldr_InLoadOrderModuleList = 0x10;   // struct _LIST_ENTRY
  offsets.ldr_InMemoryOrderModuleList = 0x20; // struct _LIST_ENTRY

  // _LDR_DATA_TABLE_ENTRY offsets
  offsets.ldr_entry_InLoadOrderLinks = 0x0; // struct _LIST_ENTRY
  offsets.ldr_entry_DllBase = 0x30;         // VOID*
  offsets.ldr_entry_SizeOfImage = 0x40;     // ULONG
  offsets.ldr_entry_EntryPoint = 0x38;      // VOID*
  offsets.ldr_entry_BaseDllName = 0x58;     // struct _UNICODE_STRING
  offsets.ldr_entry_FullDllName = 0x48;     // struct _UNICODE_STRING

  // VAD offsets (_MMVAD_SHORT)
  // Note: VAD uses RTL_BALANCED_NODE at 0x0 for tree traversal
  offsets.vad_Left = 0x0;             // RTL_BALANCED_NODE.Left
  offsets.vad_Right = 0x8;            // RTL_BALANCED_NODE.Right
  offsets.vad_StartingVpn = 0x18;     // ULONG
  offsets.vad_EndingVpn = 0x1c;       // ULONG
  offsets.vad_StartingVpnHigh = 0x20; // UCHAR
  offsets.vad_EndingVpnHigh = 0x21;   // UCHAR
  offsets.vad_VadFlags = 0x30;        // union u.LongFlags
  offsets.vad_Subsection = 0x48;      // struct _SUBSECTION* (in full MMVAD)

  // Kernel base addresses - MUST be set at runtime via ntoskrnl.exe parsing
  offsets.ntoskrnl_base = 0;          // Set by usermode
  offsets.PsInitialSystemProcess = 0; // Set by usermode (offset from base)

  return offsets;
}

// DirectoryTableBase is in KPROCESS which is at offset 0 in EPROCESS
// The actual offset within KPROCESS varies - typically 0x28 for the page
// directory
constexpr std::uint64_t KPROCESS_DirectoryTableBase = 0x28;
} // namespace windows_24h2
