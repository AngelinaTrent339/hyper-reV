#pragma once
#include <cstdint>

// ============================================================================
// PROCESS TARGETING STRUCTURES
// Used for process enumeration and targeting via CR3
// ============================================================================

#pragma pack(push, 1)

// Process information returned by get_process_list
struct process_info_t {
  std::uint64_t eprocess; // Kernel EPROCESS address
  std::uint64_t cr3;      // DirectoryTableBase (page directory)
  std::uint64_t pid;      // Process ID
  std::uint64_t peb;      // PEB address (usermode)
  char image_name[16];    // Process name (from ImageFileName)
};

// Module information returned by enumerate_modules
struct module_info_t {
  std::uint64_t dll_base;      // Base address of module
  std::uint64_t size_of_image; // Size of module in memory
  std::uint64_t entry_point;   // Entry point RVA
  wchar_t name[64];            // Module name (BaseDllName)
};

// VAD (Virtual Address Descriptor) information
struct vad_info_t {
  std::uint64_t start_address; // Start of region
  std::uint64_t end_address;   // End of region (inclusive)
  std::uint64_t protection;    // PAGE_* protection flags
  std::uint64_t vad_type;      // VadNone, VadDevicePhysicalMemory, etc.
  std::uint64_t is_private;    // Private vs mapped
  std::uint64_t commit_charge; // Committed pages
  wchar_t file_name[128];      // Backing file if mapped
};

#pragma pack(pop)

// ============================================================================
// WINDOWS KERNEL OFFSETS
// Must be set via set_windows_offsets hypercall before process enumeration
// ============================================================================

struct windows_offsets_t {
  // _EPROCESS offsets
  std::uint64_t eprocess_ActiveProcessLinks;
  std::uint64_t eprocess_ImageFileName;
  std::uint64_t eprocess_UniqueProcessId;
  std::uint64_t eprocess_DirectoryTableBase;
  std::uint64_t eprocess_Peb;
  std::uint64_t eprocess_VadRoot;
  std::uint64_t eprocess_ThreadListHead;

  // _PEB offsets
  std::uint64_t peb_Ldr;
  std::uint64_t peb_BeingDebugged;
  std::uint64_t peb_ProcessParameters;

  // _PEB_LDR_DATA offsets
  std::uint64_t ldr_InLoadOrderModuleList;
  std::uint64_t ldr_InMemoryOrderModuleList;

  // _LDR_DATA_TABLE_ENTRY offsets
  std::uint64_t ldr_entry_InLoadOrderLinks;
  std::uint64_t ldr_entry_DllBase;
  std::uint64_t ldr_entry_SizeOfImage;
  std::uint64_t ldr_entry_EntryPoint;
  std::uint64_t ldr_entry_BaseDllName;
  std::uint64_t ldr_entry_FullDllName;

  // VAD offsets (for _MMVAD / _MMVAD_SHORT)
  std::uint64_t vad_Left;
  std::uint64_t vad_Right;
  std::uint64_t vad_StartingVpn;
  std::uint64_t vad_EndingVpn;
  std::uint64_t vad_StartingVpnHigh;
  std::uint64_t vad_EndingVpnHigh;
  std::uint64_t vad_VadFlags;
  std::uint64_t vad_Subsection;

  // Kernel base addresses
  std::uint64_t ntoskrnl_base;
  std::uint64_t PsInitialSystemProcess;
};
