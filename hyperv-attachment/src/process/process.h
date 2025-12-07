#pragma once
#include <cstdint>
#include <structures/process_info.h>

namespace process {
// ========================================================================
// PROCESS TARGETING
// Target a specific process by CR3 for filtered operations
// ========================================================================

// Current target CR3 (0 = all processes)
extern std::uint64_t g_target_cr3;

// Windows kernel offsets (must be set before enumeration works)
extern windows_offsets_t g_offsets;
extern bool g_offsets_initialized;

// Set target process CR3 (0 = clear target, monitor all)
void attach(std::uint64_t cr3);

// Clear target, operate on all processes
void detach();

// Check if current guest context matches target
bool is_target_context();

// Get target CR3
std::uint64_t get_target_cr3();

// ========================================================================
// PROCESS ENUMERATION
// Walk kernel structures to enumerate processes
// ========================================================================

// Set Windows kernel offsets (required before enumeration)
void set_offsets(const windows_offsets_t &offsets);

// Find process CR3 by name (returns 0 if not found)
std::uint64_t find_by_name(const char *name);

// Enumerate all processes into buffer
// Returns number of processes found
std::uint64_t enumerate(process_info_t *buffer, std::uint64_t max_count);

// Get process info by CR3
bool get_info(std::uint64_t cr3, process_info_t *info);

// ========================================================================
// MODULE ENUMERATION
// Walk PEB->Ldr to get loaded modules
// ========================================================================

// Enumerate modules for a process
// cr3 = target process CR3
// peb = PEB address (from process_info_t)
std::uint64_t enumerate_modules(std::uint64_t cr3, std::uint64_t peb,
                                module_info_t *buffer, std::uint64_t max_count);

// Find module by name in process
bool find_module(std::uint64_t cr3, std::uint64_t peb, const wchar_t *name,
                 module_info_t *info);

} // namespace process
