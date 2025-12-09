#pragma once
#include <cstdint>
#include <string>
#include <vector>

// =============================================================================
// Hidden DLL Injector
// =============================================================================
// This module provides the ability to inject a DLL into a target process
// using the hypervisor's hidden allocation system. The injected DLL is:
// - Completely invisible to the guest OS memory queries
// - Only visible when the target process is running
// - Compatible with any standard Windows x64 DLL
//
// Usage:
//   1. Load your DLL file
//   2. Call inject_hidden_dll() with target process CR3 and DLL data
//   3. The DLL will execute hidden from anti-cheat

namespace hidden_inject {

// Injection result codes
enum class inject_result_t : uint32_t {
  success = 0,
  invalid_dll = 1,
  allocation_failed = 2,
  mapping_failed = 3,
  relocation_failed = 4,
  import_failed = 5,
  execution_failed = 6
};

// Information about an injected DLL
struct injection_info_t {
  uint64_t region_id;     // Hidden region ID
  uint64_t image_base;    // Where the DLL is mapped in target
  uint64_t entry_point;   // DLL entry point (DllMain)
  uint64_t size_of_image; // Total size of mapped image
  uint64_t target_cr3;    // Target process CR3
  bool is_exposed;        // Whether currently exposed
};

// Load a DLL file from disk
// Returns: DLL data, empty on failure
std::vector<uint8_t> load_dll_file(const std::string &path);

// Parse and validate a DLL
// Returns: true if valid x64 DLL
bool validate_dll(const std::vector<uint8_t> &dll_data);

// Get required memory size for mapping a DLL
uint64_t get_required_size(const std::vector<uint8_t> &dll_data);

// Get the preferred base address from DLL
uint64_t get_preferred_base(const std::vector<uint8_t> &dll_data);

// Inject a DLL into target process using hidden allocation
// dll_data: Raw DLL file bytes
// target_cr3: CR3 of the target process
// preferred_base: Where to map (0 = use DLL's preferred base)
// call_entry: Whether to call DllMain after mapping
// info: Output - filled with injection details
// Returns: inject_result_t
inject_result_t inject_hidden_dll(const std::vector<uint8_t> &dll_data,
                                  uint64_t target_cr3, uint64_t preferred_base,
                                  bool call_entry, injection_info_t *info);

// Hide a previously exposed DLL (makes it invisible again)
inject_result_t hide_dll(uint64_t region_id);

// Re-expose a hidden DLL
inject_result_t expose_dll(uint64_t region_id, uint64_t target_cr3);

// Eject (unload) an injected DLL
inject_result_t eject_dll(uint64_t region_id);

// Get list of all injected DLLs
std::vector<injection_info_t> get_injected_dlls();

// Helper: Find process CR3 by name (wrapper around track functionality)
uint64_t find_process_cr3(const std::string &process_name,
                          uint32_t timeout_ms = 5000);

} // namespace hidden_inject
