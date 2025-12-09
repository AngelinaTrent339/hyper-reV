#pragma once
#include <cstdint>

// =============================================================================
// Hidden Allocation System
// =============================================================================
// This module provides the ability to allocate memory that is completely
// invisible to the guest OS. The memory is:
// 1. Backed by real physical pages allocated from the hypervisor heap
// 2. Hidden from the guest via SLAT (NPT/EPT) - guest sees zeros
// 3. Optionally visible to only a specific process (via CR3)
// 4. Can be made executable for code injection
//
// Use case: DLL injection that is invisible to anti-cheat/anti-virus
//
// Architecture:
// - allocate_hidden_region(): Allocates N pages from hypervisor heap,
//   hides them from guest SLAT, returns a "hidden region ID"
// - write_hidden_region(): Write data to hidden region (via hypervisor)
// - expose_hidden_region(): Make region visible in target process's CR3
// - hide_hidden_region(): Re-hide region from all processes
// - free_hidden_region(): Free the hidden region

namespace hidden_alloc {

// Maximum number of hidden regions we can track
constexpr std::uint32_t MAX_HIDDEN_REGIONS = 32;

// Maximum pages per region (16MB max per region)
constexpr std::uint32_t MAX_PAGES_PER_REGION = 4096;

// Region state
enum class region_state_t : std::uint8_t {
  free = 0,      // Slot is available
  allocated = 1, // Allocated but hidden from all
  exposed = 2,   // Exposed to a specific process CR3
  executable = 3 // Exposed and marked executable
};

// Hidden region descriptor
struct hidden_region_t {
  std::uint64_t id;        // Unique region ID (0 = invalid)
  region_state_t state;    // Current state
  std::uint8_t page_count; // Number of 4KB pages
  std::uint16_t reserved;
  std::uint64_t host_virtual_base;  // Base address in hypervisor space
  std::uint64_t host_physical_base; // Base physical address
  std::uint64_t
      guest_virtual_target; // Target VA in guest process (when exposed)
  std::uint64_t target_cr3; // CR3 of process this is exposed to
};

// Initialize the hidden allocation system
void init();

// Allocate a hidden region
// Returns: region ID (0 = failure)
std::uint64_t allocate_region(std::uint32_t page_count);

// Write data to a hidden region
// Returns: bytes written
std::uint64_t write_region(std::uint64_t region_id, std::uint64_t offset,
                           const void *data, std::uint64_t size);

// Read data from a hidden region (for verification)
// Returns: bytes read
std::uint64_t read_region(std::uint64_t region_id, std::uint64_t offset,
                          void *buffer, std::uint64_t size);

// Expose a hidden region to a specific process
// This makes the region visible ONLY when that process's CR3 is active
// target_va: Where in the process's virtual address space to map it
// target_cr3: The CR3 of the target process
// executable: Whether to mark the region as executable
// Returns: 1 on success
std::uint64_t expose_region(std::uint64_t region_id, std::uint64_t target_va,
                            std::uint64_t target_cr3, std::uint8_t executable);

// Hide a previously exposed region (make it invisible again)
// Returns: 1 on success
std::uint64_t hide_region(std::uint64_t region_id);

// Free a hidden region, returning pages to the heap
// Returns: 1 on success
std::uint64_t free_region(std::uint64_t region_id);

// Get region info
const hidden_region_t *get_region(std::uint64_t region_id);

// Get count of active regions
std::uint32_t get_active_region_count();

// Get the current active target CR3 (for process-specific exposure)
// This is checked on every SLAT violation to determine what to show
std::uint64_t get_exposed_target_cr3();

// Check if a guest physical address belongs to a hidden region
// Returns: region_id if found, 0 if not
std::uint64_t find_region_by_gpa(std::uint64_t guest_physical_address);

} // namespace hidden_alloc
