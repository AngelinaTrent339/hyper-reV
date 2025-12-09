#include "hidden_alloc.h"
#include "../../crt/crt.h"
#include "../../memory_manager/heap_manager.h"
#include "../../memory_manager/memory_manager.h"
#include "../cr3/cr3.h"
#include "../slat.h"


// =============================================================================
// Hidden Allocation System Implementation
// =============================================================================

namespace {

// Storage for hidden region descriptors
hidden_alloc::hidden_region_t regions[hidden_alloc::MAX_HIDDEN_REGIONS];

// Next region ID to assign
std::uint64_t next_region_id = 1;

// Flag indicating if system is initialized
std::uint8_t initialized = 0;

// Mutex for thread safety (simple spinlock)
crt::mutex_t alloc_mutex = {};
} // namespace

void hidden_alloc::init() {
  alloc_mutex.lock();

  crt::set_memory(regions, 0, sizeof(regions));
  next_region_id = 1;
  initialized = 1;

  alloc_mutex.release();
}

std::uint64_t hidden_alloc::allocate_region(std::uint32_t page_count) {
  if (page_count == 0 || page_count > MAX_PAGES_PER_REGION) {
    return 0; // Invalid page count
  }

  // Check if we have enough free heap pages
  if (heap_manager::get_free_page_count() < page_count + 1) {
    return 0; // Not enough memory
  }

  alloc_mutex.lock();

  if (!initialized) {
    init();
  }

  // Find a free region slot
  hidden_region_t *region = nullptr;
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].state == region_state_t::free) {
      region = &regions[i];
      break;
    }
  }

  if (region == nullptr) {
    alloc_mutex.release();
    return 0; // No free slots
  }

  // Allocate pages from hypervisor heap
  // We allocate contiguous pages for simplicity
  void *first_page = heap_manager::allocate_page();
  if (first_page == nullptr) {
    alloc_mutex.release();
    return 0;
  }

  // Get physical address of first page
  const std::uint64_t first_physical =
      memory_manager::unmap_host_physical(first_page);

  // Zero out the first page
  crt::set_memory(first_page, 0, 0x1000);

  // Allocate remaining pages (they should be contiguous from our heap)
  for (std::uint32_t i = 1; i < page_count; ++i) {
    void *page = heap_manager::allocate_page();
    if (page == nullptr) {
      // Failed to allocate all pages - free what we have and fail
      // Note: In a real implementation we'd track and free all pages
      alloc_mutex.release();
      return 0;
    }
    crt::set_memory(page, 0, 0x1000);
  }

  // Assign region ID and fill in descriptor
  const std::uint64_t region_id = next_region_id++;

  region->id = region_id;
  region->state = region_state_t::allocated;
  region->page_count = static_cast<std::uint8_t>(page_count);
  region->host_virtual_base = reinterpret_cast<std::uint64_t>(first_page);
  region->host_physical_base = first_physical;
  region->guest_virtual_target = 0;
  region->target_cr3 = 0;

  // Hide all pages from guest SLAT
  // This makes them show as zeros when the guest reads them
  for (std::uint32_t i = 0; i < page_count; ++i) {
    const std::uint64_t page_gpa = first_physical + (i * 0x1000);
    slat::hide_physical_page_from_guest({.address = page_gpa});
  }

  alloc_mutex.release();

  return region_id;
}

std::uint64_t hidden_alloc::write_region(std::uint64_t region_id,
                                         std::uint64_t offset, const void *data,
                                         std::uint64_t size) {
  if (region_id == 0 || data == nullptr || size == 0) {
    return 0;
  }

  alloc_mutex.lock();

  // Find the region
  hidden_region_t *region = nullptr;
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].id == region_id &&
        regions[i].state != region_state_t::free) {
      region = &regions[i];
      break;
    }
  }

  if (region == nullptr) {
    alloc_mutex.release();
    return 0;
  }

  // Calculate max size based on region size
  const std::uint64_t region_size =
      static_cast<std::uint64_t>(region->page_count) * 0x1000;

  if (offset >= region_size) {
    alloc_mutex.release();
    return 0;
  }

  // Clamp size to fit within region
  const std::uint64_t max_write = region_size - offset;
  const std::uint64_t actual_size = (size > max_write) ? max_write : size;

  // Write directly to the host virtual address
  void *dest = reinterpret_cast<void *>(region->host_virtual_base + offset);
  crt::copy_memory(dest, data, actual_size);

  alloc_mutex.release();

  return actual_size;
}

std::uint64_t hidden_alloc::read_region(std::uint64_t region_id,
                                        std::uint64_t offset, void *buffer,
                                        std::uint64_t size) {
  if (region_id == 0 || buffer == nullptr || size == 0) {
    return 0;
  }

  alloc_mutex.lock();

  // Find the region
  const hidden_region_t *region = nullptr;
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].id == region_id &&
        regions[i].state != region_state_t::free) {
      region = &regions[i];
      break;
    }
  }

  if (region == nullptr) {
    alloc_mutex.release();
    return 0;
  }

  // Calculate max size based on region size
  const std::uint64_t region_size =
      static_cast<std::uint64_t>(region->page_count) * 0x1000;

  if (offset >= region_size) {
    alloc_mutex.release();
    return 0;
  }

  // Clamp size to fit within region
  const std::uint64_t max_read = region_size - offset;
  const std::uint64_t actual_size = (size > max_read) ? max_read : size;

  // Read directly from the host virtual address
  const void *src =
      reinterpret_cast<const void *>(region->host_virtual_base + offset);
  crt::copy_memory(buffer, src, actual_size);

  alloc_mutex.release();

  return actual_size;
}

std::uint64_t hidden_alloc::expose_region(std::uint64_t region_id,
                                          std::uint64_t target_va,
                                          std::uint64_t target_cr3,
                                          std::uint8_t executable) {
  if (region_id == 0 || target_cr3 == 0) {
    return 0;
  }

  alloc_mutex.lock();

  // Find the region
  hidden_region_t *region = nullptr;
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].id == region_id &&
        regions[i].state != region_state_t::free) {
      region = &regions[i];
      break;
    }
  }

  if (region == nullptr) {
    alloc_mutex.release();
    return 0;
  }

  // Store exposure info
  region->guest_virtual_target = target_va;
  region->target_cr3 = target_cr3;
  region->state =
      executable ? region_state_t::executable : region_state_t::exposed;

  // For now, we just store the exposure info
  // The actual exposure happens dynamically via SLAT CR3 switching
  // when we detect the target process running (via CR3 matching)

  // In a full implementation, we would:
  // 1. Create a shadow page table for the target process
  // 2. On SLAT violation, check if current CR3 == target_cr3
  // 3. If yes, show the real pages; if no, show dummy pages

  alloc_mutex.release();

  return 1;
}

std::uint64_t hidden_alloc::hide_region(std::uint64_t region_id) {
  if (region_id == 0) {
    return 0;
  }

  alloc_mutex.lock();

  // Find the region
  hidden_region_t *region = nullptr;
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].id == region_id &&
        regions[i].state != region_state_t::free) {
      region = &regions[i];
      break;
    }
  }

  if (region == nullptr) {
    alloc_mutex.release();
    return 0;
  }

  // Re-hide the region
  region->guest_virtual_target = 0;
  region->target_cr3 = 0;
  region->state = region_state_t::allocated;

  // Re-hide all pages from guest
  for (std::uint8_t i = 0; i < region->page_count; ++i) {
    const std::uint64_t page_gpa = region->host_physical_base + (i * 0x1000);
    slat::hide_physical_page_from_guest({.address = page_gpa});
  }

  slat::flush_all_logical_processors_cache();

  alloc_mutex.release();

  return 1;
}

std::uint64_t hidden_alloc::free_region(std::uint64_t region_id) {
  if (region_id == 0) {
    return 0;
  }

  alloc_mutex.lock();

  // Find the region
  hidden_region_t *region = nullptr;
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].id == region_id &&
        regions[i].state != region_state_t::free) {
      region = &regions[i];
      break;
    }
  }

  if (region == nullptr) {
    alloc_mutex.release();
    return 0;
  }

  // Free all pages back to heap
  for (std::uint8_t i = 0; i < region->page_count; ++i) {
    void *page =
        reinterpret_cast<void *>(region->host_virtual_base + (i * 0x1000));
    heap_manager::free_page(page);
  }

  // Clear the region descriptor
  crt::set_memory(region, 0, sizeof(hidden_region_t));

  alloc_mutex.release();

  return 1;
}

const hidden_alloc::hidden_region_t *
hidden_alloc::get_region(std::uint64_t region_id) {
  if (region_id == 0) {
    return nullptr;
  }

  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].id == region_id &&
        regions[i].state != region_state_t::free) {
      return &regions[i];
    }
  }

  return nullptr;
}

std::uint32_t hidden_alloc::get_active_region_count() {
  std::uint32_t count = 0;

  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].state != region_state_t::free) {
      ++count;
    }
  }

  return count;
}

std::uint64_t hidden_alloc::get_exposed_target_cr3() {
  // Find any exposed region and return its target CR3
  // In a multi-process scenario, this would need to be more sophisticated
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].state == region_state_t::exposed ||
        regions[i].state == region_state_t::executable) {
      return regions[i].target_cr3;
    }
  }
  return 0;
}

std::uint64_t
hidden_alloc::find_region_by_gpa(std::uint64_t guest_physical_address) {
  for (std::uint32_t i = 0; i < MAX_HIDDEN_REGIONS; ++i) {
    if (regions[i].state == region_state_t::free) {
      continue;
    }

    const std::uint64_t region_start = regions[i].host_physical_base;
    const std::uint64_t region_end =
        region_start +
        (static_cast<std::uint64_t>(regions[i].page_count) * 0x1000);

    if (guest_physical_address >= region_start &&
        guest_physical_address < region_end) {
      return regions[i].id;
    }
  }
  return 0;
}
