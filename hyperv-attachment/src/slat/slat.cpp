#include "slat.h"
#include "../crt/crt.h"
#include "../memory_manager/heap_manager.h"
#include "../memory_manager/memory_manager.h"
#include <ia32-doc/ia32.hpp>

#include "cr3/cr3.h"
#include "cr3/pte.h"
#include "hook/hook.h"
#include "slat_def.h"

namespace {
std::uint64_t dummy_page_pfn = 0;
}

void set_up_dummy_page() {
  void *const dummy_page_allocation = heap_manager::allocate_page();

  const std::uint64_t dummy_page_physical_address =
      memory_manager::unmap_host_physical(dummy_page_allocation);

  dummy_page_pfn = dummy_page_physical_address >> 12;

  crt::set_memory(dummy_page_allocation, 0, 0x1000);
}

void slat::set_up() {
  hook::set_up_entries();
  set_up_dummy_page();
}

void slat::process_first_vmexit() { set_up_hyperv_cr3(); }

std::uint64_t slat::translate_guest_physical_address(
    const cr3 slat_cr3, const virtual_address_t guest_physical_address,
    std::uint64_t *const size_left_of_page) {
  return memory_manager::translate_host_virtual_address(
      slat_cr3, guest_physical_address, size_left_of_page);
}

std::uint8_t slat::hide_heap_pages(const cr3 slat_cr3) {
  const std::uint64_t heap_physical_address =
      heap_manager::initial_physical_base;
  const std::uint64_t heap_physical_end =
      heap_physical_address + heap_manager::initial_size;

  std::uint64_t current_physical_address = heap_physical_address;

  while (current_physical_address < heap_physical_end) {
    hide_physical_page_from_guest(slat_cr3,
                                  {.address = current_physical_address});

    current_physical_address += 0x1000;
  }

  return 1;
}

std::uint64_t slat::hide_physical_page_from_guest(
    const cr3 slat_cr3, const virtual_address_t guest_physical_address) {
  slat_pte *const target_pte = get_pte(slat_cr3, guest_physical_address, 1);

  if (target_pte == nullptr) {
    return 0;
  }

  target_pte->page_frame_number = dummy_page_pfn;

  return 1;
}

std::uint64_t slat::hide_physical_page_from_guest(
    const virtual_address_t guest_physical_address) {
  return hide_physical_page_from_guest(hyperv_cr3(), guest_physical_address) &&
         hide_physical_page_from_guest(hook_cr3(), guest_physical_address);
}

// ============================================================================
// BREAKPOINT SUPPORT: Modify NPT page permissions
// For AMD NPT: We use present bit and read_write bit in pte_64
// For Intel EPT: We'd use read_access, write_access, execute_access bits
// ============================================================================

bool slat::modify_page_permissions(std::uint64_t guest_physical_address,
                                   std::uint64_t permissions_mask, bool set) {
  const virtual_address_t gpa = {.address = guest_physical_address};

  // Get the PTE for this page
  slat_pte *const target_pte = get_pte(hyperv_cr3(), gpa, 1);

  if (target_pte == nullptr)
    return false;

  // Also modify hook CR3 to keep them in sync
  slat_pte *const hook_pte = get_pte(hook_cr3(), gpa, 1);

#ifdef _INTELMACHINE
  // Intel EPT: Uses explicit read/write/execute access bits
  if (set) {
    // Add permissions
    if (permissions_mask & 1)
      target_pte->read_access = 1;
    if (permissions_mask & 2)
      target_pte->write_access = 1;
    if (permissions_mask & 4)
      target_pte->execute_access = 1;

    if (hook_pte) {
      if (permissions_mask & 1)
        hook_pte->read_access = 1;
      if (permissions_mask & 2)
        hook_pte->write_access = 1;
      if (permissions_mask & 4)
        hook_pte->execute_access = 1;
    }
  } else {
    // Remove permissions
    if (permissions_mask & 1)
      target_pte->read_access = 0;
    if (permissions_mask & 2)
      target_pte->write_access = 0;
    if (permissions_mask & 4)
      target_pte->execute_access = 0;

    if (hook_pte) {
      if (permissions_mask & 1)
        hook_pte->read_access = 0;
      if (permissions_mask & 2)
        hook_pte->write_access = 0;
      if (permissions_mask & 4)
        hook_pte->execute_access = 0;
    }
  }
#else
  // AMD NPT: Uses regular paging bits
  // present = read (bit 0)
  // write = write (bit 1)
  // execute_disable = ~execute (bit 63 in full pte)
  if (set) {
    // Add permissions (set bits)
    if (permissions_mask & 1)
      target_pte->present = 1; // R
    if (permissions_mask & 2)
      target_pte->write = 1; // W
    if (permissions_mask & 4)
      target_pte->execute_disable = 0; // X (disable NX)

    if (hook_pte) {
      if (permissions_mask & 1)
        hook_pte->present = 1;
      if (permissions_mask & 2)
        hook_pte->write = 1;
      if (permissions_mask & 4)
        hook_pte->execute_disable = 0;
    }
  } else {
    // Remove permissions (clear bits)
    // Note: For read BP, we can't just clear present bit as that would make
    // page invalid Instead, we mark it not-present which causes #PF that we
    // intercept
    if (permissions_mask & 1)
      target_pte->present = 0; // No read
    if (permissions_mask & 2)
      target_pte->write = 0; // No write
    if (permissions_mask & 4)
      target_pte->execute_disable = 1; // No execute (set NX)

    if (hook_pte) {
      if (permissions_mask & 1)
        hook_pte->present = 0;
      if (permissions_mask & 2)
        hook_pte->write = 0;
      if (permissions_mask & 4)
        hook_pte->execute_disable = 1;
    }
  }
#endif

  // Flush TLB for this page
  // AMD: Use INVLPGA or set up TLB flush
  // The VMCB clean bits should handle TLB invalidation on VM exit

  return true;
}
