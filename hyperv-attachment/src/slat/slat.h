#pragma once
#include <cstdint>
#include <ia32-doc/ia32.hpp>


union virtual_address_t;

namespace slat {
void set_up();
void process_first_vmexit();

std::uint64_t
translate_guest_physical_address(cr3 slat_cr3,
                                 virtual_address_t guest_physical_address,
                                 std::uint64_t *size_left_of_page = nullptr);

std::uint8_t hide_heap_pages(cr3 slat_cr3);

std::uint64_t
hide_physical_page_from_guest(cr3 slat_cr3,
                              virtual_address_t guest_physical_address);
std::uint64_t
hide_physical_page_from_guest(virtual_address_t guest_physical_address);

// Get the Hyper-V SLAT CR3
cr3 hyperv_cr3();

// ========================================================================
// BREAKPOINT SUPPORT: Modify NPT page permissions
// permissions_mask: bit 0 = Read, bit 1 = Write, bit 2 = Execute
// set = true: add permissions, false: remove permissions
// Returns true on success
// ========================================================================
bool modify_page_permissions(std::uint64_t guest_physical_address,
                             std::uint64_t permissions_mask, bool set);
} // namespace slat
