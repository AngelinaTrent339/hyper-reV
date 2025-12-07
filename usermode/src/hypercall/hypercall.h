#pragma once
#include <cstdint>
#include <structures/process_info.h>
#include <structures/trap_frame.h>
#include <vector>


namespace hypercall {
// === EXISTING HYPERCALLS ===
std::uint64_t
read_guest_physical_memory(void *guest_destination_buffer,
                           std::uint64_t guest_source_physical_address,
                           std::uint64_t size);
std::uint64_t
write_guest_physical_memory(void *guest_source_buffer,
                            std::uint64_t guest_destination_physical_address,
                            std::uint64_t size);

std::uint64_t
read_guest_virtual_memory(void *guest_destination_buffer,
                          std::uint64_t guest_source_virtual_address,
                          std::uint64_t source_cr3, std::uint64_t size);
std::uint64_t
write_guest_virtual_memory(void *guest_source_buffer,
                           std::uint64_t guest_destination_virtual_address,
                           std::uint64_t destination_cr3, std::uint64_t size);

std::uint64_t
translate_guest_virtual_address(std::uint64_t guest_virtual_address,
                                std::uint64_t guest_cr3);

std::uint64_t read_guest_cr3();

std::uint64_t
add_slat_code_hook(std::uint64_t target_guest_physical_address,
                   std::uint64_t shadow_page_guest_physical_address);
std::uint64_t
remove_slat_code_hook(std::uint64_t target_guest_physical_address);
std::uint64_t
hide_guest_physical_page(std::uint64_t target_guest_physical_address);

std::uint64_t flush_logs(std::vector<trap_frame_log_t> &logs);

std::uint64_t get_heap_free_page_count();

// === PHASE 2: PROCESS TARGETING ===

// Attach to specific process by CR3 (0 = all processes)
std::uint64_t attach_to_process(std::uint64_t target_cr3);

// Detach from current target, operate on all processes
std::uint64_t detach_from_process();

// Find process CR3 by name (returns 0 if not found)
std::uint64_t get_process_by_name(const char *name);

// Enumerate all processes
std::uint64_t get_process_list(std::vector<process_info_t> &processes);

// Set Windows kernel offsets (required before process enumeration)
std::uint64_t set_windows_offsets(const windows_offsets_t &offsets);

// Enumerate modules for a process
std::uint64_t enumerate_modules(std::uint64_t target_cr3, std::uint64_t peb,
                                std::vector<module_info_t> &modules);
} // namespace hypercall
