#pragma once
#include <cstdint>
#include <structures/trap_frame.h>
#include <vector>

namespace hypercall {
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

// Process CR3 auto-tracking hypercalls
std::uint64_t set_tracked_pid(std::uint64_t pid);
std::uint64_t get_tracked_cr3();
std::uint64_t clear_tracked_pid();

// Tracking status structure
struct tracking_status_t {
  std::uint64_t tracked_pid;
  std::uint64_t tracked_cr3;
  std::uint64_t match_count;
  std::uint64_t gs_base;
};

std::uint64_t get_tracking_status(tracking_status_t *status);

// MSR Shadow hypercalls (AMD only)
struct msr_shadow_entry_t {
  std::uint32_t msr_index;
  std::uint32_t padding;
  std::uint64_t shadow_value;
};

std::uint64_t add_msr_shadow(std::uint32_t msr_index,
                             std::uint64_t shadow_value);
std::uint64_t remove_msr_shadow(std::uint32_t msr_index);
std::uint64_t get_msr_shadow_list(msr_shadow_entry_t *buffer,
                                  std::uint32_t max_entries);
std::uint64_t clear_all_msr_shadows();

// MSR Debug hypercalls
std::uint64_t read_msr_value(std::uint32_t msr_index);
std::uint64_t get_msr_intercept_count();

// MSRPM Control hypercalls (AMD only) - enables actual interception
std::uint64_t set_msr_intercept(std::uint32_t msr_index, std::uint8_t flags);
std::uint64_t get_msr_intercept_status(std::uint32_t msr_index);
} // namespace hypercall
