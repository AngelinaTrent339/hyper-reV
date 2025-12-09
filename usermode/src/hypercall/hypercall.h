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

// Hidden Allocation hypercalls - allocate memory invisible to guest
struct hidden_region_info_t {
  std::uint64_t id;
  std::uint8_t state; // 0=free, 1=allocated, 2=exposed, 3=executable
  std::uint8_t page_count;
  std::uint16_t reserved;
  std::uint32_t padding;
  std::uint64_t host_virtual_base;
  std::uint64_t host_physical_base;
  std::uint64_t guest_virtual_target;
  std::uint64_t target_cr3;
};

std::uint64_t hidden_alloc_region(std::uint32_t page_count);
std::uint64_t hidden_write_region(std::uint64_t region_id, std::uint64_t offset,
                                  const void *data, std::uint64_t size);
std::uint64_t hidden_read_region(std::uint64_t region_id, std::uint64_t offset,
                                 void *buffer, std::uint64_t size);
std::uint64_t hidden_expose_region(std::uint64_t region_id,
                                   std::uint64_t target_va,
                                   std::uint64_t target_cr3, bool executable);
std::uint64_t hidden_hide_region(std::uint64_t region_id);
std::uint64_t hidden_free_region(std::uint64_t region_id);
std::uint64_t hidden_get_region_info(std::uint64_t region_id,
                                     hidden_region_info_t *info);
std::uint64_t hidden_get_region_count();

} // namespace hypercall
