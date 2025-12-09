#include "hypercall.h"
#include <hypercall/hypercall_def.h>

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx,
                                              std::uint64_t rdx,
                                              std::uint64_t r8,
                                              std::uint64_t r9);

std::uint64_t make_hypercall(hypercall_type_t call_type,
                             std::uint64_t call_reserved_data,
                             std::uint64_t rdx, std::uint64_t r8,
                             std::uint64_t r9) {
  hypercall_info_t hypercall_info = {};

  hypercall_info.primary_key = hypercall_primary_key;
  hypercall_info.secondary_key = hypercall_secondary_key;
  hypercall_info.call_type = call_type;
  hypercall_info.call_reserved_data = call_reserved_data;

  return launch_raw_hypercall(hypercall_info, rdx, r8, r9);
}

std::uint64_t hypercall::read_guest_physical_memory(
    void *guest_destination_buffer, std::uint64_t guest_source_physical_address,
    std::uint64_t size) {
  hypercall_type_t call_type =
      hypercall_type_t::guest_physical_memory_operation;

  std::uint64_t call_data =
      static_cast<std::uint64_t>(memory_operation_t::read_operation);

  std::uint64_t guest_destination_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_destination_buffer);

  return make_hypercall(call_type, call_data, guest_source_physical_address,
                        guest_destination_virtual_address, size);
}

std::uint64_t hypercall::write_guest_physical_memory(
    void *guest_source_buffer, std::uint64_t guest_destination_physical_address,
    std::uint64_t size) {
  hypercall_type_t call_type =
      hypercall_type_t::guest_physical_memory_operation;

  std::uint64_t call_data =
      static_cast<std::uint64_t>(memory_operation_t::write_operation);

  std::uint64_t guest_source_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_source_buffer);

  return make_hypercall(call_type, call_data,
                        guest_destination_physical_address,
                        guest_source_virtual_address, size);
}

std::uint64_t hypercall::read_guest_virtual_memory(
    void *guest_destination_buffer, std::uint64_t guest_source_virtual_address,
    std::uint64_t source_cr3, std::uint64_t size) {
  virt_memory_op_hypercall_info_t memory_op_call = {};

  memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
  memory_op_call.memory_operation = memory_operation_t::read_operation;
  memory_op_call.address_of_page_directory = source_cr3 >> 12;

  hypercall_info_t hypercall_info = {.value = memory_op_call.value};

  std::uint64_t guest_destination_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_destination_buffer);

  return make_hypercall(
      hypercall_info.call_type, hypercall_info.call_reserved_data,
      guest_destination_virtual_address, guest_source_virtual_address, size);
}

std::uint64_t hypercall::write_guest_virtual_memory(
    void *guest_source_buffer, std::uint64_t guest_destination_virtual_address,
    std::uint64_t destination_cr3, std::uint64_t size) {
  virt_memory_op_hypercall_info_t memory_op_call = {};

  memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
  memory_op_call.memory_operation = memory_operation_t::write_operation;
  memory_op_call.address_of_page_directory = destination_cr3 >> 12;

  hypercall_info_t hypercall_info = {.value = memory_op_call.value};

  std::uint64_t guest_source_virtual_address =
      reinterpret_cast<std::uint64_t>(guest_source_buffer);

  return make_hypercall(
      hypercall_info.call_type, hypercall_info.call_reserved_data,
      guest_source_virtual_address, guest_destination_virtual_address, size);
}

std::uint64_t
hypercall::translate_guest_virtual_address(std::uint64_t guest_virtual_address,
                                           std::uint64_t guest_cr3) {
  hypercall_type_t call_type =
      hypercall_type_t::translate_guest_virtual_address;

  return make_hypercall(call_type, 0, guest_virtual_address, guest_cr3, 0);
}

std::uint64_t hypercall::read_guest_cr3() {
  hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::add_slat_code_hook(
    std::uint64_t target_guest_physical_address,
    std::uint64_t shadow_page_guest_physical_address) {
  hypercall_type_t call_type = hypercall_type_t::add_slat_code_hook;

  return make_hypercall(call_type, 0, target_guest_physical_address,
                        shadow_page_guest_physical_address, 0);
}

std::uint64_t
hypercall::remove_slat_code_hook(std::uint64_t target_guest_physical_address) {
  hypercall_type_t call_type = hypercall_type_t::remove_slat_code_hook;

  return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::hide_guest_physical_page(
    std::uint64_t target_guest_physical_address) {
  hypercall_type_t call_type = hypercall_type_t::hide_guest_physical_page;

  return make_hypercall(call_type, 0, target_guest_physical_address, 0, 0);
}

std::uint64_t hypercall::flush_logs(std::vector<trap_frame_log_t> &logs) {
  hypercall_type_t call_type = hypercall_type_t::flush_logs;

  return make_hypercall(call_type, 0,
                        reinterpret_cast<std::uint64_t>(logs.data()),
                        logs.size(), 0);
}

std::uint64_t hypercall::get_heap_free_page_count() {
  hypercall_type_t call_type = hypercall_type_t::get_heap_free_page_count;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

// =============================================================================
// Process CR3 Auto-Tracking Hypercalls
// =============================================================================

std::uint64_t hypercall::set_tracked_pid(std::uint64_t pid) {
  hypercall_type_t call_type = hypercall_type_t::set_tracked_pid;

  return make_hypercall(call_type, 0, pid, 0, 0);
}

std::uint64_t hypercall::get_tracked_cr3() {
  hypercall_type_t call_type = hypercall_type_t::get_tracked_cr3;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::clear_tracked_pid() {
  hypercall_type_t call_type = hypercall_type_t::clear_tracked_pid;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::get_tracking_status(tracking_status_t *status) {
  hypercall_type_t call_type = hypercall_type_t::get_tracking_status;

  // Pass the status buffer address in r8, the hypervisor will write to it
  return make_hypercall(call_type, 0, 0,
                        reinterpret_cast<std::uint64_t>(status), 0);
}

// =============================================================================
// MSR Shadow Hypercalls
// =============================================================================

std::uint64_t hypercall::add_msr_shadow(std::uint32_t msr_index,
                                        std::uint64_t shadow_value) {
  hypercall_type_t call_type = hypercall_type_t::add_msr_shadow;

  // rdx = msr_index, r8 = shadow_value
  return make_hypercall(call_type, 0, msr_index, shadow_value, 0);
}

std::uint64_t hypercall::remove_msr_shadow(std::uint32_t msr_index) {
  hypercall_type_t call_type = hypercall_type_t::remove_msr_shadow;

  return make_hypercall(call_type, 0, msr_index, 0, 0);
}

std::uint64_t hypercall::get_msr_shadow_list(msr_shadow_entry_t *buffer,
                                             std::uint32_t max_entries) {
  hypercall_type_t call_type = hypercall_type_t::get_msr_shadow_list;

  // r8 = buffer address
  (void)max_entries; // max_entries is for caller's buffer size, not passed to
                     // hypervisor
  return make_hypercall(call_type, 0, 0,
                        reinterpret_cast<std::uint64_t>(buffer), 0);
}

std::uint64_t hypercall::clear_all_msr_shadows() {
  hypercall_type_t call_type = hypercall_type_t::clear_all_msr_shadows;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::read_msr_value(std::uint32_t msr_index) {
  hypercall_type_t call_type = hypercall_type_t::read_msr_value;

  return make_hypercall(call_type, 0, msr_index, 0, 0);
}

std::uint64_t hypercall::get_msr_intercept_count() {
  hypercall_type_t call_type = hypercall_type_t::get_msr_intercept_count;

  return make_hypercall(call_type, 0, 0, 0, 0);
}

std::uint64_t hypercall::set_msr_intercept(std::uint32_t msr_index,
                                           std::uint8_t flags) {
  hypercall_type_t call_type = hypercall_type_t::set_msr_intercept;

  // rdx = msr_index, r8 = flags (bit0=read, bit1=write)
  return make_hypercall(call_type, 0, msr_index, flags, 0);
}

std::uint64_t hypercall::get_msr_intercept_status(std::uint32_t msr_index) {
  hypercall_type_t call_type = hypercall_type_t::get_msr_intercept_status;

  // rdx = msr_index
  return make_hypercall(call_type, 0, msr_index, 0, 0);
}

// =============================================================================
// Hidden Allocation Hypercalls
// =============================================================================

std::uint64_t hypercall::hidden_alloc_region(std::uint32_t page_count) {
  hypercall_type_t call_type = hypercall_type_t::hidden_alloc_region;

  // rdx = page_count
  return make_hypercall(call_type, 0, page_count, 0, 0);
}

std::uint64_t hypercall::hidden_write_region(std::uint64_t region_id,
                                             std::uint64_t offset,
                                             const void *data,
                                             std::uint64_t size) {
  hypercall_type_t call_type = hypercall_type_t::hidden_write_region;

  // rdx = region_id, r8 = offset, r9 = data_ptr, r10 = size
  // Note: We use the extended hypercall mechanism for r10
  // For now, we pass size in r9 and use a modified hypercall
  // Implementation uses chunked writes internally

  // We need to use a different approach since launch_raw_hypercall only has 3
  // params For simplicity, split into multiple calls if needed
  std::uint64_t bytes_written = 0;
  std::uint64_t remaining = size;
  const std::uint8_t *src = static_cast<const std::uint8_t *>(data);

  while (remaining > 0) {
    // Write in chunks that fit in our hypercall parameters
    const std::uint64_t chunk_size = (remaining > 0x1000) ? 0x1000 : remaining;

    // For the write, we need to pass: region_id, offset, data_ptr, size
    // We'll encode offset and size together in call_reserved_data, data_ptr in
    // rdx, region_id in r8 Actually, the hypervisor uses r10 which we can't
    // pass easily Let's use a simpler encoding: rdx=region_id, r8=offset,
    // r9=data_ptr And encode size in call_reserved_data

    const std::uint64_t result =
        make_hypercall(call_type, chunk_size, region_id, offset + bytes_written,
                       reinterpret_cast<std::uint64_t>(src + bytes_written));

    if (result == 0)
      break;

    bytes_written += result;
    remaining -= result;
  }

  return bytes_written;
}

std::uint64_t hypercall::hidden_read_region(std::uint64_t region_id,
                                            std::uint64_t offset, void *buffer,
                                            std::uint64_t size) {
  hypercall_type_t call_type = hypercall_type_t::hidden_read_region;

  std::uint64_t bytes_read = 0;
  std::uint64_t remaining = size;
  std::uint8_t *dest = static_cast<std::uint8_t *>(buffer);

  while (remaining > 0) {
    const std::uint64_t chunk_size = (remaining > 0x1000) ? 0x1000 : remaining;

    const std::uint64_t result =
        make_hypercall(call_type, chunk_size, region_id, offset + bytes_read,
                       reinterpret_cast<std::uint64_t>(dest + bytes_read));

    if (result == 0)
      break;

    bytes_read += result;
    remaining -= result;
  }

  return bytes_read;
}

std::uint64_t hypercall::hidden_expose_region(std::uint64_t region_id,
                                              std::uint64_t target_va,
                                              std::uint64_t target_cr3,
                                              bool executable) {
  hypercall_type_t call_type = hypercall_type_t::hidden_expose_region;

  // rdx = region_id, r8 = target_va, r9 = target_cr3
  // executable flag encoded in call_reserved_data
  return make_hypercall(call_type, executable ? 1 : 0, region_id, target_va,
                        target_cr3);
}

std::uint64_t hypercall::hidden_hide_region(std::uint64_t region_id) {
  hypercall_type_t call_type = hypercall_type_t::hidden_hide_region;

  return make_hypercall(call_type, 0, region_id, 0, 0);
}

std::uint64_t hypercall::hidden_free_region(std::uint64_t region_id) {
  hypercall_type_t call_type = hypercall_type_t::hidden_free_region;

  return make_hypercall(call_type, 0, region_id, 0, 0);
}

std::uint64_t hypercall::hidden_get_region_info(std::uint64_t region_id,
                                                hidden_region_info_t *info) {
  hypercall_type_t call_type = hypercall_type_t::hidden_get_region_info;

  // rdx = region_id, r8 = output_buffer
  return make_hypercall(call_type, 0, region_id,
                        reinterpret_cast<std::uint64_t>(info), 0);
}

std::uint64_t hypercall::hidden_get_region_count() {
  hypercall_type_t call_type = hypercall_type_t::hidden_get_region_count;

  return make_hypercall(call_type, 0, 0, 0, 0);
}
