#include "hypercall.h"
#include "../memory_manager/heap_manager.h"
#include "../memory_manager/memory_manager.h"

#include "../slat/cr3/cr3.h"
#include "../slat/hook/hook.h"
#include "../slat/slat.h"

#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../logs/logs.h"
#include "../syscall/syscall_intercept.h"

#include <hypercall/hypercall_def.h>
#include <ia32-doc/ia32.hpp>
#include <intrin.h>

std::uint64_t
operate_on_guest_physical_memory(const trap_frame_t *const trap_frame,
                                 const memory_operation_t operation) {
  const cr3 guest_cr3 = arch::get_guest_cr3();
  const cr3 slat_cr3 = slat::hyperv_cr3();

  const std::uint64_t guest_buffer_virtual_address = trap_frame->r8;
  const std::uint64_t guest_physical_address = trap_frame->rdx;

  std::uint64_t size_left_to_copy = trap_frame->r9;

  std::uint64_t bytes_copied = 0;

  while (size_left_to_copy != 0) {
    std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;
    std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

    const std::uint64_t guest_buffer_physical_address =
        memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3,
            {.address = guest_buffer_virtual_address + bytes_copied});

    // Check if translation failed
    if (guest_buffer_physical_address == 0) {
      break;
    }

    void *host_destination = memory_manager::map_guest_physical(
        slat_cr3, guest_buffer_physical_address,
        &size_left_of_destination_slat_page);
    void *host_source = memory_manager::map_guest_physical(
        slat_cr3, guest_physical_address + bytes_copied,
        &size_left_of_source_slat_page);

    // Check if mapping failed
    if (host_destination == nullptr || host_source == nullptr) {
      break;
    }

    if (size_left_of_destination_slat_page == UINT64_MAX ||
        size_left_of_source_slat_page == UINT64_MAX) {
      break;
    }

    if (operation == memory_operation_t::write_operation) {
      crt::swap(host_source, host_destination);
    }

    const std::uint64_t size_left_of_slat_pages = crt::min(
        size_left_of_source_slat_page, size_left_of_destination_slat_page);

    const std::uint64_t copy_size =
        crt::min(size_left_to_copy, size_left_of_slat_pages);

    if (copy_size == 0) {
      break;
    }

    crt::copy_memory(host_destination, host_source, copy_size);

    size_left_to_copy -= copy_size;
    bytes_copied += copy_size;
  }

  return bytes_copied;
}

std::uint64_t
operate_on_guest_virtual_memory(const trap_frame_t *const trap_frame,
                                const memory_operation_t operation,
                                const std::uint64_t address_of_page_directory) {
  const cr3 guest_source_cr3 = {.address_of_page_directory =
                                    address_of_page_directory};

  const cr3 guest_destination_cr3 = arch::get_guest_cr3();
  const cr3 slat_cr3 = slat::hyperv_cr3();

  const std::uint64_t guest_destination_virtual_address = trap_frame->rdx;
  const std::uint64_t guest_source_virtual_address = trap_frame->r8;

  std::uint64_t size_left_to_read = trap_frame->r9;

  std::uint64_t bytes_copied = 0;

  while (size_left_to_read != 0) {
    std::uint64_t size_left_of_destination_virtual_page = UINT64_MAX;
    std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;

    std::uint64_t size_left_of_source_virtual_page = UINT64_MAX;
    std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

    const std::uint64_t guest_source_physical_address =
        memory_manager::translate_guest_virtual_address(
            guest_source_cr3, slat_cr3,
            {.address = guest_source_virtual_address + bytes_copied},
            &size_left_of_source_virtual_page);
    const std::uint64_t guest_destination_physical_address =
        memory_manager::translate_guest_virtual_address(
            guest_destination_cr3, slat_cr3,
            {.address = guest_destination_virtual_address + bytes_copied},
            &size_left_of_destination_virtual_page);

    // Check if translation failed (returned 0 or size not set)
    if (guest_source_physical_address == 0 ||
        guest_destination_physical_address == 0) {
      break;
    }

    if (size_left_of_destination_virtual_page == UINT64_MAX ||
        size_left_of_source_virtual_page == UINT64_MAX) {
      break;
    }

    void *host_destination = memory_manager::map_guest_physical(
        slat_cr3, guest_destination_physical_address,
        &size_left_of_destination_slat_page);
    void *host_source = memory_manager::map_guest_physical(
        slat_cr3, guest_source_physical_address,
        &size_left_of_source_slat_page);

    // Check if mapping failed
    if (host_destination == nullptr || host_source == nullptr) {
      break;
    }

    if (size_left_of_destination_slat_page == UINT64_MAX ||
        size_left_of_source_slat_page == UINT64_MAX) {
      break;
    }

    if (operation == memory_operation_t::write_operation) {
      crt::swap(host_source, host_destination);
    }

    const std::uint64_t size_left_of_slat_pages = crt::min(
        size_left_of_source_slat_page, size_left_of_destination_slat_page);
    const std::uint64_t size_left_of_virtual_pages =
        crt::min(size_left_of_source_virtual_page,
                 size_left_of_destination_virtual_page);

    const std::uint64_t size_left_of_pages =
        crt::min(size_left_of_slat_pages, size_left_of_virtual_pages);

    const std::uint64_t copy_size =
        crt::min(size_left_to_read, size_left_of_pages);

    if (copy_size == 0) {
      break;
    }

    crt::copy_memory(host_destination, host_source, copy_size);

    size_left_to_read -= copy_size;
    bytes_copied += copy_size;
  }

  return bytes_copied;
}

std::uint8_t copy_stack_data_from_log_exit(std::uint64_t *const stack_data,
                                           const std::uint64_t stack_data_count,
                                           const cr3 guest_cr3,
                                           const std::uint64_t rsp) {
  if (rsp == 0) {
    return 0;
  }

  const cr3 slat_cr3 = slat::hyperv_cr3();

  std::uint64_t bytes_read = 0;
  std::uint64_t bytes_remaining = stack_data_count * sizeof(std::uint64_t);

  while (bytes_remaining != 0) {
    std::uint64_t virtual_size_left = 0;

    const std::uint64_t rsp_guest_physical_address =
        memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3, {.address = rsp + bytes_read},
            &virtual_size_left);

    if (rsp_guest_physical_address == 0) {
      return 0;
    }

    std::uint64_t physical_size_left = 0;

    // rcx has just been pushed onto stack
    const auto rsp_mapped =
        static_cast<const std::uint64_t *>(memory_manager::map_guest_physical(
            slat_cr3, rsp_guest_physical_address, &physical_size_left));

    const std::uint64_t size_left_of_page =
        crt::min(physical_size_left, virtual_size_left);
    const std::uint64_t size_to_read =
        crt::min(bytes_remaining, size_left_of_page);

    if (size_to_read == 0) {
      return 0;
    }

    crt::copy_memory(reinterpret_cast<std::uint8_t *>(stack_data) + bytes_read,
                     reinterpret_cast<const std::uint8_t *>(rsp_mapped) +
                         bytes_read,
                     size_to_read);

    bytes_remaining -= size_to_read;
    bytes_read += size_to_read;
  }

  return 1;
}

void do_stack_data_copy(trap_frame_log_t &trap_frame, const cr3 guest_cr3) {
  constexpr std::uint64_t stack_data_count =
      trap_frame_log_stack_data_count + 1;

  std::uint64_t stack_data[stack_data_count] = {};

  copy_stack_data_from_log_exit(&stack_data[0], stack_data_count, guest_cr3,
                                trap_frame.rsp);

  crt::copy_memory(&trap_frame.stack_data, &stack_data[1],
                   sizeof(trap_frame.stack_data));

  trap_frame.rcx = stack_data[0];
  trap_frame.rsp += 8; // get rid of the rcx value we push onto stack ourselves
}

void log_current_state(trap_frame_log_t trap_frame) {
  cr3 guest_cr3 = arch::get_guest_cr3();

  do_stack_data_copy(trap_frame, guest_cr3);

  trap_frame.cr3 = guest_cr3.flags;
  trap_frame.rip = arch::get_guest_rip();

  logs::add_log(trap_frame);
}

std::uint64_t flush_logs(const trap_frame_t *const trap_frame) {
  std::uint64_t stored_logs_count = logs::stored_log_index;

  const cr3 guest_cr3 = arch::get_guest_cr3();
  const cr3 slat_cr3 = slat::hyperv_cr3();

  const std::uint64_t guest_virtual_address = trap_frame->rdx;
  const std::uint16_t count = static_cast<std::uint16_t>(trap_frame->r8);

  if (logs::flush(slat_cr3, guest_virtual_address, guest_cr3, count) == 0) {
    return -1;
  }

  return stored_logs_count;
}

void hypercall::process(const hypercall_info_t hypercall_info,
                        trap_frame_t *const trap_frame) {
  switch (hypercall_info.call_type) {
  case hypercall_type_t::guest_physical_memory_operation: {
    const auto memory_operation =
        static_cast<memory_operation_t>(hypercall_info.call_reserved_data);

    trap_frame->rax =
        operate_on_guest_physical_memory(trap_frame, memory_operation);

    break;
  }
  case hypercall_type_t::guest_virtual_memory_operation: {
    const virt_memory_op_hypercall_info_t virt_memory_op_info = {
        .value = hypercall_info.value};

    const memory_operation_t memory_operation =
        virt_memory_op_info.memory_operation;
    const std::uint64_t address_of_page_directory =
        virt_memory_op_info.address_of_page_directory;

    trap_frame->rax = operate_on_guest_virtual_memory(
        trap_frame, memory_operation, address_of_page_directory);

    break;
  }
  case hypercall_type_t::translate_guest_virtual_address: {
    const virtual_address_t guest_virtual_address = {.address =
                                                         trap_frame->rdx};

    const cr3 target_guest_cr3 = {.flags = trap_frame->r8};
    const cr3 slat_cr3 = slat::hyperv_cr3();

    trap_frame->rax = memory_manager::translate_guest_virtual_address(
        target_guest_cr3, slat_cr3, guest_virtual_address);

    break;
  }
  case hypercall_type_t::read_guest_cr3: {
    const cr3 guest_cr3 = arch::get_guest_cr3();

    trap_frame->rax = guest_cr3.flags;

    break;
  }
  case hypercall_type_t::add_slat_code_hook: {
    const virtual_address_t target_guest_physical_address = {
        .address = trap_frame->rdx};
    const virtual_address_t shadow_page_guest_physical_address = {
        .address = trap_frame->r8};

    trap_frame->rax = slat::hook::add(target_guest_physical_address,
                                      shadow_page_guest_physical_address);

    break;
  }
  case hypercall_type_t::remove_slat_code_hook: {
    const virtual_address_t target_guest_physical_address = {
        .address = trap_frame->rdx};

    trap_frame->rax = slat::hook::remove(target_guest_physical_address);

    break;
  }
  case hypercall_type_t::hide_guest_physical_page: {
    const virtual_address_t target_guest_physical_address = {
        .address = trap_frame->rdx};

    trap_frame->rax =
        slat::hide_physical_page_from_guest(target_guest_physical_address);

    break;
  }
  case hypercall_type_t::log_current_state: {
    trap_frame_log_t trap_frame_log;

    crt::copy_memory(&trap_frame_log, trap_frame, sizeof(trap_frame_t));

    log_current_state(trap_frame_log);

    break;
  }
  case hypercall_type_t::flush_logs: {
    trap_frame->rax = flush_logs(trap_frame);

    break;
  }
  case hypercall_type_t::get_heap_free_page_count: {
    trap_frame->rax = heap_manager::get_free_page_count();

    break;
  }

  // ============================================================================
  // HYPERVISOR-LEVEL SYSCALL INTERCEPTION (No SSDT needed!)
  // ============================================================================
  case hypercall_type_t::enable_syscall_intercept: {
    // RDX = mode (0 = disabled, 1 = log_all, 2 = log_filtered)
    syscall_intercept::filter_mode_t mode =
        static_cast<syscall_intercept::filter_mode_t>(trap_frame->rdx);
    syscall_intercept::set_mode(mode);
    trap_frame->rax = 1;
    break;
  }
  case hypercall_type_t::disable_syscall_intercept: {
    syscall_intercept::set_mode(syscall_intercept::filter_mode_t::disabled);
    trap_frame->rax = 1;
    break;
  }
  case hypercall_type_t::set_syscall_filter: {
    // RDX = syscall_min
    // R8 = syscall_max
    // R9 = cr3_filter (0 = all processes)
    syscall_intercept::set_filter(trap_frame->rdx, trap_frame->r8,
                                  trap_frame->r9);
    trap_frame->rax = 1;
    break;
  }
  case hypercall_type_t::flush_syscall_logs: {
    // RDX = guest buffer virtual address
    // R8 = max entries to copy
    // Returns: number of entries copied
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const virtual_address_t guest_buffer_va = {.address = trap_frame->rdx};
    const std::uint64_t max_entries = trap_frame->r8;

    // Translate guest VA to physical
    const std::uint64_t guest_buffer_pa =
        memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3,
                                                        guest_buffer_va);

    if (guest_buffer_pa != 0) {
      void *host_ptr = memory_manager::map_host_physical(guest_buffer_pa);
      trap_frame->rax = syscall_intercept::flush_logs(host_ptr, max_entries);
    } else {
      trap_frame->rax = 0;
    }
    break;
  }
  case hypercall_type_t::get_syscall_log_count: {
    trap_frame->rax = syscall_intercept::get_log_count();
    break;
  }
  case hypercall_type_t::read_msr: {
    // RDX = MSR index to read
    // Returns: MSR value in RAX
    std::uint32_t msr_index = static_cast<std::uint32_t>(trap_frame->rdx);
    trap_frame->rax = __readmsr(msr_index);
    break;
  }
  case hypercall_type_t::hook_lstar: {
    // RDX = KiSystemCall64 virtual address (from LSTAR MSR)
    // R8 = Shadow page physical address (with logging code)
    // This hooks the syscall entry point directly at hypervisor level!
    const virtual_address_t lstar_va = {.address = trap_frame->rdx};
    const virtual_address_t shadow_pa = {.address = trap_frame->r8};

    // Translate LSTAR VA to PA and add NPT hook
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t lstar_pa =
        memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3,
                                                        lstar_va);

    if (lstar_pa != 0) {
      // Add NPT hook: when KiSystemCall64 executes, use shadow page instead
      trap_frame->rax = slat::hook::add({.address = lstar_pa}, shadow_pa);
    } else {
      trap_frame->rax = 0;
    }
    break;
  }
  case hypercall_type_t::set_log_filter_cr3: {
    // RDX = CR3 to filter by (0 = no filter, log all)
    logs::set_filter_cr3(trap_frame->rdx);
    trap_frame->rax = 1;
    break;
  }

  default:
    break;
  }
}
