#include "hypercall.h"
#include "../memory_manager/heap_manager.h"
#include "../memory_manager/memory_manager.h"

#include "../slat/cr3/cr3.h"
#include "../slat/hook/hook.h"
#include "../slat/slat.h"

#include "../breakpoint/breakpoint.h"
#include "../process/process.h"


#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../logs/logs.h"

#include <hypercall/hypercall_def.h>
#include <ia32-doc/ia32.hpp>
#include <structures/breakpoint_info.h>
#include <structures/process_info.h>

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

    void *host_destination = memory_manager::map_guest_physical(
        slat_cr3, guest_buffer_physical_address,
        &size_left_of_destination_slat_page);
    void *host_source = memory_manager::map_guest_physical(
        slat_cr3, guest_physical_address + bytes_copied,
        &size_left_of_source_slat_page);

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

    // ========================================================================
    // PHASE 2: PROCESS TARGETING HYPERCALLS
    // ========================================================================

  case hypercall_type_t::attach_to_process: {
    // rdx = target CR3 (0 to attach to all)
    process::attach(trap_frame->rdx);
    trap_frame->rax = 1;
    break;
  }

  case hypercall_type_t::detach_from_process: {
    process::detach();
    trap_frame->rax = 1;
    break;
  }

  case hypercall_type_t::get_process_by_name: {
    // rdx = pointer to process name string (guest virtual)
    // Returns CR3 or 0 if not found
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    char name_buffer[16] = {};
    std::uint64_t bytes_read = 0;

    // Read process name from guest memory
    for (int i = 0; i < 15; i++) {
      std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
          guest_cr3, slat_cr3, {.address = trap_frame->rdx + i});

      if (gpa == 0)
        break;

      std::uint64_t size_left = 0;
      char *mapped = static_cast<char *>(
          memory_manager::map_guest_physical(slat_cr3, gpa, &size_left));
      if (!mapped)
        break;

      name_buffer[i] = *mapped;
      if (*mapped == 0)
        break;
    }

    trap_frame->rax = process::find_by_name(name_buffer);
    break;
  }

  case hypercall_type_t::get_process_list: {
    // rdx = pointer to process_info_t array (guest virtual)
    // r8 = max count
    // Returns number of processes enumerated
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t buffer_va = trap_frame->rdx;
    const std::uint64_t max_count = trap_frame->r8;

    // Allocate temp buffer in hypervisor heap for enumeration
    constexpr std::uint64_t max_enum = 256;
    const std::uint64_t actual_max =
        (max_count < max_enum) ? max_count : max_enum;

    process_info_t temp_buffer[256] = {};
    std::uint64_t count = process::enumerate(temp_buffer, actual_max);

    // Copy results to guest buffer
    for (std::uint64_t i = 0; i < count; i++) {
      std::uint64_t dest_gpa = memory_manager::translate_guest_virtual_address(
          guest_cr3, slat_cr3,
          {.address = buffer_va + i * sizeof(process_info_t)});

      if (dest_gpa == 0)
        break;

      std::uint64_t size_left = 0;
      void *dest =
          memory_manager::map_guest_physical(slat_cr3, dest_gpa, &size_left);
      if (!dest || size_left < sizeof(process_info_t))
        break;

      crt::copy_memory(dest, &temp_buffer[i], sizeof(process_info_t));
    }

    trap_frame->rax = count;
    break;
  }

  case hypercall_type_t::set_windows_offsets: {
    // rdx = pointer to windows_offsets_t (guest virtual)
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    std::uint64_t gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = trap_frame->rdx});

    if (gpa == 0) {
      trap_frame->rax = 0;
      break;
    }

    std::uint64_t size_left = 0;
    void *src = memory_manager::map_guest_physical(slat_cr3, gpa, &size_left);

    if (!src || size_left < sizeof(windows_offsets_t)) {
      trap_frame->rax = 0;
      break;
    }

    windows_offsets_t offsets = {};
    crt::copy_memory(&offsets, src, sizeof(windows_offsets_t));
    process::set_offsets(offsets);

    trap_frame->rax = 1;
    break;
  }

  case hypercall_type_t::enumerate_modules: {
    // rdx = target CR3
    // r8 = PEB address
    // r9 = pointer to module_info_t array (guest virtual)
    // [rsp+0x28] = max count (5th arg on stack)
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t target_cr3 = trap_frame->rdx;
    const std::uint64_t peb = trap_frame->r8;
    const std::uint64_t buffer_va = trap_frame->r9;

    // Read 5th argument from guest stack
    std::uint64_t max_count = 64;
    std::uint64_t stack_arg_gpa =
        memory_manager::translate_guest_virtual_address(
            guest_cr3, slat_cr3, {.address = trap_frame->rsp + 0x28});
    if (stack_arg_gpa != 0) {
      std::uint64_t size_left = 0;
      std::uint64_t *mapped =
          static_cast<std::uint64_t *>(memory_manager::map_guest_physical(
              slat_cr3, stack_arg_gpa, &size_left));
      if (mapped && size_left >= 8)
        max_count = *mapped;
    }

    constexpr std::uint64_t max_enum = 128;
    const std::uint64_t actual_max =
        (max_count < max_enum) ? max_count : max_enum;

    module_info_t temp_buffer[128] = {};
    std::uint64_t count =
        process::enumerate_modules(target_cr3, peb, temp_buffer, actual_max);

    // Copy results to guest buffer
    for (std::uint64_t i = 0; i < count; i++) {
      std::uint64_t dest_gpa = memory_manager::translate_guest_virtual_address(
          guest_cr3, slat_cr3,
          {.address = buffer_va + i * sizeof(module_info_t)});

      if (dest_gpa == 0)
        break;

      std::uint64_t size_left = 0;
      void *dest =
          memory_manager::map_guest_physical(slat_cr3, dest_gpa, &size_left);
      if (!dest || size_left < sizeof(module_info_t))
        break;

      crt::copy_memory(dest, &temp_buffer[i], sizeof(module_info_t));
    }

    trap_frame->rax = count;
    break;
  }

    // ========================================================================
    // PHASE 3: INVISIBLE NPT BREAKPOINTS
    // ========================================================================

  case hypercall_type_t::add_breakpoint: {
    // rdx = guest physical address
    // r8 = size
    // r9 = type (breakpoint_type_t)
    // Stack [rsp+0x28] = action (breakpoint_action_t)
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t gpa = trap_frame->rdx;
    const std::uint64_t size = trap_frame->r8;
    const breakpoint_type_t type =
        static_cast<breakpoint_type_t>(trap_frame->r9);

    // Read action from stack
    breakpoint_action_t action = breakpoint_action_t::action_log;
    std::uint64_t stack_gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = trap_frame->rsp + 0x28});
    if (stack_gpa != 0) {
      std::uint64_t size_left = 0;
      std::uint8_t *mapped = static_cast<std::uint8_t *>(
          memory_manager::map_guest_physical(slat_cr3, stack_gpa, &size_left));
      if (mapped && size_left >= 1)
        action = static_cast<breakpoint_action_t>(*mapped);
    }

    trap_frame->rax = breakpoint::add(gpa, size, type, action);
    break;
  }

  case hypercall_type_t::remove_breakpoint: {
    // rdx = guest physical address
    trap_frame->rax = breakpoint::remove(trap_frame->rdx) ? 1 : 0;
    break;
  }

  case hypercall_type_t::add_conditional_breakpoint: {
    // rdx = guest physical address
    // r8 = size
    // r9 = type
    // Stack args: action, condition_addr, condition_value, condition_mask
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t gpa = trap_frame->rdx;
    const std::uint64_t size = trap_frame->r8;
    const breakpoint_type_t type =
        static_cast<breakpoint_type_t>(trap_frame->r9);

    // Read remaining args from stack
    breakpoint_action_t action = breakpoint_action_t::action_log;
    std::uint64_t condition_addr = 0, condition_value = 0, condition_mask = 0;

    // action at rsp+0x28
    std::uint64_t arg_gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = trap_frame->rsp + 0x28});
    if (arg_gpa != 0) {
      std::uint64_t size_left = 0;
      std::uint8_t *mapped = static_cast<std::uint8_t *>(
          memory_manager::map_guest_physical(slat_cr3, arg_gpa, &size_left));
      if (mapped)
        action = static_cast<breakpoint_action_t>(*mapped);
    }

    // condition_addr at rsp+0x30
    arg_gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = trap_frame->rsp + 0x30});
    if (arg_gpa != 0) {
      std::uint64_t size_left = 0;
      std::uint64_t *mapped = static_cast<std::uint64_t *>(
          memory_manager::map_guest_physical(slat_cr3, arg_gpa, &size_left));
      if (mapped && size_left >= 8)
        condition_addr = *mapped;
    }

    // condition_value at rsp+0x38
    arg_gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = trap_frame->rsp + 0x38});
    if (arg_gpa != 0) {
      std::uint64_t size_left = 0;
      std::uint64_t *mapped = static_cast<std::uint64_t *>(
          memory_manager::map_guest_physical(slat_cr3, arg_gpa, &size_left));
      if (mapped && size_left >= 8)
        condition_value = *mapped;
    }

    // condition_mask at rsp+0x40
    arg_gpa = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, {.address = trap_frame->rsp + 0x40});
    if (arg_gpa != 0) {
      std::uint64_t size_left = 0;
      std::uint64_t *mapped = static_cast<std::uint64_t *>(
          memory_manager::map_guest_physical(slat_cr3, arg_gpa, &size_left));
      if (mapped && size_left >= 8)
        condition_mask = *mapped;
    }

    trap_frame->rax =
        breakpoint::add_conditional(gpa, size, type, action, condition_addr,
                                    condition_value, condition_mask);
    break;
  }

  case hypercall_type_t::list_breakpoints: {
    // rdx = pointer to breakpoint_def_t array
    // r8 = max count
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t buffer_va = trap_frame->rdx;
    const std::uint64_t max_count = trap_frame->r8;

    std::uint64_t copied = 0;
    for (std::uint64_t i = 0;
         i < breakpoint::max_breakpoints && copied < max_count; i++) {
      breakpoint_def_t *bp = breakpoint::get(i);
      if (bp && bp->enabled) {
        std::uint64_t dest_gpa =
            memory_manager::translate_guest_virtual_address(
                guest_cr3, slat_cr3,
                {.address = buffer_va + copied * sizeof(breakpoint_def_t)});
        if (dest_gpa == 0)
          break;

        std::uint64_t size_left = 0;
        void *dest =
            memory_manager::map_guest_physical(slat_cr3, dest_gpa, &size_left);
        if (!dest || size_left < sizeof(breakpoint_def_t))
          break;

        crt::copy_memory(dest, bp, sizeof(breakpoint_def_t));
        copied++;
      }
    }
    trap_frame->rax = copied;
    break;
  }

  case hypercall_type_t::get_breakpoint_hits: {
    // rdx = pointer to breakpoint_hit_t array
    // r8 = max count
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    const std::uint64_t buffer_va = trap_frame->rdx;
    const std::uint64_t max_count = trap_frame->r8;

    // Get hits into temp buffer
    breakpoint_hit_t temp_hits[256] = {};
    std::uint64_t actual_max = (max_count < 256) ? max_count : 256;
    std::uint64_t hit_count = breakpoint::get_hits(temp_hits, actual_max);

    // Copy to guest
    for (std::uint64_t i = 0; i < hit_count; i++) {
      std::uint64_t dest_gpa = memory_manager::translate_guest_virtual_address(
          guest_cr3, slat_cr3,
          {.address = buffer_va + i * sizeof(breakpoint_hit_t)});
      if (dest_gpa == 0)
        break;

      std::uint64_t size_left = 0;
      void *dest =
          memory_manager::map_guest_physical(slat_cr3, dest_gpa, &size_left);
      if (!dest || size_left < sizeof(breakpoint_hit_t))
        break;

      crt::copy_memory(dest, &temp_hits[i], sizeof(breakpoint_hit_t));
    }
    trap_frame->rax = hit_count;
    break;
  }

  case hypercall_type_t::clear_breakpoint_hits: {
    breakpoint::clear_hits();
    trap_frame->rax = 1;
    break;
  }

  default:
    break;
  }
}
