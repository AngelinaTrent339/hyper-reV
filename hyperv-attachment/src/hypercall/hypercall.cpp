#include "hypercall.h"
#include "../memory_manager/heap_manager.h"
#include "../memory_manager/memory_manager.h"

#include "../slat/cr3/cr3.h"
#include "../slat/hook/hook.h"
#include "../slat/slat.h"

#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../logs/logs.h"
#include "../msr/msr_shadow.h"
#include "../msr/msrpm.h"
#include "../slat/hidden_alloc/hidden_alloc.h"

#include <hypercall/hypercall_def.h>
#include <ia32-doc/ia32.hpp>

// =============================================================================
// Process CR3 Auto-Tracking State
// =============================================================================
// This allows automatic capture of a process's CR3 by monitoring VM exits
// and checking the current guest's GS base (which points to KTHREAD/TEB in user
// mode)

namespace process_tracking {
// The PID we're looking for
volatile std::uint64_t tracked_pid = 0;

// The captured CR3 for the tracked process
volatile std::uint64_t tracked_cr3 = 0;

// Counter for how many times we've seen the process (debugging)
volatile std::uint64_t match_count = 0;

// GS base when we captured the CR3 (for debugging)
volatile std::uint64_t captured_gs_base = 0;
} // namespace process_tracking

// =============================================================================
// try_capture_tracked_cr3 - Called on every VM exit to capture target CR3
// =============================================================================
// This function checks if the current guest process matches our tracked PID.
// On Windows x64, when in user mode:
//   - GS base points to the TEB (Thread Environment Block)
//   - TEB+0x40 contains the ClientId structure (PID at offset 0)
// When in kernel mode:
//   - GS base points to the KPCR (Kernel Processor Control Region)
//   - We can walk to KTHREAD and get the process ID
//
// For simplicity, we check user-mode GS base (TEB) since most VM exits from
// a user-mode process will have the TEB in GS.

void hypercall::try_capture_tracked_cr3() {
  // Quick check - if not tracking or already captured, return immediately
  if (process_tracking::tracked_pid == 0) {
    return;
  }

  if (process_tracking::tracked_cr3 != 0) {
    return; // Already captured
  }

#ifndef _INTELMACHINE
  // AMD: Get VMCB to check CPL and GS base
  vmcb_t *vmcb = arch::get_vmcb();
  if (vmcb == nullptr) {
    return;
  }

  // Check if we're in Ring 3 (user mode) - CS selector RPL bits
  const std::uint16_t cs_selector = vmcb->save_state.cs_selector;
  const std::uint8_t cpl = cs_selector & 0x3;

  if (cpl != 3) {
    return; // Not in user mode, skip
  }

  // In user mode, GS base points to TEB
  const std::uint64_t gs_base = vmcb->save_state.gs_base;
  if (gs_base == 0) {
    return;
  }

  // Read PID from TEB+0x40 (ClientId.UniqueProcess)
  // TEB structure (partial):
  //   +0x000 NtTib
  //   +0x038 ClientId
  //   +0x038   UniqueProcess (HANDLE = 8 bytes on x64)
  //   +0x040   UniqueThread
  // Wait, that's wrong. Let me check:
  // Actually on Windows x64, in the TEB:
  //   +0x040 points to ClientId.UniqueProcess (the PID as HANDLE)

  const cr3 guest_cr3 = {.flags = vmcb->save_state.cr3};
  const cr3 slat_cr3 = slat::hyperv_cr3();

  // Translate the GS:0x40 address (TEB+0x40 = ClientId.UniqueProcess)
  const std::uint64_t pid_addr = gs_base + 0x40;
  const std::uint64_t pid_physical =
      memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3,
                                                      {.address = pid_addr});

  if (pid_physical == 0) {
    return; // Translation failed
  }

  // Map and read the PID
  void *pid_host_addr =
      memory_manager::map_guest_physical(slat_cr3, pid_physical, nullptr);
  if (pid_host_addr == nullptr) {
    return;
  }

  // Read the PID (it's a HANDLE, which is 8 bytes on x64)
  std::uint64_t current_pid = *reinterpret_cast<std::uint64_t *>(pid_host_addr);

  // Check if this matches our tracked PID
  if (current_pid == process_tracking::tracked_pid) {
    // Match! Capture the CR3
    process_tracking::tracked_cr3 = guest_cr3.address_of_page_directory << 12;
    process_tracking::captured_gs_base = gs_base;
    process_tracking::match_count++;
  }

#else
  // Intel: Similar logic but using VMCS reads
  // For Intel, we need to use vmread to get guest state

  // Read CS access rights to check CPL
  std::uint64_t cs_access_rights = 0;
  vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_access_rights);
  const std::uint8_t dpl = (cs_access_rights >> 5) & 0x3;

  if (dpl != 3) {
    return; // Not Ring 3
  }

  // Read GS base
  std::uint64_t gs_base = 0;
  vmread(VMCS_GUEST_GS_BASE, &gs_base);

  if (gs_base == 0) {
    return;
  }

  // Read CR3
  const cr3 guest_cr3 = arch::get_guest_cr3();
  const cr3 slat_cr3 = slat::hyperv_cr3();

  // Read PID from TEB+0x40
  const std::uint64_t pid_addr = gs_base + 0x40;
  const std::uint64_t pid_physical =
      memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3,
                                                      {.address = pid_addr});

  if (pid_physical == 0) {
    return;
  }

  void *pid_host_addr =
      memory_manager::map_guest_physical(slat_cr3, pid_physical, nullptr);
  if (pid_host_addr == nullptr) {
    return;
  }

  std::uint64_t current_pid = *reinterpret_cast<std::uint64_t *>(pid_host_addr);

  if (current_pid == process_tracking::tracked_pid) {
    process_tracking::tracked_cr3 = guest_cr3.address_of_page_directory << 12;
    process_tracking::captured_gs_base = gs_base;
    process_tracking::match_count++;
  }
#endif
}

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
  // =========================================================================
  // Process CR3 Auto-Tracking Hypercalls
  // =========================================================================
  case hypercall_type_t::set_tracked_pid: {
    // rdx = PID to track
    process_tracking::tracked_pid = trap_frame->rdx;
    process_tracking::tracked_cr3 = 0; // Reset captured CR3
    process_tracking::match_count = 0; // Reset match counter
    process_tracking::captured_gs_base = 0;

    trap_frame->rax = 1; // Success
    break;
  }
  case hypercall_type_t::get_tracked_cr3: {
    // Returns the captured CR3, or 0 if not yet captured
    trap_frame->rax = process_tracking::tracked_cr3;
    break;
  }
  case hypercall_type_t::clear_tracked_pid: {
    // Clear all tracking state
    process_tracking::tracked_pid = 0;
    process_tracking::tracked_cr3 = 0;
    process_tracking::match_count = 0;
    process_tracking::captured_gs_base = 0;

    trap_frame->rax = 1; // Success
    break;
  }
  case hypercall_type_t::get_tracking_status: {
    // Returns tracking status:
    // rax = tracked_cr3 (or 0 if not captured)
    // Also writes to provided buffer if r8 is non-zero

    // If caller provides a buffer (r8), write extended status there
    if (trap_frame->r8 != 0) {
      const cr3 guest_cr3 = arch::get_guest_cr3();
      const cr3 slat_cr3 = slat::hyperv_cr3();

      // Buffer format: [tracked_pid, tracked_cr3, match_count, gs_base]
      std::uint64_t status_buffer[4] = {
          process_tracking::tracked_pid, process_tracking::tracked_cr3,
          process_tracking::match_count, process_tracking::captured_gs_base};

      const std::uint64_t guest_buffer_physical_address =
          memory_manager::translate_guest_virtual_address(
              guest_cr3, slat_cr3, {.address = trap_frame->r8});

      if (guest_buffer_physical_address != 0) {
        void *host_dest = memory_manager::map_guest_physical(
            slat_cr3, guest_buffer_physical_address, nullptr);
        if (host_dest != nullptr) {
          crt::copy_memory(host_dest, status_buffer, sizeof(status_buffer));
        }
      }
    }

    trap_frame->rax = process_tracking::tracked_cr3;
    break;
  }
  // =========================================================================
  // MSR Shadow Hypercalls
  // =========================================================================
  case hypercall_type_t::add_msr_shadow: {
    // rdx = MSR index
    // r8 = shadow value
    const std::uint32_t msr_index = static_cast<std::uint32_t>(trap_frame->rdx);
    const std::uint64_t shadow_value = trap_frame->r8;

    trap_frame->rax = msr_shadow::add_shadow(msr_index, shadow_value, 1, 0);
    break;
  }
  case hypercall_type_t::remove_msr_shadow: {
    // rdx = MSR index
    const std::uint32_t msr_index = static_cast<std::uint32_t>(trap_frame->rdx);

    trap_frame->rax = msr_shadow::remove_shadow(msr_index);
    break;
  }
  case hypercall_type_t::get_msr_shadow_list: {
    // r8 = output buffer (optional)
    // Returns: count of active shadows

    const std::uint32_t count = msr_shadow::get_shadow_count();

    // If buffer provided, write the shadow entries
    if (trap_frame->r8 != 0 && count > 0) {
      const cr3 guest_cr3 = arch::get_guest_cr3();
      const cr3 slat_cr3 = slat::hyperv_cr3();

      // Buffer format: array of [msr_index (4 bytes), shadow_value (8 bytes)]
      struct msr_entry_output {
        std::uint32_t msr_index;
        std::uint32_t padding;
        std::uint64_t shadow_value;
      };

      const std::uint64_t guest_buffer_physical =
          memory_manager::translate_guest_virtual_address(
              guest_cr3, slat_cr3, {.address = trap_frame->r8});

      if (guest_buffer_physical != 0) {
        msr_entry_output *host_buffer =
            static_cast<msr_entry_output *>(memory_manager::map_guest_physical(
                slat_cr3, guest_buffer_physical, nullptr));

        if (host_buffer != nullptr) {
          for (std::uint32_t i = 0; i < count; ++i) {
            const msr_shadow::entry_t *entry = msr_shadow::get_entry(i);
            if (entry != nullptr) {
              host_buffer[i].msr_index = entry->msr_index;
              host_buffer[i].padding = 0;
              host_buffer[i].shadow_value = entry->shadow_value;
            }
          }
        }
      }
    }

    trap_frame->rax = count;
    break;
  }
  case hypercall_type_t::clear_all_msr_shadows: {
    // Clear all MSR shadows
    msr_shadow::init();
    trap_frame->rax = 1;
    break;
  }
  case hypercall_type_t::read_msr_value: {
    // rdx = MSR index
    // Returns the value guest would see (shadow if exists)
    const std::uint32_t msr_index = static_cast<std::uint32_t>(trap_frame->rdx);
    trap_frame->rax = msr_shadow::read_msr_for_guest(msr_index);
    break;
  }
  case hypercall_type_t::get_msr_intercept_count: {
    // Returns the count of MSR intercepts that returned shadow values
    trap_frame->rax = msr_shadow::get_intercept_count();
    break;
  }
  case hypercall_type_t::set_msr_intercept: {
    // rdx = MSR index, r8 = flags (bit0=read, bit1=write)
    const std::uint32_t msr_index = static_cast<std::uint32_t>(trap_frame->rdx);
    const std::uint8_t flags = static_cast<std::uint8_t>(trap_frame->r8);
    const std::uint8_t intercept_read = (flags & 0x01) ? 1 : 0;
    const std::uint8_t intercept_write = (flags & 0x02) ? 1 : 0;
    trap_frame->rax =
        msrpm::set_msr_intercept(msr_index, intercept_read, intercept_write);
    break;
  }
  case hypercall_type_t::get_msr_intercept_status: {
    // rdx = MSR index
    // Returns intercept flags (bit0=read, bit1=write)
    const std::uint32_t msr_index = static_cast<std::uint32_t>(trap_frame->rdx);
    trap_frame->rax = msrpm::get_msr_intercept(msr_index);
    break;
  }
  // =========================================================================
  // Hidden Allocation Hypercalls
  // =========================================================================
  case hypercall_type_t::hidden_alloc_region: {
    // rdx = page_count
    // Returns: region_id (0 = failure)
    const std::uint32_t page_count =
        static_cast<std::uint32_t>(trap_frame->rdx);
    trap_frame->rax = hidden_alloc::allocate_region(page_count);
    break;
  }
  case hypercall_type_t::hidden_write_region: {
    // rdx = region_id, r8 = offset, r9 = data_ptr (guest VA), r10 = size
    const std::uint64_t region_id = trap_frame->rdx;
    const std::uint64_t offset = trap_frame->r8;
    const std::uint64_t guest_data_ptr = trap_frame->r9;
    const std::uint64_t size = trap_frame->r10;

    // Translate guest VA to host VA and copy data to hidden region
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    // Read data from guest in chunks
    std::uint64_t bytes_written = 0;
    std::uint64_t remaining = size;

    while (remaining > 0) {
      const std::uint64_t chunk_size =
          (remaining > 0x1000) ? 0x1000 : remaining;
      const std::uint64_t guest_phys =
          memory_manager::translate_guest_virtual_address(
              guest_cr3, slat_cr3, {.address = guest_data_ptr + bytes_written});

      if (guest_phys == 0)
        break;

      void *host_src =
          memory_manager::map_guest_physical(slat_cr3, guest_phys, nullptr);
      if (host_src == nullptr)
        break;

      const std::uint64_t written = hidden_alloc::write_region(
          region_id, offset + bytes_written, host_src, chunk_size);
      if (written == 0)
        break;

      bytes_written += written;
      remaining -= written;
    }

    trap_frame->rax = bytes_written;
    break;
  }
  case hypercall_type_t::hidden_read_region: {
    // rdx = region_id, r8 = offset, r9 = buffer_ptr (guest VA), r10 = size
    const std::uint64_t region_id = trap_frame->rdx;
    const std::uint64_t offset = trap_frame->r8;
    const std::uint64_t guest_buffer_ptr = trap_frame->r9;
    const std::uint64_t size = trap_frame->r10;

    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    std::uint64_t bytes_read = 0;
    std::uint64_t remaining = size;

    while (remaining > 0) {
      const std::uint64_t chunk_size =
          (remaining > 0x1000) ? 0x1000 : remaining;
      const std::uint64_t guest_phys =
          memory_manager::translate_guest_virtual_address(
              guest_cr3, slat_cr3, {.address = guest_buffer_ptr + bytes_read});

      if (guest_phys == 0)
        break;

      void *host_dest =
          memory_manager::map_guest_physical(slat_cr3, guest_phys, nullptr);
      if (host_dest == nullptr)
        break;

      const std::uint64_t read = hidden_alloc::read_region(
          region_id, offset + bytes_read, host_dest, chunk_size);
      if (read == 0)
        break;

      bytes_read += read;
      remaining -= read;
    }

    trap_frame->rax = bytes_read;
    break;
  }
  case hypercall_type_t::hidden_expose_region: {
    // rdx = region_id, r8 = target_va, r9 = target_cr3, r10 = executable
    const std::uint64_t region_id = trap_frame->rdx;
    const std::uint64_t target_va = trap_frame->r8;
    const std::uint64_t target_cr3 = trap_frame->r9;
    const std::uint8_t executable = static_cast<std::uint8_t>(trap_frame->r10);

    trap_frame->rax = hidden_alloc::expose_region(region_id, target_va,
                                                  target_cr3, executable);
    break;
  }
  case hypercall_type_t::hidden_hide_region: {
    // rdx = region_id
    const std::uint64_t region_id = trap_frame->rdx;
    trap_frame->rax = hidden_alloc::hide_region(region_id);
    break;
  }
  case hypercall_type_t::hidden_free_region: {
    // rdx = region_id
    const std::uint64_t region_id = trap_frame->rdx;
    trap_frame->rax = hidden_alloc::free_region(region_id);
    break;
  }
  case hypercall_type_t::hidden_get_region_info: {
    // rdx = region_id, r8 = output_buffer (guest VA)
    const std::uint64_t region_id = trap_frame->rdx;
    const std::uint64_t guest_buffer = trap_frame->r8;

    const hidden_alloc::hidden_region_t *region =
        hidden_alloc::get_region(region_id);

    if (region != nullptr && guest_buffer != 0) {
      const cr3 guest_cr3 = arch::get_guest_cr3();
      const cr3 slat_cr3 = slat::hyperv_cr3();

      const std::uint64_t guest_phys =
          memory_manager::translate_guest_virtual_address(
              guest_cr3, slat_cr3, {.address = guest_buffer});

      if (guest_phys != 0) {
        void *host_dest =
            memory_manager::map_guest_physical(slat_cr3, guest_phys, nullptr);
        if (host_dest != nullptr) {
          crt::copy_memory(host_dest, region,
                           sizeof(hidden_alloc::hidden_region_t));
          trap_frame->rax = 1;
          break;
        }
      }
    }
    trap_frame->rax = 0;
    break;
  }
  case hypercall_type_t::hidden_get_region_count: {
    trap_frame->rax = hidden_alloc::get_active_region_count();
    break;
  }
  default:
    break;
  }
}
