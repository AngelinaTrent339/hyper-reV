#include "violation.h"
#include "../cr3/cr3.h"
#include "../hook/hook_entry.h"
#include "../process_slat/process_slat.h"

#include "../../arch/arch.h"

// =============================================================================
// SLAT VIOLATION HANDLER WITH PROCESS-AWARE SWITCHING
// =============================================================================
// This handler now considers:
// 1. Access type (execute vs read/write)
// 2. Which PROCESS is accessing the memory
//
// Result:
// - Target process (game) gets hooked/modified view on EXECUTE
// - Scanner processes (AC using explorer.exe, etc) always get clean view
// - Other processes get clean view (safe default)

std::uint8_t slat::violation::process() {
  // Get the guest's current CR3 (identifies which process is running)
  const uint64_t guest_cr3 = arch::get_guest_cr3().flags;

  // Determine which SLAT view this process should see
  const auto view = process_slat::get_view_for_cr3(guest_cr3);

  // If this is a scanner process, ALWAYS show clean memory
  // This defeats memory scanning from trusted processes
  if (view == process_slat::slat_view_t::hyperv) {
    // For scanner processes, we don't even look at hook entries
    // They always see the original, unmodified memory
    set_cr3(hyperv_cr3());
    return 1;
  }

#ifdef _INTELMACHINE
  const auto qualification = arch::get_exit_qualification();

  if (!qualification.caused_by_translation) {
    return 0;
  }

  const std::uint64_t physical_address = arch::get_guest_physical_address();

  const hook::entry_t *const hook_entry =
      hook::entry_t::find(physical_address >> 12);

  if (hook_entry == nullptr) {
    // potentially newly added executable page
    if (qualification.execute_access) {
      set_cr3(hyperv_cr3());
    }

    return 0;
  }

  // Target process accessing hooked page
  if (qualification.execute_access) {
    set_cr3(hyperv_cr3());
    // page is now --x, and with shadow pfn (target runs hooked code)
  } else {
    set_cr3(hook_cr3());
    // page is now rw-, and with original pfn
  }
#else
  const vmcb_t *const vmcb = arch::get_vmcb();

  const npf_exit_info_1 npf_info = {.flags = vmcb->control.first_exit_info};

  if (npf_info.present == 0 || npf_info.execute_access == 0) {
    return 0;
  }

  const std::uint64_t physical_address = vmcb->control.second_exit_info;

  const hook::entry_t *const hook_entry =
      hook::entry_t::find(physical_address >> 12);

  const cr3 hook_slat_cr3 = hook_cr3();

  if (hook_entry == nullptr) {
    if (vmcb->control.nested_cr3.flags == hook_slat_cr3.flags) {
      set_cr3(hyperv_cr3());

      return 1;
    }

    return 0;
  }

  // Target process accessing hooked page - show hooked view
  set_cr3(hook_slat_cr3);
#endif

  return 1;
}
