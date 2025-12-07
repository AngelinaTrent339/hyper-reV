#include "breakpoint.h"
#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../slat/cr3/cr3.h"
#include "../slat/slat.h"
#include <intrin.h>

namespace npt_breakpoint {
// ========================================================================
// GLOBAL STATE
// ========================================================================

breakpoint_def_t breakpoints[max_breakpoints] = {};
std::uint64_t breakpoint_count = 0;

breakpoint_hit_t hit_log[max_bp_hits] = {};
std::uint64_t hit_log_head = 0;
std::uint64_t hit_log_count = 0;

saved_permissions_t saved_permissions[max_breakpoints] = {};
pending_reenable_t pending_reenable[256] = {};

// ========================================================================
// INITIALIZATION
// ========================================================================

void init() {
  crt::set_memory(breakpoints, 0, sizeof(breakpoints));
  crt::set_memory(hit_log, 0, sizeof(hit_log));
  crt::set_memory(saved_permissions, 0, sizeof(saved_permissions));
  crt::set_memory(pending_reenable, 0, sizeof(pending_reenable));
  breakpoint_count = 0;
  hit_log_head = 0;
  hit_log_count = 0;
}

// ========================================================================
// HELPER: Modify NPT permissions for a page
// ========================================================================

// Get the NPT PTE for a guest physical address and modify permissions
static bool modify_npt_permissions(std::uint64_t gpa, breakpoint_type_t type,
                                   bool remove_permissions) {
  // Get the SLAT entry for this GPA
  // We need to clear R/W/X bits based on breakpoint type

  // The SLAT module should have a function to modify permissions
  // For now, we'll use the existing hook mechanism as a pattern

  // AMD NPT: Clear present bit or R/W/X in PTE
  // When guest accesses, we get NPT violation

  std::uint64_t permissions_to_modify = 0;

  if (static_cast<std::uint8_t>(type) &
      static_cast<std::uint8_t>(breakpoint_type_t::bp_read))
    permissions_to_modify |= 1; // R bit

  if (static_cast<std::uint8_t>(type) &
      static_cast<std::uint8_t>(breakpoint_type_t::bp_write))
    permissions_to_modify |= 2; // W bit

  if (static_cast<std::uint8_t>(type) &
      static_cast<std::uint8_t>(breakpoint_type_t::bp_execute))
    permissions_to_modify |= 4; // X bit

  // Use SLAT module to modify the page permissions
  // This is architecture specific (AMD NPT vs Intel EPT)
  if (remove_permissions) {
    // Remove permissions to trigger violations
    return slat::modify_page_permissions(gpa, permissions_to_modify, false);
  } else {
    // Restore permissions
    return slat::modify_page_permissions(gpa, permissions_to_modify, true);
  }
}

// ========================================================================
// BREAKPOINT MANAGEMENT
// ========================================================================

std::int64_t add(std::uint64_t gpa, std::uint64_t size, breakpoint_type_t type,
                 breakpoint_action_t action) {
  return add_conditional(gpa, size, type, action, 0, 0, 0);
}

std::int64_t add_conditional(std::uint64_t gpa, std::uint64_t size,
                             breakpoint_type_t type, breakpoint_action_t action,
                             std::uint64_t condition_addr,
                             std::uint64_t condition_value,
                             std::uint64_t condition_mask) {
  if (breakpoint_count >= max_breakpoints)
    return -1;

  // Find free slot
  std::int64_t slot = -1;
  for (std::uint64_t i = 0; i < max_breakpoints; i++) {
    if (!breakpoints[i].enabled) {
      slot = static_cast<std::int64_t>(i);
      break;
    }
  }

  if (slot < 0)
    return -1;

  // Page-align the address
  std::uint64_t page_gpa = gpa & ~0xFFFull;

  // Save original permissions before modifying
  saved_permissions[slot].gpa = page_gpa;
  saved_permissions[slot].original_permissions = 0x7; // Assume RWX
  saved_permissions[slot].in_use = true;

  // Modify NPT to remove permissions based on BP type
  if (!modify_npt_permissions(page_gpa, type, true)) {
    saved_permissions[slot].in_use = false;
    return -1;
  }

  // Set up breakpoint entry
  breakpoints[slot].address = gpa;
  breakpoints[slot].size = size;
  breakpoints[slot].type = type;
  breakpoints[slot].action = action;
  breakpoints[slot].enabled = 1;
  breakpoints[slot].condition_address = condition_addr;
  breakpoints[slot].condition_value = condition_value;
  breakpoints[slot].condition_mask = condition_mask;

  breakpoint_count++;
  return slot;
}

bool remove(std::uint64_t gpa) {
  for (std::uint64_t i = 0; i < max_breakpoints; i++) {
    if (breakpoints[i].enabled && breakpoints[i].address == gpa) {
      // Restore original NPT permissions
      if (saved_permissions[i].in_use) {
        modify_npt_permissions(saved_permissions[i].gpa, breakpoints[i].type,
                               false);
        saved_permissions[i].in_use = false;
      }

      // Clear breakpoint
      breakpoints[i].enabled = 0;
      breakpoint_count--;
      return true;
    }
  }
  return false;
}

void remove_all() {
  for (std::uint64_t i = 0; i < max_breakpoints; i++) {
    if (breakpoints[i].enabled) {
      if (saved_permissions[i].in_use) {
        modify_npt_permissions(saved_permissions[i].gpa, breakpoints[i].type,
                               false);
        saved_permissions[i].in_use = false;
      }
      breakpoints[i].enabled = 0;
    }
  }
  breakpoint_count = 0;
}

breakpoint_def_t *find(std::uint64_t gpa) {
  for (std::uint64_t i = 0; i < max_breakpoints; i++) {
    if (breakpoints[i].enabled) {
      if (gpa >= breakpoints[i].address &&
          gpa < breakpoints[i].address + breakpoints[i].size) {
        return &breakpoints[i];
      }
    }
  }
  return nullptr;
}

breakpoint_def_t *get(std::uint64_t index) {
  if (index >= max_breakpoints)
    return nullptr;
  return &breakpoints[index];
}

// ========================================================================
// NPT VIOLATION HANDLER
// ========================================================================

bool on_npt_violation(std::uint64_t gpa, breakpoint_type_t access_type,
                      std::uint64_t rip, std::uint64_t cr3) {
  // Find matching breakpoint
  breakpoint_def_t *bp = find(gpa);
  if (!bp)
    return false;

  // Check if access type matches
  if (!(static_cast<std::uint8_t>(bp->type) &
        static_cast<std::uint8_t>(access_type)))
    return false;

  // Check condition (if conditional breakpoint)
  if (bp->condition_address != 0) {
    // Read value at condition address
    std::uint64_t current_value = 0;
    // TODO: Implement reading from condition address
    // For now, assume condition is met if condition_address is 0

    if ((current_value & bp->condition_mask) != bp->condition_value) {
      // Condition not met - allow access and don't log
      return false;
    }
  }

  // Log the hit
  breakpoint_hit_t hit = {};
  hit.timestamp = __rdtsc();
  hit.bp_address = bp->address;
  hit.access_address = gpa;
  hit.guest_rip = rip;
  hit.guest_cr3 = cr3;
  hit.access_type = access_type;
  hit.access_value = 0; // TODO: Read actual value if applicable

  // Add to circular log
  hit_log[hit_log_head] = hit;
  hit_log_head = (hit_log_head + 1) % max_bp_hits;
  if (hit_log_count < max_bp_hits)
    hit_log_count++;

  // Increment hit count
  bp->hit_count++;

  // Handle based on action
  switch (bp->action) {
  case breakpoint_action_t::action_log:
    // Just log - allow the access to continue
    // Temporarily restore permissions for this instruction
    break;

  case breakpoint_action_t::action_break:
    // TODO: Signal usermode that BP was hit
    break;

  case breakpoint_action_t::action_trace:
    // TODO: Enable instruction tracing
    break;

  default:
    break;
  }

  return true;
}

// ========================================================================
// HIT LOG MANAGEMENT
// ========================================================================

std::uint64_t get_hits(breakpoint_hit_t *buffer, std::uint64_t max_count) {
  std::uint64_t count = (hit_log_count < max_count) ? hit_log_count : max_count;

  // Copy from circular buffer
  for (std::uint64_t i = 0; i < count; i++) {
    std::uint64_t idx =
        (hit_log_head - hit_log_count + i + max_bp_hits) % max_bp_hits;
    buffer[i] = hit_log[idx];
  }

  return count;
}

void clear_hits() {
  hit_log_head = 0;
  hit_log_count = 0;
}

std::uint64_t get_hit_count() { return hit_log_count; }

// ========================================================================
// SINGLE-STEP HANDLING
// ========================================================================

void on_single_step_complete(std::uint64_t cpu_index) {
  if (cpu_index >= 256)
    return;

  if (!pending_reenable[cpu_index].pending)
    return;

  // Re-enable the breakpoint
  std::uint64_t bp_idx = pending_reenable[cpu_index].bp_index;
  if (bp_idx < max_breakpoints && breakpoints[bp_idx].enabled) {
    std::uint64_t page_gpa = breakpoints[bp_idx].address & ~0xFFFull;
    modify_npt_permissions(page_gpa, breakpoints[bp_idx].type, true);
  }

  pending_reenable[cpu_index].pending = false;
}

void setup_single_step(std::uint64_t cpu_index, std::uint64_t bp_index) {
  if (cpu_index >= 256 || bp_index >= max_breakpoints)
    return;

  // First, temporarily restore permissions so the instruction can execute
  std::uint64_t page_gpa = breakpoints[bp_index].address & ~0xFFFull;
  modify_npt_permissions(page_gpa, breakpoints[bp_index].type, false);

  // Mark that we need to re-enable after single step
  pending_reenable[cpu_index].gpa = page_gpa;
  pending_reenable[cpu_index].bp_index = bp_index;
  pending_reenable[cpu_index].pending = true;

  // The caller should now set TF in RFLAGS to enable single-step
  // (handled in arch-specific code)
}
} // namespace npt_breakpoint
