#pragma once
#include <structures/trap_frame.h>

union hypercall_info_t;

namespace hypercall {
void process(hypercall_info_t hypercall_info, trap_frame_t *trap_frame);

// Process CR3 auto-tracking: call this on every VM exit to attempt
// to capture the CR3 of the tracked process
void try_capture_tracked_cr3();
} // namespace hypercall
