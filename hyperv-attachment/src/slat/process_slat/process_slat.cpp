#include "process_slat.h"
#include "../../crt/crt.h"

namespace {
// Target process (the game)
process_slat::target_process_t target = {};

// Scanner processes
process_slat::scanner_entry_t scanners[process_slat::MAX_SCANNER_PROCESSES] =
    {};

// Statistics
process_slat::stats_t stats = {};

// Mutex for thread safety
crt::mutex_t slat_mutex = {};

// Initialized flag
bool initialized = false;
} // namespace

void process_slat::init() {
  slat_mutex.lock();

  crt::set_memory(&target, 0, sizeof(target));
  crt::set_memory(scanners, 0, sizeof(scanners));
  crt::set_memory(&stats, 0, sizeof(stats));
  initialized = true;

  slat_mutex.release();
}

void process_slat::set_target_process(uint64_t cr3, uint64_t pid) {
  slat_mutex.lock();

  if (!initialized)
    init();

  target.cr3 = cr3;
  target.pid = pid;
  target.active = true;

  slat_mutex.release();
}

void process_slat::clear_target_process() {
  slat_mutex.lock();

  target.active = false;
  target.cr3 = 0;
  target.pid = 0;

  slat_mutex.release();
}

uint64_t process_slat::get_target_cr3() {
  return target.active ? target.cr3 : 0;
}

uint64_t process_slat::register_scanner(uint64_t cr3, uint64_t pid) {
  slat_mutex.lock();

  if (!initialized)
    init();

  // Find free slot
  for (uint32_t i = 0; i < MAX_SCANNER_PROCESSES; ++i) {
    if (!scanners[i].active) {
      scanners[i].cr3 = cr3;
      scanners[i].pid = pid;
      scanners[i].active = true;

      slat_mutex.release();
      return i + 1; // Return 1-based index
    }
  }

  slat_mutex.release();
  return 0; // No free slots
}

void process_slat::unregister_scanner(uint64_t cr3) {
  slat_mutex.lock();

  for (uint32_t i = 0; i < MAX_SCANNER_PROCESSES; ++i) {
    if (scanners[i].active && scanners[i].cr3 == cr3) {
      scanners[i].active = false;
      scanners[i].cr3 = 0;
      scanners[i].pid = 0;
      break;
    }
  }

  slat_mutex.release();
}

void process_slat::clear_all_scanners() {
  slat_mutex.lock();

  for (uint32_t i = 0; i < MAX_SCANNER_PROCESSES; ++i) {
    scanners[i].active = false;
    scanners[i].cr3 = 0;
    scanners[i].pid = 0;
  }

  slat_mutex.release();
}

uint32_t process_slat::get_scanner_count() {
  uint32_t count = 0;

  for (uint32_t i = 0; i < MAX_SCANNER_PROCESSES; ++i) {
    if (scanners[i].active)
      ++count;
  }

  return count;
}

bool process_slat::is_scanner(uint64_t cr3) {
  for (uint32_t i = 0; i < MAX_SCANNER_PROCESSES; ++i) {
    if (scanners[i].active && scanners[i].cr3 == cr3) {
      return true;
    }
  }
  return false;
}

// =============================================================================
// CORE DECISION FUNCTION
// =============================================================================
// This is the heart of process-aware SLAT switching.
// Called on every SLAT violation to determine which view to present.

process_slat::slat_view_t process_slat::get_view_for_cr3(uint64_t guest_cr3) {
  // Fast path: if no target is set, always show clean
  if (!target.active) {
    stats.other_accesses++;
    return slat_view_t::hyperv;
  }

  // Check if this is the target process (the game)
  // Target sees the hooked view
  if (guest_cr3 == target.cr3) {
    stats.target_accesses++;
    return slat_view_t::hooked;
  }

  // Check if this is a registered scanner process
  // Scanners see the clean view (they're actively hunting)
  if (is_scanner(guest_cr3)) {
    stats.scanner_accesses++;
    return slat_view_t::hyperv;
  }

  // Unknown process - show clean view (safe default)
  // This includes:
  // - Anti-cheat kernel driver
  // - System processes
  // - Any other usermode process
  stats.other_accesses++;
  return slat_view_t::hyperv;
}

const process_slat::stats_t &process_slat::get_stats() { return stats; }

void process_slat::reset_stats() {
  slat_mutex.lock();
  crt::set_memory(&stats, 0, sizeof(stats));
  slat_mutex.release();
}
