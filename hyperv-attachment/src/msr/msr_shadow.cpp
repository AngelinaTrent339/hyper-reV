#include "msr_shadow.h"
#include "../crt/crt.h"

namespace {
// Storage for MSR shadow entries
msr_shadow::entry_t shadow_entries[msr_shadow::MAX_SHADOW_ENTRIES] = {};
std::uint32_t shadow_count = 0;
} // namespace

void msr_shadow::init() {
  // Clear all shadow entries
  crt::set_memory(shadow_entries, 0, sizeof(shadow_entries));
  shadow_count = 0;
}

std::uint8_t msr_shadow::add_shadow(std::uint32_t msr_index,
                                    std::uint64_t shadow_value,
                                    std::uint8_t shadow_reads,
                                    std::uint8_t shadow_writes) {
  // Check if already exists and update
  for (std::uint32_t i = 0; i < shadow_count; ++i) {
    if (shadow_entries[i].msr_index == msr_index) {
      shadow_entries[i].shadow_value = shadow_value;
      shadow_entries[i].is_active = 1;
      shadow_entries[i].shadow_on_read = shadow_reads;
      shadow_entries[i].shadow_on_write = shadow_writes;
      return 1;
    }
  }

  // Add new entry
  if (shadow_count >= MAX_SHADOW_ENTRIES) {
    return 0; // Full
  }

  shadow_entries[shadow_count].msr_index = msr_index;
  shadow_entries[shadow_count].shadow_value = shadow_value;
  shadow_entries[shadow_count].is_active = 1;
  shadow_entries[shadow_count].shadow_on_read = shadow_reads;
  shadow_entries[shadow_count].shadow_on_write = shadow_writes;
  ++shadow_count;

  return 1;
}

std::uint8_t msr_shadow::remove_shadow(std::uint32_t msr_index) {
  for (std::uint32_t i = 0; i < shadow_count; ++i) {
    if (shadow_entries[i].msr_index == msr_index) {
      // Shift remaining entries down
      for (std::uint32_t j = i; j < shadow_count - 1; ++j) {
        shadow_entries[j] = shadow_entries[j + 1];
      }
      --shadow_count;
      return 1;
    }
  }
  return 0;
}

const msr_shadow::entry_t *msr_shadow::get_shadow(std::uint32_t msr_index) {
  for (std::uint32_t i = 0; i < shadow_count; ++i) {
    if (shadow_entries[i].msr_index == msr_index &&
        shadow_entries[i].is_active) {
      return &shadow_entries[i];
    }
  }
  return nullptr;
}

std::uint8_t msr_shadow::handle_rdmsr(std::uint32_t msr_index,
                                      std::uint64_t *value_out) {
  const entry_t *entry = get_shadow(msr_index);

  if (entry == nullptr) {
    return 0; // No shadow for this MSR
  }

  if (entry->shadow_on_read == 0) {
    return 0; // Shadow exists but read interception disabled
  }

  *value_out = entry->shadow_value;
  return 1; // Shadow applied
}

std::uint8_t msr_shadow::handle_wrmsr(std::uint32_t msr_index,
                                      std::uint64_t value) {
  const entry_t *entry = get_shadow(msr_index);

  if (entry == nullptr) {
    return 0; // No shadow for this MSR
  }

  if (entry->shadow_on_write == 0) {
    return 0; // Shadow exists but write interception disabled
  }

  // For write shadowing, we typically just block the write
  // or allow it but track the "intended" value
  // For now, we just block (return 1 = handled, don't actually write)
  return 1;
}

std::uint32_t msr_shadow::get_shadow_count() { return shadow_count; }

const msr_shadow::entry_t *msr_shadow::get_entry(std::uint32_t index) {
  if (index >= shadow_count) {
    return nullptr;
  }
  return &shadow_entries[index];
}
