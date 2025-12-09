#include "msr_shadow.h"
#include "../crt/crt.h"

// Storage for MSR shadow entries - using volatile to ensure proper access
// in hypervisor context where memory ordering matters
namespace msr_shadow_state {
    // Use a simple struct to hold all state together
    struct state_t {
        msr_shadow::entry_t entries[msr_shadow::MAX_SHADOW_ENTRIES];
        volatile std::uint32_t count;
        volatile std::uint64_t intercept_count;
        volatile std::uint8_t initialized;
    };
    
    // Single global state - marked volatile
    volatile state_t g_state;
    
    // Ensure state is initialized before use
    void ensure_init() {
        if (g_state.initialized != 0xAB) {
            // First-time initialization
            crt::set_memory((void*)&g_state, 0, sizeof(g_state));
            g_state.initialized = 0xAB;  // Magic marker
        }
    }
}

void msr_shadow::init() {
    crt::set_memory((void*)&msr_shadow_state::g_state, 0, sizeof(msr_shadow_state::g_state));
    msr_shadow_state::g_state.initialized = 0xAB;
}

std::uint8_t msr_shadow::add_shadow(std::uint32_t msr_index,
                                    std::uint64_t shadow_value,
                                    std::uint8_t shadow_reads,
                                    std::uint8_t shadow_writes) {
    msr_shadow_state::ensure_init();
    
    volatile auto& state = msr_shadow_state::g_state;
    
    // Check if already exists and update
    for (std::uint32_t i = 0; i < state.count; ++i) {
        if (state.entries[i].msr_index == msr_index) {
            state.entries[i].shadow_value = shadow_value;
            state.entries[i].is_active = 1;
            state.entries[i].shadow_on_read = shadow_reads;
            state.entries[i].shadow_on_write = shadow_writes;
            return 1;
        }
    }

    // Add new entry
    if (state.count >= MAX_SHADOW_ENTRIES) {
        return 0; // Full
    }

    std::uint32_t idx = state.count;
    state.entries[idx].msr_index = msr_index;
    state.entries[idx].shadow_value = shadow_value;
    state.entries[idx].is_active = 1;
    state.entries[idx].shadow_on_read = shadow_reads;
    state.entries[idx].shadow_on_write = shadow_writes;
    state.count = idx + 1;

    return 1;
}

std::uint8_t msr_shadow::remove_shadow(std::uint32_t msr_index) {
    msr_shadow_state::ensure_init();
    
    volatile auto& state = msr_shadow_state::g_state;
    
    for (std::uint32_t i = 0; i < state.count; ++i) {
        if (state.entries[i].msr_index == msr_index) {
            // Shift remaining entries down - manual copy for volatile
            for (std::uint32_t j = i; j < state.count - 1; ++j) {
                state.entries[j].msr_index = state.entries[j + 1].msr_index;
                state.entries[j].shadow_value = state.entries[j + 1].shadow_value;
                state.entries[j].is_active = state.entries[j + 1].is_active;
                state.entries[j].shadow_on_read = state.entries[j + 1].shadow_on_read;
                state.entries[j].shadow_on_write = state.entries[j + 1].shadow_on_write;
            }
            state.count = state.count - 1;
            return 1;
        }
    }
    return 0;
}

const msr_shadow::entry_t* msr_shadow::get_shadow(std::uint32_t msr_index) {
    msr_shadow_state::ensure_init();
    
    volatile auto& state = msr_shadow_state::g_state;
    
    for (std::uint32_t i = 0; i < state.count; ++i) {
        if (state.entries[i].msr_index == msr_index &&
            state.entries[i].is_active) {
            return const_cast<const entry_t*>(&state.entries[i]);
        }
    }
    return nullptr;
}

std::uint8_t msr_shadow::handle_rdmsr(std::uint32_t msr_index,
                                      std::uint64_t* value_out) {
    msr_shadow_state::ensure_init();
    
    const entry_t* entry = get_shadow(msr_index);

    if (entry == nullptr) {
        return 0; // No shadow for this MSR
    }

    if (entry->shadow_on_read == 0) {
        return 0; // Shadow exists but read interception disabled
    }

    *value_out = entry->shadow_value;
    msr_shadow_state::g_state.intercept_count++;
    return 1;
}

std::uint8_t msr_shadow::handle_wrmsr(std::uint32_t msr_index,
                                      std::uint64_t value) {
    msr_shadow_state::ensure_init();
    
    const entry_t* entry = get_shadow(msr_index);

    if (entry == nullptr) {
        return 0; // No shadow for this MSR
    }

    if (entry->shadow_on_write == 0) {
        return 0; // Shadow exists but write interception disabled
    }

    // Block the write
    msr_shadow_state::g_state.intercept_count++;
    return 1;
}

std::uint32_t msr_shadow::get_shadow_count() {
    msr_shadow_state::ensure_init();
    return msr_shadow_state::g_state.count;
}

const msr_shadow::entry_t* msr_shadow::get_entry(std::uint32_t index) {
    msr_shadow_state::ensure_init();
    
    if (index >= msr_shadow_state::g_state.count) {
        return nullptr;
    }
    return const_cast<const entry_t*>(&msr_shadow_state::g_state.entries[index]);
}

std::uint64_t msr_shadow::get_intercept_count() {
    msr_shadow_state::ensure_init();
    return msr_shadow_state::g_state.intercept_count;
}

void msr_shadow::increment_intercept_count() {
    msr_shadow_state::ensure_init();
    msr_shadow_state::g_state.intercept_count++;
}

std::uint64_t msr_shadow::read_msr_for_guest(std::uint32_t msr_index) {
    msr_shadow_state::ensure_init();
    
    // Check if we have a shadow for this MSR
    const entry_t* entry = get_shadow(msr_index);
    if (entry != nullptr && entry->shadow_on_read) {
        return entry->shadow_value;
    }

    // No shadow available
    return 0x8000000000000000ULL;
}
