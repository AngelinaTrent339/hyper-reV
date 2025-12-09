#include "msrpm.h"
#include "../crt/crt.h"
#include "../arch/amd_def.h"
#include "../memory_manager/memory_manager.h"

// We need PA to VA mapping. Using the memory_manager module.

namespace msrpm {

// Cached MSRPM virtual address (set on first access)
static std::uint8_t* cached_msrpm_va = nullptr;
static std::uint64_t cached_msrpm_pa = 0;

std::uint64_t get_msrpm_base() {
#ifndef _INTELMACHINE
    vmcb_t* vmcb = arch::get_vmcb();
    if (vmcb == nullptr) {
        return 0;
    }
    return vmcb->control.msrpm_basePA;
#else
    return 0; // Intel uses different mechanism
#endif
}

std::uint8_t* get_msrpm_va() {
#ifndef _INTELMACHINE
    std::uint64_t pa = get_msrpm_base();
    if (pa == 0) {
        return nullptr;
    }
    
    // If we already cached it and PA hasn't changed, return cached
    if (cached_msrpm_va != nullptr && cached_msrpm_pa == pa) {
        return cached_msrpm_va;
    }
    
    // Use proper PA to VA mapping through memory_manager
    // This maps the host physical address to a usable virtual address
    void* va = memory_manager::map_host_physical(pa);
    if (va == nullptr) {
        return nullptr;
    }
    
    cached_msrpm_pa = pa;
    cached_msrpm_va = reinterpret_cast<std::uint8_t*>(va);
    
    return cached_msrpm_va;
#else
    return nullptr;
#endif
}


std::uint8_t get_msr_position(std::uint32_t msr_index, 
                               std::uint32_t* offset_out, 
                               std::uint8_t* bit_out) {
    std::uint32_t base_offset = 0;
    std::uint32_t msr_offset = 0;
    
    // Determine which range this MSR belongs to
    if (msr_index >= MSR_RANGE_LOW_START && msr_index <= MSR_RANGE_LOW_END) {
        base_offset = MSRPM_OFFSET_LOW;
        msr_offset = msr_index - MSR_RANGE_LOW_START;
    }
    else if (msr_index >= MSR_RANGE_HIGH_START && msr_index <= MSR_RANGE_HIGH_END) {
        base_offset = MSRPM_OFFSET_HIGH;
        msr_offset = msr_index - MSR_RANGE_HIGH_START;
    }
    else if (msr_index >= MSR_RANGE_EXT_START && msr_index <= MSR_RANGE_EXT_END) {
        base_offset = MSRPM_OFFSET_EXT;
        msr_offset = msr_index - MSR_RANGE_EXT_START;
    }
    else {
        // MSR not in controllable range
        return 0;
    }
    
    // Each MSR takes 2 bits in the MSRPM
    // bit 0 = RDMSR intercept, bit 1 = WRMSR intercept
    // So 4 MSRs per byte
    
    // Byte offset = base_offset + (msr_offset / 4)
    // Bit offset = (msr_offset % 4) * 2
    
    *offset_out = base_offset + (msr_offset / 4);
    *bit_out = (msr_offset % 4) * 2;
    
    return 1;
}

std::uint8_t set_msr_intercept(std::uint32_t msr_index, 
                                std::uint8_t intercept_read,
                                std::uint8_t intercept_write) {
    std::uint8_t* msrpm = get_msrpm_va();
    if (msrpm == nullptr) {
        return 0;
    }
    
    std::uint32_t offset = 0;
    std::uint8_t bit = 0;
    
    if (get_msr_position(msr_index, &offset, &bit) == 0) {
        return 0; // Invalid MSR range
    }
    
    // Ensure offset is within MSRPM bounds
    if (offset >= MSRPM_SIZE) {
        return 0;
    }
    
    // Read current byte
    std::uint8_t current = msrpm[offset];
    
    // Clear both bits for this MSR
    current &= ~(0x03 << bit);
    
    // Set the intercept bits
    if (intercept_read) {
        current |= (INTERCEPT_RDMSR << bit);
    }
    if (intercept_write) {
        current |= (INTERCEPT_WRMSR << bit);
    }
    
    // Write back
    msrpm[offset] = current;
    
    return 1;
}

std::uint8_t get_msr_intercept(std::uint32_t msr_index) {
    std::uint8_t* msrpm = get_msrpm_va();
    if (msrpm == nullptr) {
        return 0;
    }
    
    std::uint32_t offset = 0;
    std::uint8_t bit = 0;
    
    if (get_msr_position(msr_index, &offset, &bit) == 0) {
        return 0; // Invalid MSR range
    }
    
    if (offset >= MSRPM_SIZE) {
        return 0;
    }
    
    // Read current byte and extract the 2 bits for this MSR
    std::uint8_t current = msrpm[offset];
    return (current >> bit) & 0x03;
}

void enable_common_intercepts() {
    // Enable interception for common MSRs used in anti-detection
    
    // IA32_DEBUGCTL (0x1D9) - debugger detection
    set_msr_intercept(0x1D9, 1, 1);
    
    // IA32_LSTAR (0xC0000082) - syscall handler
    set_msr_intercept(0xC0000082, 1, 1);
    
    // IA32_KERNEL_GS_BASE (0xC0000102)
    set_msr_intercept(0xC0000102, 1, 0);
    
    // Hyper-V MSRs (0x40000000 - 0x400000FF range)
    // Note: These may not be in the standard MSRPM ranges
    // Hyper-V handles these differently
}

void dump_info() {
    // This would log debug info - requires logging infrastructure
}

} // namespace msrpm
