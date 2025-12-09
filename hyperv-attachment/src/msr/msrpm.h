#pragma once
#include <cstdint>
#include "../arch/arch.h"

namespace msrpm {

// MSRPM is 8KB (0x2000 bytes) / 2 pages
// It controls intercepts for MSRs:
// - Page 0, 1: MSRs 0x00000000 - 0x00001FFF
// - Page 2, 3: MSRs 0xC0000000 - 0xC0001FFF  
// - Page 4, 5: MSRs 0xC0010000 - 0xC0011FFF
// Each MSR has 2 bits: bit 0 = intercept RDMSR, bit 1 = intercept WRMSR

constexpr std::uint32_t MSRPM_SIZE = 0x2000; // 8KB

// MSR ranges
constexpr std::uint32_t MSR_RANGE_LOW_START  = 0x00000000;
constexpr std::uint32_t MSR_RANGE_LOW_END    = 0x00001FFF;
constexpr std::uint32_t MSR_RANGE_HIGH_START = 0xC0000000;
constexpr std::uint32_t MSR_RANGE_HIGH_END   = 0xC0001FFF;
constexpr std::uint32_t MSR_RANGE_EXT_START  = 0xC0010000;
constexpr std::uint32_t MSR_RANGE_EXT_END    = 0xC0011FFF;

// Offsets in MSRPM for each range (in bytes)
constexpr std::uint32_t MSRPM_OFFSET_LOW  = 0x0000;  // MSRs 0x00000000-0x00001FFF
constexpr std::uint32_t MSRPM_OFFSET_HIGH = 0x0800;  // MSRs 0xC0000000-0xC0001FFF
constexpr std::uint32_t MSRPM_OFFSET_EXT  = 0x1000;  // MSRs 0xC0010000-0xC0011FFF

// Intercept flags
constexpr std::uint8_t INTERCEPT_RDMSR = 0x01;
constexpr std::uint8_t INTERCEPT_WRMSR = 0x02;
constexpr std::uint8_t INTERCEPT_BOTH  = 0x03;

// Get the MSRPM physical address from current VMCB
std::uint64_t get_msrpm_base();

// Get pointer to MSRPM (virtual address) - requires PA to VA mapping
// Returns nullptr if cannot be mapped
std::uint8_t* get_msrpm_va();

// Calculate bit position in MSRPM for a given MSR
// Returns true if MSR is in a valid range, false otherwise
// offset_out: byte offset in MSRPM
// bit_out: bit position within that byte (0-7)
std::uint8_t get_msr_position(std::uint32_t msr_index, 
                               std::uint32_t* offset_out, 
                               std::uint8_t* bit_out);

// Enable/disable MSR interception
// Returns 1 on success, 0 on failure
std::uint8_t set_msr_intercept(std::uint32_t msr_index, 
                                std::uint8_t intercept_read,
                                std::uint8_t intercept_write);

// Check current intercept status for an MSR
// Returns the intercept flags (INTERCEPT_RDMSR | INTERCEPT_WRMSR)
std::uint8_t get_msr_intercept(std::uint32_t msr_index);

// Enable interception for common MSRs needed for anti-detection
void enable_common_intercepts();

// Debug: dump MSRPM info
void dump_info();

} // namespace msrpm
