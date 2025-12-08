#pragma once
#include <cstdint>

namespace msr_shadow {
// MSR shadow entry - maps an MSR index to a shadow value
struct entry_t {
  std::uint32_t msr_index;
  std::uint64_t shadow_value;
  std::uint8_t is_active;       // 1 if shadowing is enabled for this MSR
  std::uint8_t shadow_on_read;  // 1 to intercept reads
  std::uint8_t shadow_on_write; // 1 to intercept writes
};

// Common MSR indices for anti-cheat detection
constexpr std::uint32_t MSR_IA32_DEBUGCTL = 0x1D9;
constexpr std::uint32_t MSR_IA32_SYSENTER_CS = 0x174;
constexpr std::uint32_t MSR_IA32_SYSENTER_ESP = 0x175;
constexpr std::uint32_t MSR_IA32_SYSENTER_EIP = 0x176;
constexpr std::uint32_t MSR_IA32_EFER = 0xC0000080;
constexpr std::uint32_t MSR_IA32_STAR = 0xC0000081;
constexpr std::uint32_t MSR_IA32_LSTAR = 0xC0000082;
constexpr std::uint32_t MSR_IA32_CSTAR = 0xC0000083;
constexpr std::uint32_t MSR_IA32_FMASK = 0xC0000084;
constexpr std::uint32_t MSR_IA32_FS_BASE = 0xC0000100;
constexpr std::uint32_t MSR_IA32_GS_BASE = 0xC0000101;
constexpr std::uint32_t MSR_IA32_KERNEL_GS_BASE = 0xC0000102;
constexpr std::uint32_t MSR_IA32_TSC_AUX = 0xC0000103;

// Hypervisor-related MSRs (common detection vectors)
constexpr std::uint32_t MSR_HV_GUEST_OS_ID = 0x40000000;
constexpr std::uint32_t MSR_HV_HYPERCALL = 0x40000001;
constexpr std::uint32_t MSR_HV_VP_INDEX = 0x40000002;
constexpr std::uint32_t MSR_HV_RESET = 0x40000003;

// Maximum number of MSR shadow entries
constexpr std::uint32_t MAX_SHADOW_ENTRIES = 32;

// Initialize the MSR shadow system
void init();

// Add or update a shadow for an MSR
// Returns 1 on success, 0 on failure
std::uint8_t add_shadow(std::uint32_t msr_index, std::uint64_t shadow_value,
                        std::uint8_t shadow_reads = 1,
                        std::uint8_t shadow_writes = 0);

// Remove a shadow for an MSR
std::uint8_t remove_shadow(std::uint32_t msr_index);

// Get the shadow value for an MSR
// Returns nullptr if no shadow exists
const entry_t *get_shadow(std::uint32_t msr_index);

// Check if we should intercept this MSR read and return shadow value
// Returns 1 if handled (shadow applied), 0 to let the read proceed normally
std::uint8_t handle_rdmsr(std::uint32_t msr_index, std::uint64_t *value_out);

// Check if we should intercept this MSR write
// Returns 1 if handled (write blocked/modified), 0 to let the write proceed
std::uint8_t handle_wrmsr(std::uint32_t msr_index, std::uint64_t value);

// Get list of all active shadows (for status display)
std::uint32_t get_shadow_count();
const entry_t *get_entry(std::uint32_t index);

// Debug: Get count of intercepted MSR operations
std::uint64_t get_intercept_count();
void increment_intercept_count();

// Debug: Read an MSR value - returns shadow if exists, otherwise actual value
// Returns the value that would be seen by the guest
std::uint64_t read_msr_for_guest(std::uint32_t msr_index);
} // namespace msr_shadow
