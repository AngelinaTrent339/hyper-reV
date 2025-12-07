#pragma once
#include <cstdint>
#include <structures/process_info.h>

namespace memory_analysis {
// ========================================================================
// MEMORY ANALYSIS MODULE
//
// Provides advanced memory introspection capabilities:
// - VAD tree enumeration (Virtual Address Descriptors)
// - Pattern/signature scanning (AOB - Array of Bytes)
// - Module dumping (bypasses AC read protection)
// ========================================================================

// Maximum results
constexpr std::uint64_t max_vad_entries = 512;
constexpr std::uint64_t max_pattern_results = 256;

// ========================================================================
// VAD ENUMERATION
// Walk the process VAD tree to enumerate all memory regions
// ========================================================================

// Enumerate VAD entries for a process
// Returns number of entries filled
std::uint64_t enumerate_vad(std::uint64_t target_cr3, std::uint64_t vad_root,
                            vad_info_t *buffer, std::uint64_t max_count);

// ========================================================================
// PATTERN SCANNING
// Search for byte patterns in guest memory (AOB scan)
// ========================================================================

// Pattern scan result
struct pattern_result_t {
  std::uint64_t address;
  std::uint64_t offset_from_start;
};

// Scan a memory range for a pattern
// pattern = byte array to search for
// mask = wildcard mask ('?' = any byte)
// Returns number of matches found
std::uint64_t
scan_pattern(std::uint64_t target_cr3, std::uint64_t start_address,
             std::uint64_t size, const std::uint8_t *pattern,
             const std::uint8_t *mask, std::uint64_t pattern_length,
             pattern_result_t *results, std::uint64_t max_results);

// Simplified scan using string pattern like "48 8B ? ? 90"
// '?' means wildcard
std::uint64_t
scan_pattern_string(std::uint64_t target_cr3, std::uint64_t start_address,
                    std::uint64_t size, const char *pattern_string,
                    pattern_result_t *results, std::uint64_t max_results);

// ========================================================================
// MODULE DUMPING
// Dump module from memory (bypasses AC protection since we read directly)
// ========================================================================

// Dump module to buffer
// Returns bytes copied
std::uint64_t dump_module(std::uint64_t target_cr3, std::uint64_t module_base,
                          std::uint64_t module_size, void *buffer,
                          std::uint64_t buffer_size);

// Get module headers (DOS + NT headers)
// Returns true if valid PE
bool get_pe_headers(std::uint64_t target_cr3, std::uint64_t module_base,
                    void *header_buffer, std::uint64_t buffer_size);

// ========================================================================
// MEMORY READING HELPERS
// Read guest memory bypassing any guest-side protection
// ========================================================================

// Read guest virtual memory (works even if guest has no-read pages)
std::uint64_t read_memory(std::uint64_t target_cr3,
                          std::uint64_t virtual_address, void *buffer,
                          std::uint64_t size);

// Compare memory at address with pattern
bool compare_pattern(std::uint64_t target_cr3, std::uint64_t virtual_address,
                     const std::uint8_t *pattern, const std::uint8_t *mask,
                     std::uint64_t pattern_length);
} // namespace memory_analysis
