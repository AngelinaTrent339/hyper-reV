#pragma once
#include "ia32-doc/ia32.hpp"
#include <structures/trap_frame.h>


namespace logs {
void set_up();

void add_log(const trap_frame_log_t &trap_frame);
std::uint8_t flush(cr3 slat_cr3, std::uint64_t guest_virtual_buffer,
                   cr3 guest_cr3, std::uint16_t count);

// CR3 filter for process-specific monitoring
void set_filter_cr3(std::uint64_t cr3);
void clear_filter_cr3();
std::uint64_t get_filter_cr3();

inline trap_frame_log_t *stored_logs = nullptr;
inline std::uint16_t stored_log_index = 0;
inline std::uint16_t stored_log_max = 0;
inline std::uint64_t filter_cr3 = 0; // 0 = no filter, log all
} // namespace logs
