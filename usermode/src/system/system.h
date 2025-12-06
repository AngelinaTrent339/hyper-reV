#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>


namespace sys {

struct kernel_module_t {
  std::unordered_map<std::string, std::uint64_t> exports;
  std::uint64_t base_address;
  std::uint32_t size;
};

struct process_info_t {
  std::uint64_t id;
  std::uint64_t cr3;
  std::uint64_t peb;
  std::string name;
};

void clean_up();

namespace kernel {
std::uint8_t parse_modules();
std::uint8_t dump_module_to_disk(std::string_view target_module_name,
                                 const std::string_view output_directory);
inline std::unordered_map<std::string, kernel_module_t> modules_list = {};
} // namespace kernel

namespace user {
std::uint32_t query_system_information(std::int32_t information_class,
                                       void *information_out,
                                       std::uint32_t information_size,
                                       std::uint32_t *returned_size);
std::uint32_t adjust_privilege(std::uint32_t privilege, std::uint8_t enable,
                               std::uint8_t current_thread_only,
                               std::uint8_t *previous_enabled_state);
std::uint8_t set_debug_privilege(std::uint8_t state,
                                 std::uint8_t *previous_state);
void *allocate_locked_memory(std::uint64_t size, std::uint32_t protection);
std::uint8_t free_memory(void *address);
std::string to_string(const std::wstring &wstring);
} // namespace user

namespace fs {
std::uint8_t exists(std::string_view path);
std::uint8_t write_to_disk(std::string_view full_path,
                           const std::vector<std::uint8_t> &buffer);
} // namespace fs

std::optional<process_info_t> get_process_by_name(std::string_view name);
std::uint64_t get_module_base(std::uint64_t cr3, std::uint64_t peb,
                              std::string_view module_name);
std::uint64_t get_module_export(std::uint64_t cr3, std::uint64_t module_base,
                                std::string_view export_name);
std::uint64_t find_code_padding(std::uint64_t cr3, std::uint64_t module_base,
                                std::uint64_t size);

inline std::uint64_t current_cr3 = 0;
} // namespace sys
