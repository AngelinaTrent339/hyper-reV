#pragma once
#include <cstdint>
#include <format>
#include <print>
#include <string>
#include <vector>


namespace console {
// ANSI color codes for terminal output
namespace color {
constexpr const char *reset = "\033[0m";
constexpr const char *red = "\033[31m";
constexpr const char *green = "\033[32m";
constexpr const char *yellow = "\033[33m";
constexpr const char *blue = "\033[34m";
constexpr const char *magenta = "\033[35m";
constexpr const char *cyan = "\033[36m";
constexpr const char *gray = "\033[90m";
constexpr const char *white = "\033[97m";
constexpr const char *bold = "\033[1m";
constexpr const char *dim = "\033[2m";
} // namespace color

// Print success message
inline void success(const std::string &msg) {
  std::println("{}[+]{} {}", color::green, color::reset, msg);
}

// Print error message with reason
inline void error(const std::string &msg, const std::string &reason = "") {
  if (reason.empty())
    std::println("{}[-]{} {}", color::red, color::reset, msg);
  else
    std::println("{}[-]{} {}: {}{}{}", color::red, color::reset, msg,
                 color::dim, reason, color::reset);
}

// Print info message
inline void info(const std::string &msg) {
  std::println("{}[*]{} {}", color::cyan, color::reset, msg);
}

// Print warning message
inline void warn(const std::string &msg) {
  std::println("{}[!]{} {}", color::yellow, color::reset, msg);
}

// Print a hex dump of memory (classic reversing format)
inline void hexdump(const void *data, std::uint64_t size,
                    std::uint64_t base_address = 0) {
  const std::uint8_t *bytes = static_cast<const std::uint8_t *>(data);
  constexpr std::uint64_t bytes_per_line = 16;

  for (std::uint64_t offset = 0; offset < size; offset += bytes_per_line) {
    // Address column
    std::print("{}{:016X}{} | ", color::cyan, base_address + offset,
               color::reset);

    // Hex bytes
    for (std::uint64_t i = 0; i < bytes_per_line; i++) {
      if (offset + i < size) {
        std::uint8_t byte = bytes[offset + i];
        if (byte == 0x00)
          std::print("{}{:02X}{} ", color::dim, byte, color::reset);
        else if (byte == 0xCC || byte == 0x90)
          std::print("{}{:02X}{} ", color::yellow, byte, color::reset);
        else
          std::print("{:02X} ", byte);
      } else {
        std::print("   ");
      }
      if (i == 7)
        std::print(" ");
    }

    std::print("| ");

    // ASCII representation
    for (std::uint64_t i = 0; i < bytes_per_line && (offset + i) < size; i++) {
      std::uint8_t byte = bytes[offset + i];
      if (byte >= 0x20 && byte < 0x7F)
        std::print("{}", static_cast<char>(byte));
      else
        std::print(".");
    }

    std::println("");
  }
}

// Print a formatted pointer/value
inline void print_value(const std::string &name, std::uint64_t value) {
  std::println("  {}{:<20}{} = {}0x{:X}{}", color::gray, name, color::reset,
               color::green, value, color::reset);
}

// Print a separator line
inline void separator(const std::string &title = "") {
  if (title.empty())
    std::println("{}----------------------------------------{}", color::dim,
                 color::reset);
  else
    std::println("{}---- {} ----------------------------{}", color::dim, title,
                 color::reset);
}

// Format size nicely (bytes, KB, MB)
inline std::string format_size(std::uint64_t bytes) {
  if (bytes < 1024)
    return std::to_string(bytes) + " B";
  else if (bytes < 1024 * 1024)
    return std::to_string(bytes / 1024) + " KB";
  else
    return std::to_string(bytes / (1024 * 1024)) + " MB";
}
} // namespace console
