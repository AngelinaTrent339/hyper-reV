#pragma once
#include "console.h"
#include <cstdint>
#include <format>
#include <print>
#include <string>
#include <vector>


// Simple x64 disassembly display (basic instruction identification)
// Note: Project already links Zydis.lib - this is a fallback for quick viewing
namespace disasm {
// Basic instruction pattern recognition for common x64 instructions
inline std::string identify_instruction(const std::uint8_t *bytes,
                                        std::uint64_t size,
                                        std::uint64_t &consumed) {
  if (size == 0) {
    consumed = 0;
    return "";
  }

  consumed = 1;

  switch (bytes[0]) {
  case 0x90:
    return "nop";
  case 0xCC:
    return "int3";
  case 0xC3:
    return "ret";
  case 0xCB:
    return "retf";
  case 0xC9:
    return "leave";
  case 0x9C:
    return "pushfq";
  case 0x9D:
    return "popfq";
  case 0xF4:
    return "hlt";
  case 0xFC:
    return "cld";
  case 0xFD:
    return "std";
  case 0xF8:
    return "clc";
  case 0xF9:
    return "stc";

  case 0x50:
    return "push rax";
  case 0x51:
    return "push rcx";
  case 0x52:
    return "push rdx";
  case 0x53:
    return "push rbx";
  case 0x54:
    return "push rsp";
  case 0x55:
    return "push rbp";
  case 0x56:
    return "push rsi";
  case 0x57:
    return "push rdi";
  case 0x58:
    return "pop rax";
  case 0x59:
    return "pop rcx";
  case 0x5A:
    return "pop rdx";
  case 0x5B:
    return "pop rbx";
  case 0x5C:
    return "pop rsp";
  case 0x5D:
    return "pop rbp";
  case 0x5E:
    return "pop rsi";
  case 0x5F:
    return "pop rdi";
  }

  // REX.B + push/pop r8-r15
  if (bytes[0] == 0x41 && size >= 2) {
    consumed = 2;
    switch (bytes[1]) {
    case 0x50:
      return "push r8";
    case 0x51:
      return "push r9";
    case 0x52:
      return "push r10";
    case 0x53:
      return "push r11";
    case 0x54:
      return "push r12";
    case 0x55:
      return "push r13";
    case 0x56:
      return "push r14";
    case 0x57:
      return "push r15";
    case 0x58:
      return "pop r8";
    case 0x59:
      return "pop r9";
    case 0x5A:
      return "pop r10";
    case 0x5B:
      return "pop r11";
    case 0x5C:
      return "pop r12";
    case 0x5D:
      return "pop r13";
    case 0x5E:
      return "pop r14";
    case 0x5F:
      return "pop r15";
    }
    consumed = 1;
  }

  // 0F prefix
  if (bytes[0] == 0x0F && size >= 2) {
    consumed = 2;
    switch (bytes[1]) {
    case 0x05:
      return "syscall";
    case 0x07:
      return "sysret";
    case 0x0B:
      return "ud2";
    case 0x30:
      return "wrmsr";
    case 0x31:
      return "rdtsc";
    case 0x32:
      return "rdmsr";
    case 0x33:
      return "rdpmc";
    case 0x34:
      return "sysenter";
    case 0x35:
      return "sysexit";
    case 0xA2:
      return "cpuid";
    case 0x01:
      if (size >= 3) {
        consumed = 3;
        switch (bytes[2]) {
        case 0xC1:
          return "vmcall";
        case 0xC2:
          return "vmlaunch";
        case 0xC3:
          return "vmresume";
        case 0xC4:
          return "vmxoff";
        case 0xD8:
          return "vmrun";
        case 0xD9:
          return "vmmcall";
        case 0xDA:
          return "vmload";
        case 0xDB:
          return "vmsave";
        }
        consumed = 2;
      }
      break;
    }
  }

  // Call rel32
  if (bytes[0] == 0xE8 && size >= 5) {
    consumed = 5;
    std::int32_t rel = *reinterpret_cast<const std::int32_t *>(&bytes[1]);
    return std::format("call $+{:X}h", rel + 5);
  }

  // Jmp rel32
  if (bytes[0] == 0xE9 && size >= 5) {
    consumed = 5;
    std::int32_t rel = *reinterpret_cast<const std::int32_t *>(&bytes[1]);
    return std::format("jmp $+{:X}h", rel + 5);
  }

  // Short jmp
  if (bytes[0] == 0xEB && size >= 2) {
    consumed = 2;
    std::int8_t rel = static_cast<std::int8_t>(bytes[1]);
    return std::format("jmp short $+{:X}h", rel + 2);
  }

  // Mov imm32 to eax-edi (B8-BF)
  if (bytes[0] >= 0xB8 && bytes[0] <= 0xBF && size >= 5) {
    consumed = 5;
    const char *regs[] = {"eax", "ecx", "edx", "ebx",
                          "esp", "ebp", "esi", "edi"};
    std::uint32_t imm = *reinterpret_cast<const std::uint32_t *>(&bytes[1]);
    return std::format("mov {}, {:X}h", regs[bytes[0] - 0xB8], imm);
  }

  // REX.W mov imm64
  if (bytes[0] == 0x48 && size >= 2 && bytes[1] >= 0xB8 && bytes[1] <= 0xBF &&
      size >= 10) {
    consumed = 10;
    const char *regs[] = {"rax", "rcx", "rdx", "rbx",
                          "rsp", "rbp", "rsi", "rdi"};
    std::uint64_t imm = *reinterpret_cast<const std::uint64_t *>(&bytes[2]);
    return std::format("mov {}, {:X}h", regs[bytes[1] - 0xB8], imm);
  }

  return std::format("db {:02X}h", bytes[0]);
}

// Disassemble and print code
inline void print_disasm(const void *data, std::uint64_t size,
                         std::uint64_t base_address) {
  const std::uint8_t *bytes = static_cast<const std::uint8_t *>(data);
  std::uint64_t offset = 0;

  while (offset < size) {
    std::uint64_t consumed = 0;
    std::string mnemonic =
        identify_instruction(bytes + offset, size - offset, consumed);

    std::print("{}{:016X}{}  ", console::color::cyan, base_address + offset,
               console::color::reset);

    for (std::uint64_t i = 0; i < consumed && i < 10; i++) {
      std::uint8_t b = bytes[offset + i];
      if (b == 0xCC)
        std::print("{}{:02X}{} ", console::color::yellow, b,
                   console::color::reset);
      else
        std::print("{:02X} ", b);
    }
    for (std::uint64_t i = consumed; i < 10; i++)
      std::print("   ");

    std::println(" {}{}{}", console::color::white, mnemonic,
                 console::color::reset);

    offset += consumed;
    if (consumed == 0)
      break;
  }
}
} // namespace disasm
