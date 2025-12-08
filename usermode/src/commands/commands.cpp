#include "commands.h"
#include "../hook/hook.h"
#include "../hypercall/hypercall.h"
#include "../system/system.h"
#include "../util/console.h"
#include "../util/disasm.h"
#include <CLI/CLI.hpp>
#include <hypercall/hypercall_def.h>

#include <array>
#include <cctype>
#include <chrono>
#include <format>
#include <print>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

// Extended SYSTEM_PROCESS_INFORMATION (winternl.h has incomplete definition)
typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize;
  ULONG HardFaultCount;
  ULONG NumberOfThreadsHighWatermark;
  ULONGLONG CycleTime;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  LONG BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR UniqueProcessKey;
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
} MY_SYSTEM_PROCESS_INFORMATION;

#define d_invoke_command_processor(command) process_##command(##command)
#define d_initial_process_command(command)                                     \
  if (*##command)                                                              \
  d_invoke_command_processor(command)
#define d_process_command(command)                                             \
  else if (*##command) d_invoke_command_processor(command)

template <class t>
t get_command_option(CLI::App *app, std::string option_name) {
  auto option = app->get_option(option_name);

  return option->empty() == false ? option->as<t>() : t{};
}

CLI::Option *add_command_option(CLI::App *app, std::string option_name) {
  return app->add_option(option_name);
}

CLI::Option *add_transformed_command_option(CLI::App *app,
                                            std::string option_name,
                                            CLI::Transformer &transformer) {
  CLI::Option *option = add_command_option(app, option_name);

  return option->transform(transformer);
}

std::uint8_t get_command_flag(CLI::App *app, std::string flag_name) {
  auto option = app->get_option(flag_name);

  return !option->empty();
}

CLI::Option *add_command_flag(CLI::App *app, std::string flag_name) {
  return app->add_flag(flag_name);
}

// ============================================================================
// STATUS / INFO COMMANDS
// ============================================================================

CLI::App *init_status(CLI::App &app) {
  CLI::App *status =
      app.add_subcommand("status", "show current hypervisor and session status")
          ->ignore_case()
          ->alias("info");
  return status;
}

void process_status(CLI::App *status) {
  console::separator("Session Status");

  console::print_value("CR3", sys::current_cr3);
  console::print_value("Modules Loaded", sys::kernel::modules_list.size());
  console::print_value("Detour Base", hook::kernel_detour_holder_base);

  std::uint64_t heap_pages = hypercall::get_heap_free_page_count();
  console::print_value("Heap Free Pages", heap_pages);
  console::print_value("Heap Free Memory", heap_pages * 0x1000);

  console::separator();
}

CLI::App *init_help_cmd(CLI::App &app) {
  CLI::App *help_cmd =
      app.add_subcommand("?", "quick command reference")->ignore_case();
  return help_cmd;
}

void process_help_cmd(CLI::App *help_cmd) {
  std::println("\n{}Memory Commands:{}", console::color::bold,
               console::color::reset);
  std::println(
      "  {}read{}    / {}rgpm{}   <addr> <size>      - read physical memory",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}write{}   / {}wgpm{}   <addr> <val> <sz>  - write physical memory",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}vread{}   / {}rgvm{}   <addr> <cr3> <sz>  - read virtual memory",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}vwrite{}  / {}wgvm{}   <addr> <cr3> <v> <sz> - write virtual memory",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}dump{}    / {}db{}     <addr> <size> [--cr3]  - hex dump memory",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}disasm{} / {}u{}      <addr> <size> [--cr3]  - disassemble code",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}translate{} / {}gvat{} <vaddr> <cr3>    - VA to PA translation",
      console::color::green, console::color::reset, console::color::dim,
      console::color::reset);

  std::println("\n{}Hooking Commands:{}", console::color::bold,
               console::color::reset);
  std::println("  {}hook{}    / {}akh{}    <addr> --asmbytes 0xCC 0x90  - add "
               "kernel hook",
               console::color::yellow, console::color::reset,
               console::color::dim, console::color::reset);
  std::println(
      "  {}unhook{} / {}rkh{}    <addr>             - remove kernel hook",
      console::color::yellow, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}hide{}   / {}hgpp{}   <phys_addr>        - hide physical page",
      console::color::yellow, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}logs{}    / {}fl{}                       - flush trap frame logs",
      console::color::yellow, console::color::reset, console::color::dim,
      console::color::reset);

  std::println("\n{}Analysis Commands:{}", console::color::bold,
               console::color::reset);
  std::println(
      "  {}modules{} / {}lkm{}                      - list kernel modules",
      console::color::cyan, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}exports{} / {}kme{}   <module>           - list module exports",
      console::color::cyan, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}dumpmod{} / {}dkm{}   <mod> <outdir>     - dump module to disk",
      console::color::cyan, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}resolve{} / {}gva{}   <alias>            - resolve alias to address",
      console::color::cyan, console::color::reset, console::color::dim,
      console::color::reset);

  std::println("\n{}Session Commands:{}", console::color::bold,
               console::color::reset);
  std::println(
      "  {}status{} / {}info{}                      - show session info",
      console::color::magenta, console::color::reset, console::color::dim,
      console::color::reset);
  std::println(
      "  {}heap{}    / {}hfpc{}                      - heap free page count",
      console::color::magenta, console::color::reset, console::color::dim,
      console::color::reset);
  std::println("  {}?{}                                    - this help",
               console::color::magenta, console::color::reset);
  std::println("  {}exit{}                                 - exit session\n",
               console::color::magenta, console::color::reset);

  std::println("{}Syscall Hooking:{}", console::color::bold,
               console::color::reset);
  std::println(
      "  {}syscall hook <name> --monitor{}     - hook specific syscall",
      console::color::red, console::color::reset);
  std::println("  {}syscall list / active / logs{}      - list/view syscalls\n",
               console::color::red, console::color::reset);

  std::println("{}Tip:{} Use module names/exports as aliases: e.g., "
               "'ntoskrnl.exe!KeQueryPerformanceCounter'",
               console::color::dim, console::color::reset);
  std::println("{}Tip:{} 'current_cr3' is always the current process CR3\n",
               console::color::dim, console::color::reset);
}

// ============================================================================
// MEMORY READ/WRITE COMMANDS
// ============================================================================

CLI::App *init_rgpm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *rgpm = app.add_subcommand("rgpm", "read guest physical memory")
                       ->ignore_case()
                       ->alias("read");

  add_transformed_command_option(rgpm, "physical_address", aliases_transformer)
      ->required();
  add_command_option(rgpm, "size")->check(CLI::Range(1, 8))->required();

  return rgpm;
}

void process_rgpm(CLI::App *rgpm) {
  const std::uint64_t guest_physical_address =
      get_command_option<std::uint64_t>(rgpm, "physical_address");
  const std::uint64_t size = get_command_option<std::uint64_t>(rgpm, "size");

  std::uint64_t value = 0;

  const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(
      &value, guest_physical_address, size);

  if (bytes_read == size) {
    console::print_value(std::format("@{:X}", guest_physical_address), value);
  } else {
    console::error(
        "Failed to read physical memory",
        std::format("address=0x{:X}, requested={} bytes, read={} bytes",
                    guest_physical_address, size, bytes_read));
  }
}

CLI::App *init_wgpm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *wgpm = app.add_subcommand("wgpm", "write guest physical memory")
                       ->ignore_case()
                       ->alias("write");

  add_transformed_command_option(wgpm, "physical_address", aliases_transformer)
      ->required();
  add_command_option(wgpm, "value")->required();
  add_command_option(wgpm, "size")->check(CLI::Range(1, 8))->required();

  return wgpm;
}

void process_wgpm(CLI::App *wgpm) {
  const std::uint64_t guest_physical_address =
      get_command_option<std::uint64_t>(wgpm, "physical_address");
  const std::uint64_t size = get_command_option<std::uint64_t>(wgpm, "size");
  std::uint64_t value = get_command_option<std::uint64_t>(wgpm, "value");

  const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(
      &value, guest_physical_address, size);

  if (bytes_written == size) {
    console::success(std::format("Wrote 0x{:X} ({} bytes) to 0x{:X}", value,
                                 size, guest_physical_address));
  } else {
    console::error(
        "Failed to write physical memory",
        std::format("address=0x{:X}, requested={} bytes, written={} bytes",
                    guest_physical_address, size, bytes_written));
  }
}

CLI::App *init_cgpm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *cgpm = app.add_subcommand("cgpm", "copy guest physical memory")
                       ->ignore_case()
                       ->alias("copy");

  add_transformed_command_option(cgpm, "destination_physical_address",
                                 aliases_transformer)
      ->required();
  add_transformed_command_option(cgpm, "source_physical_address",
                                 aliases_transformer)
      ->required();
  add_command_option(cgpm, "size")->required();

  return cgpm;
}

void process_cgpm(CLI::App *cgpm) {
  const std::uint64_t guest_destination_physical_address =
      get_command_option<std::uint64_t>(cgpm, "destination_physical_address");
  const std::uint64_t guest_source_physical_address =
      get_command_option<std::uint64_t>(cgpm, "source_physical_address");
  const std::uint64_t size = get_command_option<std::uint64_t>(cgpm, "size");

  std::vector<std::uint8_t> buffer(size);

  const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(
      buffer.data(), guest_source_physical_address, size);

  if (bytes_read != size) {
    console::error("Failed to read source memory",
                   std::format("source=0x{:X}, read={}/{} bytes",
                               guest_source_physical_address, bytes_read,
                               size));
    return;
  }

  const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(
      buffer.data(), guest_destination_physical_address, size);

  if (bytes_written == size) {
    console::success(std::format("Copied {} bytes: 0x{:X} -> 0x{:X}", size,
                                 guest_source_physical_address,
                                 guest_destination_physical_address));
  } else {
    console::error("Failed to write destination memory",
                   std::format("dest=0x{:X}, written={}/{} bytes",
                               guest_destination_physical_address,
                               bytes_written, size));
  }
}

CLI::App *init_gvat(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *gvat =
      app.add_subcommand("gvat", "translate virtual address to physical")
          ->ignore_case()
          ->alias("translate");

  add_transformed_command_option(gvat, "virtual_address", aliases_transformer)
      ->required();
  add_transformed_command_option(gvat, "cr3", aliases_transformer)->required();

  return gvat;
}

void process_gvat(CLI::App *gvat) {
  const std::uint64_t virtual_address =
      get_command_option<std::uint64_t>(gvat, "virtual_address");
  const std::uint64_t cr3 = get_command_option<std::uint64_t>(gvat, "cr3");

  const std::uint64_t physical_address =
      hypercall::translate_guest_virtual_address(virtual_address, cr3);

  if (physical_address != 0) {
    console::print_value("Virtual", virtual_address);
    console::print_value("Physical", physical_address);
    console::print_value("Page Offset", virtual_address & 0xFFF);
  } else {
    console::error(
        "Translation failed",
        std::format("VA=0x{:X} with CR3=0x{:X} - page may not be present",
                    virtual_address, cr3));
  }
}

CLI::App *init_rgvm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *rgvm = app.add_subcommand("rgvm", "read guest virtual memory")
                       ->ignore_case()
                       ->alias("vread");

  add_transformed_command_option(rgvm, "virtual_address", aliases_transformer)
      ->required();
  add_transformed_command_option(rgvm, "cr3", aliases_transformer)->required();
  add_command_option(rgvm, "size")->check(CLI::Range(1, 8))->required();

  return rgvm;
}

void process_rgvm(CLI::App *rgvm) {
  const std::uint64_t guest_virtual_address =
      get_command_option<std::uint64_t>(rgvm, "virtual_address");
  const std::uint64_t cr3 = get_command_option<std::uint64_t>(rgvm, "cr3");
  const std::uint64_t size = get_command_option<std::uint64_t>(rgvm, "size");

  std::uint64_t value = 0;

  const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
      &value, guest_virtual_address, cr3, size);

  if (bytes_read == size) {
    console::print_value(std::format("@{:X}", guest_virtual_address), value);
  } else {
    console::error(
        "Failed to read virtual memory",
        std::format("VA=0x{:X}, CR3=0x{:X}, requested={}, read={} bytes",
                    guest_virtual_address, cr3, size, bytes_read));
  }
}

CLI::App *init_wgvm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *wgvm = app.add_subcommand("wgvm", "write guest virtual memory")
                       ->ignore_case()
                       ->alias("vwrite");

  add_transformed_command_option(wgvm, "virtual_address", aliases_transformer)
      ->required();
  add_transformed_command_option(wgvm, "cr3", aliases_transformer)->required();
  add_command_option(wgvm, "value")->required();
  add_command_option(wgvm, "size")->check(CLI::Range(1, 8))->required();

  return wgvm;
}

void process_wgvm(CLI::App *wgvm) {
  const std::uint64_t guest_virtual_address =
      get_command_option<std::uint64_t>(wgvm, "virtual_address");
  const std::uint64_t cr3 = get_command_option<std::uint64_t>(wgvm, "cr3");
  const std::uint64_t size = get_command_option<std::uint64_t>(wgvm, "size");
  std::uint64_t value = get_command_option<std::uint64_t>(wgvm, "value");

  const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
      &value, guest_virtual_address, cr3, size);

  if (bytes_written == size) {
    console::success(std::format("Wrote 0x{:X} ({} bytes) to VA 0x{:X}", value,
                                 size, guest_virtual_address));
  } else {
    console::error(
        "Failed to write virtual memory",
        std::format("VA=0x{:X}, CR3=0x{:X}, requested={}, written={} bytes",
                    guest_virtual_address, cr3, size, bytes_written));
  }
}

CLI::App *init_cgvm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *cgvm = app.add_subcommand("cgvm", "copy guest virtual memory")
                       ->ignore_case()
                       ->alias("vcopy");

  add_transformed_command_option(cgvm, "destination_virtual_address",
                                 aliases_transformer)
      ->required();
  add_transformed_command_option(cgvm, "destination_cr3", aliases_transformer)
      ->required();
  add_transformed_command_option(cgvm, "source_virtual_address",
                                 aliases_transformer)
      ->required();
  add_transformed_command_option(cgvm, "source_cr3", aliases_transformer)
      ->required();
  add_command_option(cgvm, "size")->required();

  return cgvm;
}

void process_cgvm(CLI::App *cgvm) {
  const std::uint64_t guest_destination_virtual_address =
      get_command_option<std::uint64_t>(cgvm, "destination_virtual_address");
  const std::uint64_t guest_destination_cr3 =
      get_command_option<std::uint64_t>(cgvm, "destination_cr3");
  const std::uint64_t guest_source_virtual_address =
      get_command_option<std::uint64_t>(cgvm, "source_virtual_address");
  const std::uint64_t guest_source_cr3 =
      get_command_option<std::uint64_t>(cgvm, "source_cr3");
  const std::uint64_t size = get_command_option<std::uint64_t>(cgvm, "size");

  std::vector<std::uint8_t> buffer(size);

  const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
      buffer.data(), guest_source_virtual_address, guest_source_cr3, size);

  if (bytes_read != size) {
    console::error("Failed to read source virtual memory",
                   std::format("source VA=0x{:X}, read={}/{} bytes",
                               guest_source_virtual_address, bytes_read, size));
    return;
  }

  const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
      buffer.data(), guest_destination_virtual_address, guest_destination_cr3,
      size);

  if (bytes_written == size) {
    console::success(std::format("Copied {} bytes: VA 0x{:X} -> VA 0x{:X}",
                                 size, guest_source_virtual_address,
                                 guest_destination_virtual_address));
  } else {
    console::error("Failed to write destination virtual memory",
                   std::format("dest VA=0x{:X}, written={}/{} bytes",
                               guest_destination_virtual_address, bytes_written,
                               size));
  }
}

// ============================================================================
// HEX DUMP AND DISASSEMBLY COMMANDS
// ============================================================================

CLI::App *init_dump(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *dump =
      app.add_subcommand("dump", "hex dump memory")->ignore_case()->alias("db");

  add_transformed_command_option(dump, "address", aliases_transformer)
      ->required();
  add_command_option(dump, "size")->required();
  add_transformed_command_option(
      dump, "--cr3", aliases_transformer); // optional, if provided = virtual

  return dump;
}

void process_dump(CLI::App *dump) {
  const std::uint64_t address =
      get_command_option<std::uint64_t>(dump, "address");
  const std::uint64_t size = get_command_option<std::uint64_t>(dump, "size");
  const std::uint64_t cr3 = get_command_option<std::uint64_t>(dump, "--cr3");

  if (size > 0x10000) {
    console::error("Size too large", "maximum 64KB per dump");
    return;
  }

  std::vector<std::uint8_t> buffer(size);
  std::uint64_t bytes_read = 0;

  if (cr3 != 0) {
    bytes_read =
        hypercall::read_guest_virtual_memory(buffer.data(), address, cr3, size);
    console::info(
        std::format("Virtual memory dump @ 0x{:X} (CR3=0x{:X})", address, cr3));
  } else {
    bytes_read =
        hypercall::read_guest_physical_memory(buffer.data(), address, size);
    console::info(std::format("Physical memory dump @ 0x{:X}", address));
  }

  if (bytes_read == 0) {
    console::error("Failed to read memory", "no bytes returned");
    return;
  }

  if (bytes_read < size) {
    console::warn(
        std::format("Partial read: {} of {} bytes", bytes_read, size));
  }

  std::println("");
  console::hexdump(buffer.data(), bytes_read, address);
  std::println("");
}

CLI::App *init_disasm(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *dis = app.add_subcommand("disasm", "disassemble code")
                      ->ignore_case()
                      ->alias("u");

  add_transformed_command_option(dis, "address", aliases_transformer)
      ->required();
  add_command_option(dis, "size")->required();
  add_transformed_command_option(dis, "--cr3", aliases_transformer);

  return dis;
}

void process_dis(CLI::App *dis) {
  const std::uint64_t address =
      get_command_option<std::uint64_t>(dis, "address");
  const std::uint64_t size = get_command_option<std::uint64_t>(dis, "size");
  const std::uint64_t cr3 = get_command_option<std::uint64_t>(dis, "--cr3");

  if (size > 0x1000) {
    console::error("Size too large", "maximum 4KB per disassembly");
    return;
  }

  std::vector<std::uint8_t> buffer(size);
  std::uint64_t bytes_read = 0;

  if (cr3 != 0) {
    bytes_read =
        hypercall::read_guest_virtual_memory(buffer.data(), address, cr3, size);
    console::info(
        std::format("Disassembly @ VA 0x{:X} (CR3=0x{:X})", address, cr3));
  } else {
    bytes_read =
        hypercall::read_guest_physical_memory(buffer.data(), address, size);
    console::info(std::format("Disassembly @ PA 0x{:X}", address));
  }

  if (bytes_read == 0) {
    console::error("Failed to read memory");
    return;
  }

  std::println("");
  disasm::print_disasm(buffer.data(), bytes_read, address);
  std::println("");
}

// ============================================================================
// HOOKING COMMANDS
// ============================================================================

CLI::App *init_akh(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *akh =
      app.add_subcommand("akh",
                         "add kernel hook (format: --asmbytes 0xE8 0x12 ...)")
          ->ignore_case()
          ->alias("hook");

  add_transformed_command_option(akh, "virtual_address", aliases_transformer)
      ->required();
  add_command_option(akh, "--asmbytes")
      ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)
      ->expected(-1);
  add_command_option(akh, "--post_original_asmbytes")
      ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)
      ->expected(-1);
  add_command_flag(akh, "--monitor");

  return akh;
}

void process_akh(CLI::App *akh) {
  const std::uint64_t virtual_address =
      get_command_option<std::uint64_t>(akh, "virtual_address");
  std::vector<uint8_t> asm_bytes =
      get_command_option<std::vector<uint8_t>>(akh, "--asmbytes");
  const std::vector<uint8_t> post_original_asm_bytes =
      get_command_option<std::vector<uint8_t>>(akh, "--post_original_asmbytes");
  const std::uint8_t monitor = get_command_flag(akh, "--monitor");

  if (monitor == 1) {
    std::array<std::uint8_t, 9> monitor_bytes = {
        0x51,                         // push rcx
        0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
        0x0F, 0xA2,                   // cpuid
        0x59                          // pop rcx
    };

    hypercall_info_t call_info = {};
    call_info.primary_key = hypercall_primary_key;
    call_info.secondary_key = hypercall_secondary_key;
    call_info.call_type = hypercall_type_t::log_current_state;
    *reinterpret_cast<std::uint32_t *>(&monitor_bytes[2]) =
        static_cast<std::uint32_t>(call_info.value);

    asm_bytes.insert(asm_bytes.end(), monitor_bytes.begin(),
                     monitor_bytes.end());
  }

  const std::uint8_t hook_status = hook::add_kernel_hook(
      virtual_address, asm_bytes, post_original_asm_bytes);

  if (hook_status == 1) {
    console::success(std::format(
        "Hook installed at 0x{:X} ({} bytes payload{})", virtual_address,
        asm_bytes.size(), monitor ? " + monitor" : ""));
  } else {
    console::error("Failed to install hook",
                   std::format("target=0x{:X}, payload size={} bytes",
                               virtual_address, asm_bytes.size()));
  }
}

CLI::App *init_rkh(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *rkh = app.add_subcommand("rkh", "remove kernel hook")
                      ->ignore_case()
                      ->alias("unhook");

  add_transformed_command_option(rkh, "virtual_address", aliases_transformer)
      ->required();

  return rkh;
}

void process_rkh(CLI::App *rkh) {
  const std::uint64_t virtual_address =
      get_command_option<std::uint64_t>(rkh, "virtual_address");

  const std::uint8_t hook_removal_status =
      hook::remove_kernel_hook(virtual_address, 1);

  if (hook_removal_status == 1) {
    console::success(std::format("Hook removed from 0x{:X}", virtual_address));
  } else {
    console::error("Failed to remove hook",
                   std::format("target=0x{:X}", virtual_address));
  }
}

CLI::App *init_hgpp(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *hgpp =
      app.add_subcommand("hgpp", "hide physical page from guest reads")
          ->ignore_case()
          ->alias("hide");

  add_transformed_command_option(hgpp, "physical_address", aliases_transformer)
      ->required();

  return hgpp;
}

void process_hgpp(CLI::App *hgpp) {
  const std::uint64_t physical_address =
      get_command_option<std::uint64_t>(hgpp, "physical_address");

  const std::uint64_t hide_status =
      hypercall::hide_guest_physical_page(physical_address);

  if (hide_status == 1) {
    console::success(std::format("Page hidden: PA 0x{:X} (page 0x{:X})",
                                 physical_address, physical_address >> 12));
  } else {
    console::error("Failed to hide page",
                   std::format("PA=0x{:X}", physical_address));
  }
}

CLI::App *init_fl(CLI::App &app) {
  CLI::App *fl = app.add_subcommand("fl", "flush and display trap frame logs")
                     ->ignore_case()
                     ->alias("logs");

  add_command_option(fl, "--count"); // limit number of logs to show
  add_command_flag(fl, "--compact"); // compact single-line view
  add_command_flag(fl, "--regs"); // show all registers (default in full mode)

  return fl;
}

// Helper: resolve address to module!symbol+offset format
std::string resolve_symbol(std::uint64_t address) {
  if (address == 0)
    return "(null)";

  // Check if it's a kernel address
  if ((address >> 48) != 0xFFFF) {
    return std::format("0x{:X} (user)", address);
  }

  // Find containing module
  for (const auto &[module_name, module_info] : sys::kernel::modules_list) {
    std::uint64_t module_end = module_info.base_address + module_info.size;

    if (address >= module_info.base_address && address < module_end) {
      std::uint64_t offset = address - module_info.base_address;

      // Try to find nearest export
      std::string nearest_export;
      std::uint64_t nearest_distance = UINT64_MAX;

      for (const auto &[export_name, export_addr] : module_info.exports) {
        if (export_addr <= address &&
            (address - export_addr) < nearest_distance) {
          nearest_distance = address - export_addr;
          // Extract just the function name (after the !)
          size_t bang_pos = export_name.find('!');
          if (bang_pos != std::string::npos) {
            nearest_export = export_name.substr(bang_pos + 1);
          } else {
            nearest_export = export_name;
          }
        }
      }

      if (!nearest_export.empty() && nearest_distance < 0x10000) {
        if (nearest_distance == 0) {
          return std::format("{}!{}", module_name, nearest_export);
        } else {
          return std::format("{}!{}+0x{:X}", module_name, nearest_export,
                             nearest_distance);
        }
      }

      return std::format("{}+0x{:X}", module_name, offset);
    }
  }

  return std::format("0x{:016X}", address);
}

// Helper: classify pointer type
std::string classify_pointer(std::uint64_t value) {
  if (value == 0)
    return "NULL";
  if ((value >> 48) == 0xFFFF) {
    if ((value & 0xF000'0000'0000) == 0xF000'0000'0000)
      return "KRNL";
    return "KERN";
  }
  if (value < 0x10000)
    return "SMAL";
  if (value < 0x7FFF'FFFF'FFFF)
    return "USER";
  return "????";
}

void process_fl(CLI::App *fl) {
  constexpr std::uint64_t log_count = 100;
  constexpr std::uint64_t failed_log_count = static_cast<std::uint64_t>(-1);

  const std::uint64_t max_show =
      get_command_option<std::uint64_t>(fl, "--count");
  const std::uint8_t compact_mode = get_command_flag(fl, "--compact");
  const std::uint8_t show_regs = get_command_flag(fl, "--regs");

  std::vector<trap_frame_log_t> logs(log_count);

  const std::uint64_t logs_flushed = hypercall::flush_logs(logs);

  if (logs_flushed == failed_log_count) {
    console::error("Failed to flush logs");
    return;
  }

  if (logs_flushed == 0) {
    console::info("No logs to flush");
    return;
  }

  const std::uint64_t show_count =
      (max_show > 0 && max_show < logs_flushed) ? max_show : logs_flushed;

  std::println("");
  std::println("{}"
               "╔══════════════════════════════════════════════════════════════"
               "════════════════╗{}",
               console::color::cyan, console::color::reset);
  std::println("{}║{} {}TRAP FRAME LOGS{} - {} entries captured, showing {}    "
               "                          {}║{}",
               console::color::cyan, console::color::reset,
               console::color::bold, console::color::reset, logs_flushed,
               show_count, console::color::cyan, console::color::reset);
  std::println("{}"
               "╚══════════════════════════════════════════════════════════════"
               "════════════════╝{}",
               console::color::cyan, console::color::reset);
  std::println("");

  for (std::uint64_t i = 0; i < show_count; i++) {
    const trap_frame_log_t &log = logs[i];

    if (log.rip == 0)
      break;

    std::string rip_symbol = resolve_symbol(log.rip);
    std::string caller_symbol = (log.stack_data[0] != 0)
                                    ? resolve_symbol(log.stack_data[0])
                                    : "(unknown)";

    if (compact_mode) {
      // Compact single-line format
      std::println("{}#{:3}{} {}RIP{} {:016X}  {}CR3{} {:08X}  {}Caller{} {}",
                   console::color::dim, i + 1, console::color::reset,
                   console::color::gray, console::color::reset, log.rip,
                   console::color::gray, console::color::reset,
                   log.cr3 & 0xFFFFFFFF, console::color::gray,
                   console::color::reset, caller_symbol);
    } else {
      // Full detailed format
      std::println("{}"
                   "┌──────────────────────────────────────────────────────────"
                   "────────────────────┐{}",
                   console::color::dim, console::color::reset);
      std::println("{}│{} {}LOG #{}{:<4}                                       "
                   "                              {}│{}",
                   console::color::dim, console::color::reset,
                   console::color::bold, console::color::reset, i + 1,
                   console::color::dim, console::color::reset);
      std::println("{}"
                   "├──────────────────────────────────────────────────────────"
                   "────────────────────┤{}",
                   console::color::dim, console::color::reset);

      // RIP with symbol
      std::println("{}│{}  {}RIP{} {:016X}  →  {}{}{}", console::color::dim,
                   console::color::reset, console::color::yellow,
                   console::color::reset, log.rip, console::color::green,
                   rip_symbol, console::color::reset);

      // CR3 (process context)
      std::println("{}│{}  {}CR3{} {:016X}  {}(process page table){}",
                   console::color::dim, console::color::reset,
                   console::color::magenta, console::color::reset, log.cr3,
                   console::color::dim, console::color::reset);

      // Caller (return address)
      std::println("{}│{}  {}RET{} {:016X}  →  {}{}{}", console::color::dim,
                   console::color::reset, console::color::cyan,
                   console::color::reset, log.stack_data[0],
                   console::color::green, caller_symbol, console::color::reset);

      std::println("{}│{}", console::color::dim, console::color::reset);

      // Arguments (Windows x64 ABI: RCX, RDX, R8, R9)
      std::println("{}│{}  {}═══ Arguments (x64 ABI) ═══{}",
                   console::color::dim, console::color::reset,
                   console::color::bold, console::color::reset);
      std::println("{}│{}  {}Arg1 (RCX){} {:016X}  [{}]", console::color::dim,
                   console::color::reset, console::color::yellow,
                   console::color::reset, log.rcx, classify_pointer(log.rcx));
      std::println("{}│{}  {}Arg2 (RDX){} {:016X}  [{}]", console::color::dim,
                   console::color::reset, console::color::yellow,
                   console::color::reset, log.rdx, classify_pointer(log.rdx));
      std::println("{}│{}  {}Arg3 (R8) {} {:016X}  [{}]", console::color::dim,
                   console::color::reset, console::color::yellow,
                   console::color::reset, log.r8, classify_pointer(log.r8));
      std::println("{}│{}  {}Arg4 (R9) {} {:016X}  [{}]", console::color::dim,
                   console::color::reset, console::color::yellow,
                   console::color::reset, log.r9, classify_pointer(log.r9));

      // Full registers (if --regs or default in full mode)
      std::println("{}│{}", console::color::dim, console::color::reset);
      std::println("{}│{}  {}═══ General Purpose Registers ═══{}",
                   console::color::dim, console::color::reset,
                   console::color::bold, console::color::reset);
      std::println("{}│{}  RAX {:016X}  RBX {:016X}  RCX {:016X}  RDX {:016X}",
                   console::color::dim, console::color::reset, log.rax, log.rbx,
                   log.rcx, log.rdx);
      std::println("{}│{}  RSP {:016X}  RBP {:016X}  RSI {:016X}  RDI {:016X}",
                   console::color::dim, console::color::reset, log.rsp, log.rbp,
                   log.rsi, log.rdi);
      std::println("{}│{}  R8  {:016X}  R9  {:016X}  R10 {:016X}  R11 {:016X}",
                   console::color::dim, console::color::reset, log.r8, log.r9,
                   log.r10, log.r11);
      std::println("{}│{}  R12 {:016X}  R13 {:016X}  R14 {:016X}  R15 {:016X}",
                   console::color::dim, console::color::reset, log.r12, log.r13,
                   log.r14, log.r15);

      // Stack with symbol resolution
      std::println("{}│{}", console::color::dim, console::color::reset);
      std::println("{}│{}  {}═══ Stack (top {} QWORDs) ═══{}",
                   console::color::dim, console::color::reset,
                   console::color::bold, trap_frame_log_stack_data_count,
                   console::color::reset);

      for (std::uint64_t s = 0; s < trap_frame_log_stack_data_count; s++) {
        std::uint64_t stack_val = log.stack_data[s];
        if (stack_val != 0) {
          std::string stack_sym = resolve_symbol(stack_val);
          std::string annotation = (s == 0) ? " ← return addr" : "";
          std::println("{}│{}  [RSP+{:02X}] {:016X}  {}{}{}{}",
                       console::color::dim, console::color::reset, s * 8,
                       stack_val, console::color::dim, stack_sym, annotation,
                       console::color::reset);
        }
      }

      std::println("{}"
                   "└──────────────────────────────────────────────────────────"
                   "────────────────────┘{}",
                   console::color::dim, console::color::reset);
      std::println("");
    }
  }

  if (compact_mode && show_count > 0) {
    std::println("");
  }

  std::println("{}Tip:{} Use --compact for one-line summaries, or 'logs "
               "--count 5' for fewer entries",
               console::color::dim, console::color::reset);
  std::println("");
}

// ============================================================================
// ANALYSIS COMMANDS
// ============================================================================

CLI::App *init_hfpc(CLI::App &app) {
  CLI::App *hfpc =
      app.add_subcommand("hfpc", "get hyperv-attachment heap free page count")
          ->ignore_case()
          ->alias("heap");

  return hfpc;
}

void process_hfpc(CLI::App *hfpc) {
  const std::uint64_t heap_free_page_count =
      hypercall::get_heap_free_page_count();

  console::print_value("Heap Free Pages", heap_free_page_count);
  console::print_value("Heap Free Memory", heap_free_page_count * 0x1000);
  console::info(
      std::format("~{}", console::format_size(heap_free_page_count * 0x1000)));
}

CLI::App *init_lkm(CLI::App &app) {
  CLI::App *lkm = app.add_subcommand("lkm", "list loaded kernel modules")
                      ->ignore_case()
                      ->alias("modules");

  return lkm;
}

void process_lkm(CLI::App *lkm) {
  console::info(
      std::format("Loaded Modules: {}", sys::kernel::modules_list.size()));
  std::println("");

  std::println("  {}{:<30} {:<18} {:<12}{}", console::color::dim, "MODULE",
               "BASE", "SIZE", console::color::reset);
  console::separator();

  for (const auto &[module_name, module_info] : sys::kernel::modules_list) {
    std::println("  {:<30} {}0x{:016X}{}  {}", module_name,
                 console::color::cyan, module_info.base_address,
                 console::color::reset, console::format_size(module_info.size));
  }
  std::println("");
}

CLI::App *init_kme(CLI::App &app) {
  CLI::App *kme = app.add_subcommand("kme", "list exports of a kernel module")
                      ->ignore_case()
                      ->alias("exports");

  add_command_option(kme, "module_name")->required();
  add_command_option(kme, "--filter"); // optional filter

  return kme;
}

void process_kme(CLI::App *kme) {
  const std::string module_name =
      get_command_option<std::string>(kme, "module_name");
  const std::string filter = get_command_option<std::string>(kme, "--filter");

  if (sys::kernel::modules_list.contains(module_name) == false) {
    console::error("Module not found", module_name);
    return;
  }

  const sys::kernel_module_t module = sys::kernel::modules_list[module_name];

  std::uint64_t shown = 0;
  console::info(std::format("Exports from '{}' (base: 0x{:X})", module_name,
                            module.base_address));
  std::println("");

  for (auto &[export_name, export_address] : module.exports) {
    // Apply filter if provided
    if (!filter.empty() && export_name.find(filter) == std::string::npos)
      continue;

    std::println("  {}0x{:016X}{}  {}", console::color::cyan, export_address,
                 console::color::reset, export_name);
    shown++;
  }

  std::println("\n{}Shown {} of {} exports{}", console::color::dim, shown,
               module.exports.size(), console::color::reset);
}

CLI::App *init_dkm(CLI::App &app) {
  CLI::App *dkm = app.add_subcommand("dkm", "dump kernel module to file")
                      ->ignore_case()
                      ->alias("dumpmod");

  add_command_option(dkm, "module_name")->required();
  add_command_option(dkm, "output_directory")->required();

  return dkm;
}

void process_dkm(CLI::App *dkm) {
  const std::string module_name =
      get_command_option<std::string>(dkm, "module_name");

  if (sys::kernel::modules_list.contains(module_name) == false) {
    console::error("Module not found", module_name);
    return;
  }

  const std::string output_directory =
      get_command_option<std::string>(dkm, "output_directory");

  console::info(
      std::format("Dumping '{}' to '{}'...", module_name, output_directory));

  const std::uint8_t status =
      sys::kernel::dump_module_to_disk(module_name, output_directory);

  if (status == 1) {
    std::string output_path = output_directory + "\\dump_" + module_name;
    console::success(std::format("Module dumped to '{}'", output_path));
  } else {
    console::error("Failed to dump module", "check path and permissions");
  }
}

CLI::App *init_gva(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *gva =
      app.add_subcommand("gva", "resolve alias to numerical address")
          ->ignore_case()
          ->alias("resolve");

  add_transformed_command_option(gva, "alias_name", aliases_transformer)
      ->required();

  return gva;
}

void process_gva(CLI::App *gva) {
  const std::uint64_t alias_value =
      get_command_option<std::uint64_t>(gva, "alias_name");

  console::print_value("Address", alias_value);
}

// ============================================================================
// PROCESS MONITOR - Simple process-filtered syscall monitoring
// Usage: monitor <process.exe>    - Start monitoring
//        monitor stop             - Stop monitoring
//        logs                     - View captured syscalls
// ============================================================================

namespace process_monitor {
static std::uint64_t target_cr3 = 0;
static std::string target_process = "";
static std::uint64_t ki_syscall_hook_addr = 0;
static bool is_monitoring = false;

// Find process CR3 by name using NtQuerySystemInformation + kernel read
std::uint64_t find_process_cr3(const std::string &process_name) {
  // Query process list
  std::uint32_t buffer_size = 0;
  sys::user::query_system_information(5, nullptr, 0, &buffer_size);

  if (buffer_size == 0) {
    console::error("Failed to query process information buffer size");
    return 0;
  }

  std::vector<std::uint8_t> buffer(buffer_size + 0x10000);
  std::uint32_t returned = 0;

  if (sys::user::query_system_information(
          5, buffer.data(), static_cast<std::uint32_t>(buffer.size()),
          &returned) != 0) {
    console::error("Failed to query system process information");
    return 0;
  }

  // Parse process list to find target
  std::uint8_t *ptr = buffer.data();
  DWORD target_pid = 0;

  while (true) {
    auto *proc_info = reinterpret_cast<MY_SYSTEM_PROCESS_INFORMATION *>(ptr);

    if (proc_info->ImageName.Buffer != nullptr) {
      // Convert wide string to narrow for comparison
      std::wstring wname(proc_info->ImageName.Buffer,
                         proc_info->ImageName.Length / sizeof(wchar_t));
      std::string name(wname.begin(), wname.end());

      // Case-insensitive compare
      std::string lower_name = name;
      std::string lower_target = process_name;
      for (auto &c : lower_name)
        c = static_cast<char>(std::tolower(c));
      for (auto &c : lower_target)
        c = static_cast<char>(std::tolower(c));

      if (lower_name == lower_target) {
        target_pid = static_cast<DWORD>(
            reinterpret_cast<ULONG_PTR>(proc_info->UniqueProcessId));
        console::success(
            std::format("Found process: {} (PID: {})", name, target_pid));
        break;
      }
    }

    if (proc_info->NextEntryOffset == 0)
      break;
    ptr += proc_info->NextEntryOffset;
  }

  if (target_pid == 0) {
    console::error(std::format("Process '{}' not found", process_name));
    return 0;
  }

  // Now we need to get the CR3 from the EPROCESS structure
  // Use PsLookupProcessByProcessId or read EPROCESS directly
  // We'll read PsInitialSystemProcess and walk the ActiveProcessLinks

  // Get PsInitialSystemProcess address
  auto &ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];
  std::uint64_t ps_initial = 0;

  if (ntoskrnl.exports.contains("PsInitialSystemProcess")) {
    std::uint64_t ptr_addr = ntoskrnl.exports["PsInitialSystemProcess"];
    // Read the pointer value
    hypercall::read_guest_virtual_memory(&ps_initial, ptr_addr,
                                         sys::current_cr3, 8);
  }

  if (ps_initial == 0) {
    console::warn(
        "Cannot resolve PsInitialSystemProcess - process filtering disabled");
    console::info("Monitoring ALL syscalls instead");
    return 0;
  }

  // Walk EPROCESS list to find our target PID
  // EPROCESS offsets for Windows 11 24H2 (Germanium kernel):
  // DirectoryTableBase: 0x28 (in KPROCESS at start of EPROCESS)
  // UniqueProcessId: 0x1d0
  // ActiveProcessLinks: 0x1d8
  constexpr std::uint64_t EPROCESS_PID_OFFSET = 0x1d0;
  constexpr std::uint64_t EPROCESS_DTB_OFFSET = 0x28;
  constexpr std::uint64_t EPROCESS_LINKS_OFFSET = 0x1d8;

  std::uint64_t current_eprocess = ps_initial;
  std::uint64_t first_eprocess = ps_initial;

  for (int i = 0; i < 1000; i++) { // Safety limit
    // Read PID from this EPROCESS
    std::uint64_t pid = 0;
    hypercall::read_guest_virtual_memory(
        &pid, current_eprocess + EPROCESS_PID_OFFSET, sys::current_cr3, 8);

    if (static_cast<DWORD>(pid) == target_pid) {
      // Found it! Read CR3
      std::uint64_t cr3 = 0;
      hypercall::read_guest_virtual_memory(
          &cr3, current_eprocess + EPROCESS_DTB_OFFSET, sys::current_cr3, 8);

      console::success(std::format("Process CR3: {:#x}", cr3));
      return cr3;
    }

    // Move to next process
    std::uint64_t flink = 0;
    hypercall::read_guest_virtual_memory(
        &flink, current_eprocess + EPROCESS_LINKS_OFFSET, sys::current_cr3, 8);

    current_eprocess = flink - EPROCESS_LINKS_OFFSET;

    if (current_eprocess == first_eprocess || current_eprocess == 0) {
      break; // Wrapped around or invalid
    }
  }

  console::warn("Could not find process EPROCESS - monitoring ALL syscalls");
  return 0;
}

// Find KiSystemCall64 address by pattern scanning
std::uint64_t find_ki_system_call64() {
  auto &ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];

  // Check if already in exports (might have been added)
  if (ntoskrnl.exports.contains("KiSystemCall64")) {
    return ntoskrnl.exports["KiSystemCall64"];
  }

  // Pattern scan for KiSystemCall64
  // Look for the characteristic prologue: swapgs; mov gs:[...], rsp
  // Pattern: 0F 01 F8 (swapgs) followed by typical syscall handler code

  constexpr std::uint64_t scan_size = 0x800000;
  std::vector<std::uint8_t> ntoskrnl_bytes(scan_size);

  hypercall::read_guest_virtual_memory(ntoskrnl_bytes.data(),
                                       ntoskrnl.base_address, sys::current_cr3,
                                       scan_size);

  // Pattern: swapgs (0F 01 F8) + mov gs:[offset], rsp (65 48 89 24 25 ...)
  const std::uint8_t pattern[] = {0x0F, 0x01, 0xF8, 0x65, 0x48, 0x89};

  for (std::uint64_t i = 0; i < scan_size - 16; i++) {
    bool match = true;
    for (int j = 0; j < 6 && match; j++) {
      if (ntoskrnl_bytes[i + j] != pattern[j])
        match = false;
    }

    if (match) {
      std::uint64_t addr = ntoskrnl.base_address + i;
      console::success(std::format("Found KiSystemCall64 at {:#x}", addr));
      return addr;
    }
  }

  return 0;
}
} // namespace process_monitor

// ============================================================================
// HYPERVISOR-LEVEL SYSCALL INTERCEPTION (SELECTIVE)
// ============================================================================

namespace syscall_intercept {
// Track hooked syscalls: name -> hooked VA
static std::unordered_map<std::string, std::uint64_t> hooked_syscalls = {};

// Syscall name <-> number mapping
static const std::unordered_map<std::string, std::uint32_t> syscall_nums = {
    {"NtAccessCheck", 0},
    {"NtWaitForSingleObject", 4},
    {"NtReadFile", 6},
    {"NtDeviceIoControlFile", 7},
    {"NtWriteFile", 8},
    {"NtClose", 15},
    {"NtQueryObject", 16},
    {"NtQueryInformationFile", 17},
    {"NtOpenKey", 18},
    {"NtAllocateVirtualMemory", 24},
    {"NtQueryInformationProcess", 25},
    {"NtFreeVirtualMemory", 30},
    {"NtQueryVirtualMemory", 35},
    {"NtOpenProcess", 38},
    {"NtMapViewOfSection", 40},
    {"NtUnmapViewOfSection", 42},
    {"NtTerminateProcess", 44},
    {"NtOpenFile", 51},
    {"NtQuerySystemInformation", 54},
    {"NtWriteVirtualMemory", 58},
    {"NtReadVirtualMemory", 63},
    {"NtCreateSection", 74},
    {"NtProtectVirtualMemory", 80},
    {"NtResumeThread", 82},
    {"NtTerminateThread", 83},
    {"NtCreateFile", 85},
    {"NtWaitForMultipleObjects", 91},
    {"NtCreateThreadEx", 201},
    {"NtCreateUserProcess", 209},
    {"NtRaiseHardError", 373},
    {"NtLoadDriver", 270},
    {"NtDebugActiveProcess", 214},
};
} // namespace syscall_intercept

CLI::App *init_syscall(CLI::App &app, CLI::Transformer &aliases_transformer) {
  CLI::App *syscall_cmd =
      app.add_subcommand("syscall", "hook individual syscalls by name")
          ->ignore_case();

  // Hook a specific syscall - don't transform, we need the original name for
  // tracking
  auto hook_cmd =
      syscall_cmd->add_subcommand("hook", "hook a specific syscall");
  add_command_option(hook_cmd,
                     "target"); // Keep original name, don't resolve to address
  add_command_flag(hook_cmd, "--monitor");

  // Unhook
  auto unhook_cmd = syscall_cmd->add_subcommand("unhook", "unhook a syscall");
  add_command_option(unhook_cmd, "target");

  // List/status
  syscall_cmd->add_subcommand("list", "list available syscalls");
  syscall_cmd->add_subcommand("active", "show hooked syscalls");
  syscall_cmd->add_subcommand("logs", "view captured logs");
  syscall_cmd->add_subcommand("clear", "unhook all");

  return syscall_cmd;
}

void process_syscall_cmd(CLI::App *syscall_cmd) {
  auto hook_cmd = syscall_cmd->get_subcommand("hook");
  auto unhook_cmd = syscall_cmd->get_subcommand("unhook");
  auto list_cmd = syscall_cmd->get_subcommand("list");
  auto active_cmd = syscall_cmd->get_subcommand("active");
  auto logs_cmd = syscall_cmd->get_subcommand("logs");
  auto clear_cmd = syscall_cmd->get_subcommand("clear");

  if (*hook_cmd) {
    std::string target = get_command_option<std::string>(hook_cmd, "target");
    bool monitor = get_command_flag(hook_cmd, "--monitor");

    if (target.empty()) {
      console::error("Usage: syscall hook <NtFunctionName> [--monitor]");
      console::info("Example: syscall hook NtCreateFile --monitor");
      return;
    }

    // Already hooked?
    if (syscall_intercept::hooked_syscalls.contains(target)) {
      console::warn(std::format("'{}' already hooked", target));
      return;
    }

    // Try to resolve address
    std::uint64_t addr = 0;

    // Check if numeric
    try {
      addr = std::stoull(target, nullptr, 0);
    } catch (...) {
    }

    // Look up in exports
    if (addr == 0) {
      auto &ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];

      if (ntoskrnl.exports.contains(target)) {
        addr = ntoskrnl.exports[target];
      } else if (ntoskrnl.exports.contains("ntoskrnl.exe!" + target)) {
        addr = ntoskrnl.exports["ntoskrnl.exe!" + target];
      }
      // Try Zw version
      else if (target.starts_with("Nt")) {
        std::string zw = "Zw" + target.substr(2);
        if (ntoskrnl.exports.contains(zw)) {
          addr = ntoskrnl.exports[zw];
        }
      }
    }

    if (addr == 0) {
      console::error(std::format("Cannot resolve '{}'", target));
      console::info("Use 'syscall list' to see available syscalls");
      return;
    }

    console::print_value(target, addr);

    // Build monitor code if needed
    std::vector<std::uint8_t> pre_asm;
    std::vector<std::uint8_t> post_asm;

    if (monitor) {
      hypercall_info_t hc = {};
      hc.primary_key = hypercall_primary_key;
      hc.secondary_key = hypercall_secondary_key;
      hc.call_type = hypercall_type_t::log_current_state;

      pre_asm = {
          0x51,                         // push rcx
          0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, <magic>
          0x0F, 0xA2,                   // cpuid
          0x59,                         // pop rcx
      };
      *reinterpret_cast<std::uint32_t *>(&pre_asm[2]) =
          static_cast<std::uint32_t>(hc.value);
    }

    // Hook!
    std::uint8_t result = hook::add_kernel_hook(addr, pre_asm, post_asm);

    if (result == 0) {
      console::error(std::format("Failed to hook '{}'", target));
      return;
    }

    syscall_intercept::hooked_syscalls[target] = addr;
    console::success(
        std::format("Hooked '{}'{}", target, monitor ? " [logging]" : ""));

    if (monitor) {
      console::info("Use 'logs' or 'syscall logs' to view calls");
    }
  } else if (*unhook_cmd) {
    std::string target = get_command_option<std::string>(unhook_cmd, "target");

    if (target.empty()) {
      console::error("Usage: syscall unhook <name>");
      return;
    }

    auto it = syscall_intercept::hooked_syscalls.find(target);
    if (it == syscall_intercept::hooked_syscalls.end()) {
      console::warn(std::format("'{}' not hooked", target));
      return;
    }

    hook::remove_kernel_hook(it->second, 1);
    syscall_intercept::hooked_syscalls.erase(it);
    console::success(std::format("Unhooked '{}'", target));
  } else if (*list_cmd) {
    console::separator("Available Syscalls");
    auto &ntoskrnl = sys::kernel::modules_list["ntoskrnl.exe"];

    int col = 0;
    for (const auto &[name, num] : syscall_intercept::syscall_nums) {
      bool ok = ntoskrnl.exports.contains(name) ||
                ntoskrnl.exports.contains("ntoskrnl.exe!" + name);

      std::print("{}{:<28}{}", ok ? console::color::green : console::color::dim,
                 name, console::color::reset);

      if (++col % 3 == 0)
        std::println("");
    }
    if (col % 3 != 0)
      std::println("");

    std::println("\n{}Tip:{} syscall hook NtCreateFile --monitor",
                 console::color::dim, console::color::reset);
    console::separator();
  } else if (*active_cmd) {
    if (syscall_intercept::hooked_syscalls.empty()) {
      console::info("No syscalls hooked");
      console::info("Try: syscall hook NtCreateFile --monitor");
      return;
    }

    console::separator("Hooked Syscalls");
    for (const auto &[name, addr] : syscall_intercept::hooked_syscalls) {
      std::println("  {} {}{}{} at 0x{:X}", console::color::green,
                   console::color::reset, name, console::color::dim, addr);
    }
    console::separator();
  } else if (*logs_cmd) {
    constexpr std::uint64_t log_count = 100;
    std::vector<trap_frame_log_t> logs(log_count);
    std::uint64_t n = hypercall::flush_logs(logs);

    if (n == static_cast<std::uint64_t>(-1)) {
      console::error("Failed to flush logs");
      return;
    }
    if (n == 0) {
      console::info("No logs yet");
      return;
    }

    console::separator("Syscall Logs");
    for (std::uint64_t i = 0; i < n; i++) {
      const auto &l = logs[i];

      // Find which syscall by address proximity
      std::string name = "?";
      for (const auto &[nm, addr] : syscall_intercept::hooked_syscalls) {
        if (l.rip >= addr && l.rip < addr + 0x1000) {
          name = nm;
          break;
        }
      }

      std::println("  [{}] {}{}{} CR3=0x{:X}", i, console::color::green, name,
                   console::color::reset, l.cr3);
      std::println("      RCX=0x{:X} RDX=0x{:X} R8=0x{:X} R9=0x{:X}", l.rcx,
                   l.rdx, l.r8, l.r9);
    }
    console::separator();
  } else if (*clear_cmd) {
    if (syscall_intercept::hooked_syscalls.empty()) {
      console::info("Nothing to clear");
      return;
    }

    std::uint64_t count = syscall_intercept::hooked_syscalls.size();
    for (const auto &[n, addr] : syscall_intercept::hooked_syscalls) {
      hook::remove_kernel_hook(addr, 1);
    }
    syscall_intercept::hooked_syscalls.clear();
    console::success(std::format("Cleared {} hook(s)", count));
  } else {
    // Help
    std::println("\n{}Syscall Hooking:{}", console::color::bold,
                 console::color::reset);
    std::println("  {}syscall hook <name> [--monitor]{}  Hook a syscall",
                 console::color::green, console::color::reset);
    std::println("  {}syscall unhook <name>{}            Unhook",
                 console::color::green, console::color::reset);
    std::println("  {}syscall list{}                     Show available",
                 console::color::green, console::color::reset);
    std::println("  {}syscall active{}                   Show hooked",
                 console::color::green, console::color::reset);
    std::println("  {}syscall logs{}                     View logs",
                 console::color::green, console::color::reset);
    std::println("  {}syscall clear{}                    Unhook all",
                 console::color::green, console::color::reset);
    std::println("\n{}Example:{}", console::color::dim, console::color::reset);
    std::println("  syscall hook NtCreateFile --monitor");
    std::println("  syscall hook NtOpenProcess --monitor");
    std::println("  syscall logs");
  }
}

// ============================================================================
// SIMPLE MONITOR COMMAND
// Usage: monitor <process.exe>  - Start monitoring all syscalls from process
//        monitor stop           - Stop monitoring
//        logs                   - View captured syscalls (existing command)
// ============================================================================

CLI::App *init_monitor(CLI::App &app) {
  CLI::App *monitor_cmd =
      app.add_subcommand("monitor", "Simple process syscall monitoring")
          ->ignore_case();

  add_command_option(monitor_cmd, "target");

  return monitor_cmd;
}

void process_monitor_cmd(CLI::App *monitor_cmd) {
  if (!*monitor_cmd)
    return;

  std::string target = get_command_option<std::string>(monitor_cmd, "target");

  if (target.empty()) {
    // Show help
    console::separator("Process Monitor");
    std::println("{}Usage:{}", console::color::bold, console::color::reset);
    std::println("  {}monitor <process.exe>{}  - Start monitoring",
                 console::color::green, console::color::reset);
    std::println("  {}monitor stop{}          - Stop monitoring",
                 console::color::green, console::color::reset);
    std::println("  {}logs{}                  - View captured syscalls",
                 console::color::green, console::color::reset);

    std::println("\n{}Status:{}", console::color::bold, console::color::reset);
    if (process_monitor::is_monitoring) {
      std::println("  Monitoring: {} (CR3: {:#x})",
                   process_monitor::target_process,
                   process_monitor::target_cr3);
    } else {
      std::println("  Not monitoring");
    }
    console::separator();
    return;
  }

  // Handle "stop" command
  if (target == "stop" || target == "off" || target == "disable") {
    if (!process_monitor::is_monitoring) {
      console::warn("Not currently monitoring");
      return;
    }

    // Remove the KiSystemCall64 hook
    if (process_monitor::ki_syscall_hook_addr != 0) {
      hook::remove_kernel_hook(process_monitor::ki_syscall_hook_addr, 1);
    }

    // Disable syscall intercept
    hypercall::disable_syscall_intercept();

    process_monitor::is_monitoring = false;
    process_monitor::target_process = "";
    process_monitor::target_cr3 = 0;
    process_monitor::ki_syscall_hook_addr = 0;

    console::success("Monitoring stopped");
    return;
  }

  // Start monitoring a process
  if (process_monitor::is_monitoring) {
    console::warn(
        std::format("Already monitoring {}. Use 'monitor stop' first.",
                    process_monitor::target_process));
    return;
  }

  console::info(std::format("Setting up monitoring for: {}", target));

  // Find KiSystemCall64
  std::uint64_t ki_addr = process_monitor::find_ki_system_call64();
  if (ki_addr == 0) {
    console::error("Failed to find KiSystemCall64");
    return;
  }

  // Look up process and get CR3 for filtering
  std::uint64_t target_cr3 = process_monitor::find_process_cr3(target);
  process_monitor::target_cr3 = target_cr3;

  // Build monitor code (same as hook --monitor)
  hypercall_info_t hc = {};
  hc.primary_key = hypercall_primary_key;
  hc.secondary_key = hypercall_secondary_key;
  hc.call_type = hypercall_type_t::log_current_state;

  std::vector<std::uint8_t> pre_asm = {
      0x51,                         // push rcx
      0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, <magic>
      0x0F, 0xA2,                   // cpuid
      0x59,                         // pop rcx
  };
  *reinterpret_cast<std::uint32_t *>(&pre_asm[2]) =
      static_cast<std::uint32_t>(hc.value);

  std::vector<std::uint8_t> post_asm; // Empty

  // Hook KiSystemCall64
  std::uint8_t result = hook::add_kernel_hook(ki_addr, pre_asm, post_asm);

  if (result == 0) {
    console::error("Failed to hook KiSystemCall64");
    return;
  }

  // Set up syscall filtering
  if (target_cr3 != 0) {
    // Enable filtered mode with process CR3
    hypercall::set_syscall_filter(0, 0xFFFFFFFF,
                                  target_cr3); // All syscalls, from this CR3
    hypercall::enable_syscall_intercept(2);    // Mode 2 = log_filtered
    console::info(
        std::format("Filtering syscalls from CR3: {:#x}", target_cr3));
  } else {
    // No CR3 filter - log all syscalls (might be spammy)
    hypercall::enable_syscall_intercept(1); // Mode 1 = log_all
    console::warn("No CR3 filter - logging ALL syscalls (may be spammy)");
  }

  process_monitor::is_monitoring = true;
  process_monitor::target_process = target;
  process_monitor::ki_syscall_hook_addr = ki_addr;

  console::success(std::format("Monitoring started for: {}", target));
  console::info("Use 'logs' to view captured syscalls");
  console::warn("Use 'monitor stop' to stop (prevents BSOD on exit)");
}

// ============================================================================
// MAIN COMMAND PROCESSOR
// ============================================================================

std::unordered_map<std::string, std::uint64_t> form_aliases() {
  std::unordered_map<std::string, std::uint64_t> aliases = {
      {"current_cr3", sys::current_cr3}};

  for (auto &[module_name, module_info] : sys::kernel::modules_list) {
    aliases.insert({module_name, module_info.base_address});
    aliases.insert(module_info.exports.begin(), module_info.exports.end());
  }

  return aliases;
}

void commands::process(const std::string command) {
  if (command.empty() == true) {
    return;
  }

  CLI::App app;
  app.require_subcommand();

  sys::kernel::parse_modules();

  const std::unordered_map<std::string, std::uint64_t> aliases = form_aliases();

  CLI::Transformer aliases_transformer =
      CLI::Transformer(aliases, CLI::ignore_case);
  aliases_transformer.description(" (alias)");

  // Session commands
  CLI::App *status = init_status(app);
  CLI::App *help_cmd = init_help_cmd(app);

  // Memory commands
  CLI::App *rgpm = init_rgpm(app, aliases_transformer);
  CLI::App *wgpm = init_wgpm(app, aliases_transformer);
  CLI::App *cgpm = init_cgpm(app, aliases_transformer);
  CLI::App *gvat = init_gvat(app, aliases_transformer);
  CLI::App *rgvm = init_rgvm(app, aliases_transformer);
  CLI::App *wgvm = init_wgvm(app, aliases_transformer);
  CLI::App *cgvm = init_cgvm(app, aliases_transformer);
  CLI::App *dump = init_dump(app, aliases_transformer);
  CLI::App *dis = init_disasm(app, aliases_transformer);

  // Hooking commands
  CLI::App *akh = init_akh(app, aliases_transformer);
  CLI::App *rkh = init_rkh(app, aliases_transformer);
  CLI::App *hgpp = init_hgpp(app, aliases_transformer);
  CLI::App *fl = init_fl(app);

  // Analysis commands
  CLI::App *hfpc = init_hfpc(app);
  CLI::App *lkm = init_lkm(app);
  CLI::App *kme = init_kme(app);
  CLI::App *dkm = init_dkm(app);
  CLI::App *gva = init_gva(app, aliases_transformer);

  // Hypervisor-level syscall interception
  CLI::App *syscall_cmd = init_syscall(app, aliases_transformer);

  // Simple process monitor
  CLI::App *monitor_cmd = init_monitor(app);

  try {
    app.parse(command);

    // Session
    d_initial_process_command(status);
    d_process_command(help_cmd);

    // Memory
    d_process_command(rgpm);
    d_process_command(wgpm);
    d_process_command(cgpm);
    d_process_command(gvat);
    d_process_command(rgvm);
    d_process_command(wgvm);
    d_process_command(cgvm);
    d_process_command(dump);
    d_process_command(dis);

    // Hooking
    d_process_command(akh);
    d_process_command(rkh);
    d_process_command(hgpp);
    d_process_command(fl);

    // Analysis
    d_process_command(hfpc);
    d_process_command(lkm);
    d_process_command(kme);
    d_process_command(dkm);
    d_process_command(gva);

    // Hypervisor-level syscall interception
    d_process_command(syscall_cmd);

    // Simple process monitor
    process_monitor_cmd(monitor_cmd);
  } catch (const CLI::ParseError &error) {
    app.exit(error);
  }
}

// Cleanup syscall interception on exit
void commands::syscall_intercept_cleanup() {
  // Remove monitor hook if active
  if (process_monitor::is_monitoring) {
    if (process_monitor::ki_syscall_hook_addr != 0) {
      hook::remove_kernel_hook(process_monitor::ki_syscall_hook_addr, 1);
    }
    hypercall::disable_syscall_intercept();
    process_monitor::is_monitoring = false;
  }

  // Remove all hooked syscalls
  for (const auto &[name, addr] : syscall_intercept::hooked_syscalls) {
    hook::remove_kernel_hook(addr, 1);
  }
  syscall_intercept::hooked_syscalls.clear();
}
