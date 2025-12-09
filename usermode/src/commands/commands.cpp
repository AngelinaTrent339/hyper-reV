#include "commands.h"
#include "../hook/hook.h"
#include "../hypercall/hypercall.h"
#include "../inject/hidden_inject.h"
#include "../inject/hook_exec.h"
#include "../system/system.h"
#include "../util/console.h"
#include "../util/disasm.h"
#include <CLI/CLI.hpp>
#include <hypercall/hypercall_def.h>

#include <array>
#include <chrono>
#include <format>
#include <print>

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
  std::println("  {}exit{}                                 - exit session",
               console::color::magenta, console::color::reset);

  std::println("\n{}Process Tracking:{}", console::color::bold,
               console::color::reset);
  std::println("  {}track set \u003cname|pid\u003e{}                 - "
               "auto-capture process CR3",
               console::color::cyan, console::color::reset);
  std::println("  {}track status{}                         - show tracked CR3",
               console::color::cyan, console::color::reset);
  std::println("  {}track clear{}                          - clear tracking",
               console::color::cyan, console::color::reset);

  std::println("\n{}MSR Shadowing (AMD):{}", console::color::bold,
               console::color::reset);
  std::println("  {}msr add \u003cmsr\u003e \u003cvalue\u003e{}                "
               "- shadow MSR read",
               console::color::yellow, console::color::reset);
  std::println(
      "  {}msr remove \u003cmsr\u003e{}                     - remove shadow",
      console::color::yellow, console::color::reset);
  std::println("  {}msr list{}                             - list all shadows",
               console::color::yellow, console::color::reset);
  std::println("  {}msr clear{}                            - clear all shadows",
               console::color::yellow, console::color::reset);
  std::println(
      "  {}msr status{}                           - show intercept stats",
      console::color::yellow, console::color::reset);
  std::println("  {}msr intercept \u003cmsr\u003e [flags]{}          - enable "
               "MSRPM intercept",
               console::color::yellow, console::color::reset);

  std::println("");
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
// PROCESS CR3 AUTO-TRACKING COMMANDS
// ============================================================================

CLI::App *init_track(CLI::App &app) {
  CLI::App *track = app.add_subcommand("track", "process CR3 auto-tracking")
                        ->ignore_case()
                        ->alias("tpid");

  // Subcommands for different tracking operations
  track->add_subcommand(
      "set", "set PID or process name to track and auto-capture CR3");
  track->add_subcommand("status", "show current tracking status");
  track->add_subcommand("clear", "clear tracked PID and captured CR3");
  track->add_subcommand("cr3", "get captured CR3 for tracked process");

  // For 'track set', we need a target (PID or process name)
  add_command_option(track->get_subcommand("set"), "target")->required();

  return track;
}

// Helper to check if a string is a valid numeric PID
bool is_numeric_pid(const std::string &str) {
  if (str.empty())
    return false;

  // Check for hex format (0x...)
  if (str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
    return std::all_of(str.begin() + 2, str.end(), [](char c) {
      return std::isxdigit(static_cast<unsigned char>(c));
    });
  }

  // Check for decimal
  return std::all_of(str.begin(), str.end(), [](char c) {
    return std::isdigit(static_cast<unsigned char>(c));
  });
}

void process_track(CLI::App *track) {
  auto *set_cmd = track->get_subcommand("set");
  auto *status_cmd = track->get_subcommand("status");
  auto *clear_cmd = track->get_subcommand("clear");
  auto *cr3_cmd = track->get_subcommand("cr3");

  if (*set_cmd) {
    const std::string target =
        get_command_option<std::string>(set_cmd, "target");
    std::uint64_t pid = 0;
    std::string process_name;

    if (is_numeric_pid(target)) {
      // It's a numeric PID
      if (target.size() > 2 && target[0] == '0' &&
          (target[1] == 'x' || target[1] == 'X')) {
        pid = std::stoull(target, nullptr, 16);
      } else {
        pid = std::stoull(target);
      }
    } else {
      // It's a process name, look it up
      process_name = target;
      console::info(std::format("Looking up process '{}'...", process_name));

      auto found_pid = sys::user::find_process_by_name(process_name);
      if (found_pid.has_value()) {
        pid = found_pid.value();
        console::success(std::format("Found '{}' with PID {} (0x{:X})",
                                     process_name, pid, pid));
      } else {
        console::error("Process not found",
                       std::format("'{}' is not running", process_name));
        console::info("Make sure the process is running and try again.");
        console::info("Tip: You can also use Task Manager to find the PID and "
                      "use 'track set <pid>'");
        return;
      }
    }

    const std::uint64_t result = hypercall::set_tracked_pid(pid);

    if (result == 1) {
      if (process_name.empty()) {
        console::success(std::format("Now tracking PID {} (0x{:X})", pid, pid));
      } else {
        console::success(std::format("Now tracking '{}' (PID {} / 0x{:X})",
                                     process_name, pid, pid));
      }
      console::info(
          "The hypervisor will capture the CR3 when this process executes.");
      console::info(
          "Use 'track status' or 'track cr3' to check if CR3 was captured.");
    } else {
      console::error("Failed to set tracked PID", std::format("PID={}", pid));
    }
  } else if (*status_cmd) {
    hypercall::tracking_status_t status = {};
    const std::uint64_t cr3 = hypercall::get_tracking_status(&status);

    std::println("");
    std::println(
        "{}╔════════════════════════════════════════════════════════════════╗{"
        "}",
        console::color::cyan, console::color::reset);
    std::println("{}║{} {}PROCESS CR3 TRACKING STATUS{}                        "
                 "            {}║{}",
                 console::color::cyan, console::color::reset,
                 console::color::bold, console::color::reset,
                 console::color::cyan, console::color::reset);
    std::println(
        "{}╚════════════════════════════════════════════════════════════════╝{"
        "}",
        console::color::cyan, console::color::reset);
    std::println("");

    if (status.tracked_pid == 0) {
      console::info("No process is currently being tracked.");
      console::info("Use 'track set <pid>' to start tracking a process.");
    } else {
      std::println("  {}Tracked PID{}:    {} (0x{:X})", console::color::yellow,
                   console::color::reset, status.tracked_pid,
                   status.tracked_pid);

      if (status.tracked_cr3 != 0) {
        std::println("  {}Captured CR3{}:   {}0x{:016X}{}  ✓",
                     console::color::green, console::color::reset,
                     console::color::cyan, status.tracked_cr3,
                     console::color::reset);
        std::println("  {}GS Base{}:        0x{:016X}", console::color::dim,
                     console::color::reset, status.gs_base);
        std::println("  {}Match Count{}:    {}", console::color::dim,
                     console::color::reset, status.match_count);
        std::println("");
        console::success(
            "CR3 captured! You can now use this CR3 for memory operations.");
        std::println("");
        console::info("Examples:");
        std::println("  dump <address> <size> --cr3 0x{:X}",
                     status.tracked_cr3);
        std::println("  rgvm <address> 0x{:X} <1-8>  (read single value)",
                     status.tracked_cr3);
      } else {
        std::println("  {}Captured CR3{}:   (not yet captured)",
                     console::color::yellow, console::color::reset);
        std::println("");
        console::info("Waiting for the tracked process to execute...");
        console::info("Make sure the target process is running and active.");
      }
    }
    std::println("");
  } else if (*clear_cmd) {
    const std::uint64_t result = hypercall::clear_tracked_pid();

    if (result == 1) {
      console::success("Tracking cleared.");
    } else {
      console::error("Failed to clear tracking");
    }
  } else if (*cr3_cmd) {
    const std::uint64_t cr3 = hypercall::get_tracked_cr3();

    if (cr3 != 0) {
      console::print_value("Tracked CR3", cr3);
    } else {
      console::warn("CR3 not yet captured or no PID is being tracked.");
      console::info("Use 'track set <pid/name>' first, then wait for the "
                    "process to execute.");
    }
  } else {
    // No subcommand specified, show help
    console::info("Process CR3 Auto-Tracking Commands:");
    std::println("");
    std::println(
        "  {}track set <target>{}   - Start tracking by PID or process name",
        console::color::yellow, console::color::reset);
    std::println(
        "  {}track status{}        - Show tracking status and captured CR3",
        console::color::yellow, console::color::reset);
    std::println("  {}track cr3{}           - Get the captured CR3 value",
                 console::color::yellow, console::color::reset);
    std::println("  {}track clear{}         - Stop tracking and clear state",
                 console::color::yellow, console::color::reset);
    std::println("");
    std::println("  {}Examples:{}", console::color::cyan,
                 console::color::reset);
    std::println("    track set notepad.exe   - Track by process name");
    std::println("    track set 1234          - Track by PID (decimal)");
    std::println("    track set 0x4D2         - Track by PID (hex)");
    std::println("");
    console::info(
        "The hypervisor automatically captures CR3 when the tracked process");
    console::info("is seen executing in user mode during any VM exit.");
  }
}

// ============================================================================
// MSR SHADOW COMMANDS (AMD only)
// ============================================================================

// Common MSR names for convenience
std::string get_msr_name(std::uint32_t msr_index) {
  switch (msr_index) {
  case 0x1D9:
    return "IA32_DEBUGCTL";
  case 0x174:
    return "IA32_SYSENTER_CS";
  case 0x175:
    return "IA32_SYSENTER_ESP";
  case 0x176:
    return "IA32_SYSENTER_EIP";
  case 0xC0000080:
    return "IA32_EFER";
  case 0xC0000081:
    return "IA32_STAR";
  case 0xC0000082:
    return "IA32_LSTAR";
  case 0xC0000083:
    return "IA32_CSTAR";
  case 0xC0000084:
    return "IA32_FMASK";
  case 0xC0000100:
    return "IA32_FS_BASE";
  case 0xC0000101:
    return "IA32_GS_BASE";
  case 0xC0000102:
    return "IA32_KERNEL_GS_BASE";
  case 0xC0000103:
    return "IA32_TSC_AUX";
  case 0x40000000:
    return "HV_GUEST_OS_ID";
  case 0x40000001:
    return "HV_HYPERCALL";
  case 0x40000002:
    return "HV_VP_INDEX";
  default:
    return "";
  }
}

CLI::App *init_msr(CLI::App &app) {
  CLI::App *msr = app.add_subcommand("msr", "MSR shadowing (AMD only)")
                      ->ignore_case()
                      ->alias("shadow");

  msr->add_subcommand("add", "add/update MSR shadow");
  msr->add_subcommand("remove", "remove MSR shadow");
  msr->add_subcommand("list", "list active MSR shadows");
  msr->add_subcommand("clear", "clear all MSR shadows");
  msr->add_subcommand("read", "read MSR value (shows shadow if exists)");
  msr->add_subcommand("test", "test if shadowing works for an MSR");
  msr->add_subcommand("status", "show MSR intercept statistics");
  msr->add_subcommand("intercept", "enable/disable MSR interception in MSRPM");

  add_command_option(msr->get_subcommand("add"), "msr_index")->required();
  add_command_option(msr->get_subcommand("add"), "shadow_value")->required();
  add_command_option(msr->get_subcommand("remove"), "msr_index")->required();
  add_command_option(msr->get_subcommand("read"), "msr_index")->required();
  add_command_option(msr->get_subcommand("test"), "msr_index")->required();
  add_command_option(msr->get_subcommand("intercept"), "msr_index")->required();
  add_command_option(msr->get_subcommand("intercept"),
                     "flags"); // Optional: 1=read, 2=write, 3=both, 0=disable

  return msr;
}

void process_msr(CLI::App *msr) {
  auto *add_cmd = msr->get_subcommand("add");
  auto *remove_cmd = msr->get_subcommand("remove");
  auto *list_cmd = msr->get_subcommand("list");
  auto *clear_cmd = msr->get_subcommand("clear");

  if (*add_cmd) {
    const std::uint64_t msr_index =
        get_command_option<std::uint64_t>(add_cmd, "msr_index");
    const std::uint64_t shadow_value =
        get_command_option<std::uint64_t>(add_cmd, "shadow_value");

    const std::uint64_t result = hypercall::add_msr_shadow(
        static_cast<std::uint32_t>(msr_index), shadow_value);

    if (result == 1) {
      std::string msr_name =
          get_msr_name(static_cast<std::uint32_t>(msr_index));
      if (!msr_name.empty()) {
        console::success(
            std::format("MSR shadow added: 0x{:X} ({}) -> 0x{:016X}", msr_index,
                        msr_name, shadow_value));
      } else {
        console::success(std::format("MSR shadow added: 0x{:X} -> 0x{:016X}",
                                     msr_index, shadow_value));
      }
      console::info("Guest RDMSR will now return the shadow value.");
    } else {
      console::error("Failed to add MSR shadow",
                     "max shadows reached or invalid MSR");
    }
  } else if (*remove_cmd) {
    const std::uint64_t msr_index =
        get_command_option<std::uint64_t>(remove_cmd, "msr_index");

    const std::uint64_t result =
        hypercall::remove_msr_shadow(static_cast<std::uint32_t>(msr_index));

    if (result == 1) {
      console::success(std::format("MSR shadow removed: 0x{:X}", msr_index));
    } else {
      console::error("MSR shadow not found", std::format("0x{:X}", msr_index));
    }
  } else if (*list_cmd) {
    hypercall::msr_shadow_entry_t buffer[32] = {};
    const std::uint64_t count = hypercall::get_msr_shadow_list(buffer, 32);

    std::println("");
    std::println(
        "{}╔════════════════════════════════════════════════════════════════╗{"
        "}",
        console::color::cyan, console::color::reset);
    std::println("{}║{} {}MSR SHADOW LIST{}                                   "
                 "             {}║{}",
                 console::color::cyan, console::color::reset,
                 console::color::bold, console::color::reset,
                 console::color::cyan, console::color::reset);
    std::println(
        "{}╚════════════════════════════════════════════════════════════════╝{"
        "}",
        console::color::cyan, console::color::reset);
    std::println("");

    if (count == 0) {
      console::info("No MSR shadows are currently active.");
      console::info("Use 'msr add <msr_index> <shadow_value>' to add one.");
    } else {
      std::println("  {:>12}  {:>20}  {}", "MSR Index", "Shadow Value", "Name");
      std::println("  {:>12}  {:>20}  {}", "─────────", "────────────", "────");

      for (std::uint32_t i = 0; i < count; ++i) {
        std::string msr_name = get_msr_name(buffer[i].msr_index);
        std::println("  {}0x{:08X}{}  {}0x{:016X}{}  {}",
                     console::color::yellow, buffer[i].msr_index,
                     console::color::reset, console::color::cyan,
                     buffer[i].shadow_value, console::color::reset, msr_name);
      }
      std::println("");
      console::info(std::format("Total shadows: {}", count));
    }
    std::println("");
  } else if (*clear_cmd) {
    const std::uint64_t result = hypercall::clear_all_msr_shadows();

    if (result == 1) {
      console::success("All MSR shadows cleared.");
    } else {
      console::error("Failed to clear MSR shadows");
    }
  } else if (*msr->get_subcommand("read")) {
    // Read MSR - shows shadow value if exists
    auto *read_cmd = msr->get_subcommand("read");
    const std::uint64_t msr_index =
        get_command_option<std::uint64_t>(read_cmd, "msr_index");

    const std::uint64_t value =
        hypercall::read_msr_value(static_cast<std::uint32_t>(msr_index));
    std::string msr_name = get_msr_name(static_cast<std::uint32_t>(msr_index));

    std::println("");
    if (value == 0x8000000000000000ULL) {
      console::warn(std::format(
          "MSR 0x{:X}{} - No shadow, actual read not available", msr_index,
          msr_name.empty() ? "" : " (" + msr_name + ")"));
      console::info("Add a shadow first with 'msr add'");
    } else {
      console::success(
          std::format("MSR 0x{:X}{} = {}0x{:016X}{}", msr_index,
                      msr_name.empty() ? "" : " (" + msr_name + ")",
                      console::color::cyan, value, console::color::reset));

      // Check if this is a shadow or actual value
      hypercall::msr_shadow_entry_t buffer[32] = {};
      const std::uint64_t count = hypercall::get_msr_shadow_list(buffer, 32);
      bool is_shadow = false;
      for (std::uint32_t i = 0; i < count; ++i) {
        if (buffer[i].msr_index == msr_index) {
          is_shadow = true;
          break;
        }
      }
      if (is_shadow) {
        console::info("(This is the SHADOW value)");
      }
    }
    std::println("");
  } else if (*msr->get_subcommand("test")) {
    // Test MSR shadowing - add a test shadow, check intercepts, then remove
    auto *test_cmd = msr->get_subcommand("test");
    const std::uint64_t msr_index =
        get_command_option<std::uint64_t>(test_cmd, "msr_index");
    const std::uint64_t test_value = 0xDEADBEEFCAFEBABEULL;

    std::string msr_name = get_msr_name(static_cast<std::uint32_t>(msr_index));

    std::println("");
    console::info(std::format("Testing MSR shadowing for 0x{:X}{}...",
                              msr_index,
                              msr_name.empty() ? "" : " (" + msr_name + ")"));
    std::println("");

    // Get initial intercept count
    const std::uint64_t initial_count = hypercall::get_msr_intercept_count();

    // Add a test shadow
    const std::uint64_t add_result = hypercall::add_msr_shadow(
        static_cast<std::uint32_t>(msr_index), test_value);

    if (add_result != 1) {
      console::error("Failed to add test shadow");
      return;
    }

    std::println("  [1] Added test shadow: 0x{:X} -> 0x{:016X}", msr_index,
                 test_value);

    // Read it back
    const std::uint64_t read_value =
        hypercall::read_msr_value(static_cast<std::uint32_t>(msr_index));

    std::println("  [2] Read back value:   0x{:016X}", read_value);

    // Check if it matches
    if (read_value == test_value) {
      std::println("  [3] {}✓ Shadow value returned correctly!{}",
                   console::color::green, console::color::reset);
    } else if (read_value == 0x8000000000000000ULL) {
      std::println("  [3] {}✗ No shadow returned (MSR read not available){}",
                   console::color::red, console::color::reset);
    } else {
      std::println("  [3] {}? Unexpected value (may be actual MSR){}",
                   console::color::yellow, console::color::reset);
    }

    // Check intercept count
    const std::uint64_t final_count = hypercall::get_msr_intercept_count();
    const std::uint64_t intercepts = final_count - initial_count;

    std::println("  [4] MSR intercepts during test: {}", intercepts);

    // Remove the test shadow
    hypercall::remove_msr_shadow(static_cast<std::uint32_t>(msr_index));
    std::println("  [5] Removed test shadow");

    std::println("");
    if (read_value == test_value) {
      console::success("MSR shadowing is WORKING for this MSR!");
    } else {
      console::warn("MSR shadowing may not be active for this MSR.");
      console::info("Note: Hyper-V must be configured to intercept this MSR.");
    }
    std::println("");
  } else if (*msr->get_subcommand("status")) {
    // Show MSR intercept statistics
    const std::uint64_t intercept_count = hypercall::get_msr_intercept_count();
    const std::uint64_t shadow_count =
        hypercall::get_msr_shadow_list(nullptr, 0);

    std::println("");
    std::println(
        "{}╔════════════════════════════════════════════════════════════════╗{"
        "}",
        console::color::cyan, console::color::reset);
    std::println("{}║{} {}MSR SHADOW STATUS{}                                 "
                 "             {}║{}",
                 console::color::cyan, console::color::reset,
                 console::color::bold, console::color::reset,
                 console::color::cyan, console::color::reset);
    std::println(
        "{}╚════════════════════════════════════════════════════════════════╝{"
        "}",
        console::color::cyan, console::color::reset);
    std::println("");

    std::println("  {}Active shadows:{}    {}", console::color::dim,
                 console::color::reset, shadow_count);
    std::println("  {}Total intercepts:{} {}", console::color::dim,
                 console::color::reset, intercept_count);
    std::println("");

    // Show intercept status for each shadow
    if (shadow_count > 0) {
      hypercall::msr_shadow_entry_t buffer[32] = {};
      hypercall::get_msr_shadow_list(buffer, 32);

      std::println("  {}Shadowed MSRs:{}", console::color::dim,
                   console::color::reset);
      for (std::uint32_t i = 0; i < shadow_count && i < 32; ++i) {
        std::uint32_t msr = buffer[i].msr_index;
        std::uint64_t intercept_flags =
            hypercall::get_msr_intercept_status(msr);
        std::string msr_name = get_msr_name(msr);

        std::string intercept_desc;
        if (intercept_flags == 0)
          intercept_desc = "NOT INTERCEPTED";
        else if (intercept_flags == 1)
          intercept_desc = "RDMSR";
        else if (intercept_flags == 2)
          intercept_desc = "WRMSR";
        else
          intercept_desc = "RDMSR+WRMSR";

        std::println("    0x{:08X} {:20} -> 0x{:016X} [{}]", msr,
                     msr_name.empty() ? "" : "(" + msr_name + ")",
                     buffer[i].shadow_value, intercept_desc);
      }
      std::println("");
    }

    if (intercept_count > 0) {
      console::success(
          "MSR interception is ACTIVE - shadows have been applied.");
    } else if (shadow_count > 0) {
      console::warn("Shadows configured but no intercepts yet.");
      console::info(
          "Intercepts will be counted when guest reads shadowed MSRs.");
      console::info("Note: IA32_LSTAR is rarely read - try triggering with "
                    "WinDbg/driver.");
    } else {
      console::info("No shadows configured. Use 'msr add' to add one.");
    }
    std::println("");
  } else if (*msr->get_subcommand("intercept")) {
    // Enable/disable MSR interception in MSRPM
    auto *intercept_cmd = msr->get_subcommand("intercept");
    const std::uint64_t msr_index =
        get_command_option<std::uint64_t>(intercept_cmd, "msr_index");

    // Default to 3 (both read and write) if not specified
    std::uint64_t flags = 3;
    try {
      flags = get_command_option<std::uint64_t>(intercept_cmd, "flags");
    } catch (...) {
      // Use default
    }

    std::string msr_name = get_msr_name(static_cast<std::uint32_t>(msr_index));

    std::println("");

    // First check current status
    const std::uint64_t old_status = hypercall::get_msr_intercept_status(
        static_cast<std::uint32_t>(msr_index));

    // Set the new intercept status
    const std::uint64_t result =
        hypercall::set_msr_intercept(static_cast<std::uint32_t>(msr_index),
                                     static_cast<std::uint8_t>(flags));

    if (result == 1) {
      std::string flag_desc;
      if (flags == 0)
        flag_desc = "DISABLED";
      else if (flags == 1)
        flag_desc = "RDMSR only";
      else if (flags == 2)
        flag_desc = "WRMSR only";
      else
        flag_desc = "RDMSR+WRMSR";

      console::success(std::format(
          "MSR 0x{:X}{} interception set to: {}", msr_index,
          msr_name.empty() ? "" : " (" + msr_name + ")", flag_desc));

      if (old_status != flags) {
        console::info(std::format("(Changed from flags={} to flags={})",
                                  old_status, flags));
      }

      if (flags > 0) {
        console::info("Now add a shadow value with 'msr add' for this MSR.");
      }
    } else if (result == 0) {
      console::error(
          "Failed to set MSR intercept",
          "MSR may be outside controllable range or MSRPM not accessible");
      console::info("Controllable ranges: 0x0-0x1FFF, 0xC0000000-0xC0001FFF, "
                    "0xC0010000-0xC0011FFF");
    } else {
      console::warn(std::format("Unexpected result: {}", result));
    }
    std::println("");
  } else {
    console::info("MSR Shadow Commands (AMD only):");
    std::println("");
    std::println(
        "  {}msr add <msr_index> <shadow_value>{}  - Add/update MSR shadow",
        console::color::yellow, console::color::reset);
    std::println(
        "  {}msr remove <msr_index>{}              - Remove MSR shadow",
        console::color::yellow, console::color::reset);
    std::println(
        "  {}msr list{}                            - List active shadows",
        console::color::yellow, console::color::reset);
    std::println(
        "  {}msr clear{}                           - Clear all shadows",
        console::color::yellow, console::color::reset);
    std::println("  {}msr read <msr_index>{}                - Read MSR (shows "
                 "shadow if exists)",
                 console::color::yellow, console::color::reset);
    std::println(
        "  {}msr test <msr_index>{}                - Test if shadowing works",
        console::color::yellow, console::color::reset);
    std::println(
        "  {}msr status{}                          - Show intercept statistics",
        console::color::yellow, console::color::reset);
    std::println("  {}msr intercept <msr_index> [flags]{}   - Enable "
                 "interception (flags: 0=off, 1=read, 2=write, 3=both)",
                 console::color::yellow, console::color::reset);
    std::println("");
    std::println("  {}Workflow:{}", console::color::cyan,
                 console::color::reset);
    std::println("    1. Enable intercept: msr intercept 0xC0000082 3");
    std::println("    2. Add shadow value: msr add 0xC0000082 0xDEADBEEF");
    std::println("    3. Check status:     msr status");
    std::println("");
    std::println("  {}Common MSRs:{}", console::color::cyan,
                 console::color::reset);
    std::println("    0xC0000082  IA32_LSTAR       (SYSCALL handler address)");
    std::println("    0xC0000080  IA32_EFER        (Extended feature enable)");
    std::println("    0x1D9       IA32_DEBUGCTL    (Debug control)");
    std::println("    0x40000000  HV_GUEST_OS_ID   (Hyper-V guest OS ID)");
    std::println("");
    console::warn("IMPORTANT: 'msr intercept' modifies Hyper-V's MSRPM.");
    console::info("Without enabling interception, shadows won't take effect!");
  }
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
// HIDDEN INJECTION COMMANDS
// ============================================================================

CLI::App *init_inject(CLI::App &app) {
  CLI::App *inject = app.add_subcommand("inject", "hidden DLL injection")
                         ->ignore_case()
                         ->alias("hid");

  inject->add_subcommand("dll", "inject a DLL into target process");
  inject->add_subcommand("list", "list all injected DLLs");
  inject->add_subcommand("hide", "hide an injected DLL");
  inject->add_subcommand("show", "re-expose a hidden DLL");
  inject->add_subcommand("eject", "eject (unload) an injected DLL");
  inject->add_subcommand("findcr3", "find process CR3 by name");
  inject->add_subcommand("exec", "execute DLL via hook (no thread creation)");

  // inject dll <dll_path> <process_name|cr3> [--base <addr>]
  add_command_option(inject->get_subcommand("dll"), "dll_path")->required();
  add_command_option(inject->get_subcommand("dll"), "target")->required();
  add_command_option(inject->get_subcommand("dll"), "--base");

  // inject hide <region_id>
  add_command_option(inject->get_subcommand("hide"), "region_id")->required();

  // inject show <region_id> <cr3>
  add_command_option(inject->get_subcommand("show"), "region_id")->required();
  add_command_option(inject->get_subcommand("show"), "cr3")->required();

  // inject eject <region_id>
  add_command_option(inject->get_subcommand("eject"), "region_id")->required();

  // inject findcr3 <process_name>
  add_command_option(inject->get_subcommand("findcr3"), "process_name")
      ->required();

  // inject exec <entry_point> <base> <hook_func> <cr3>
  add_command_option(inject->get_subcommand("exec"), "entry_point")->required();
  add_command_option(inject->get_subcommand("exec"), "base")->required();
  add_command_option(inject->get_subcommand("exec"), "hook_func")->required();
  add_command_option(inject->get_subcommand("exec"), "cr3")->required();

  return inject;
}

void process_inject(CLI::App *inject) {
  auto *dll_cmd = inject->get_subcommand("dll");
  auto *list_cmd = inject->get_subcommand("list");
  auto *hide_cmd = inject->get_subcommand("hide");
  auto *show_cmd = inject->get_subcommand("show");
  auto *eject_cmd = inject->get_subcommand("eject");
  auto *findcr3_cmd = inject->get_subcommand("findcr3");

  if (*dll_cmd) {
    const std::string dll_path =
        get_command_option<std::string>(dll_cmd, "dll_path");
    const std::string target =
        get_command_option<std::string>(dll_cmd, "target");
    const std::uint64_t base_addr =
        get_command_option<std::uint64_t>(dll_cmd, "--base");

    std::println("");
    console::separator("Hidden DLL Injection");

    // Load DLL file
    console::info(std::format("Loading DLL: {}", dll_path));
    std::vector<uint8_t> dll_data = hidden_inject::load_dll_file(dll_path);

    if (dll_data.empty()) {
      console::error("Failed to load DLL file", "check path and permissions");
      return;
    }

    console::success(std::format("Loaded {} bytes", dll_data.size()));

    // Validate DLL
    if (!hidden_inject::validate_dll(dll_data)) {
      console::error("Invalid DLL", "must be a valid x64 Windows DLL");
      return;
    }

    // Determine target CR3
    uint64_t target_cr3 = 0;

    // Check if target is a hex number (CR3) or process name
    if (target.size() > 2 && target[0] == '0' &&
        (target[1] == 'x' || target[1] == 'X')) {
      target_cr3 = std::stoull(target, nullptr, 16);
      console::info(std::format("Using provided CR3: 0x{:X}", target_cr3));
    } else {
      // It's a process name, find its CR3
      console::info(std::format("Finding CR3 for process: {}", target));
      target_cr3 = hidden_inject::find_process_cr3(target, 10000);

      if (target_cr3 == 0) {
        console::error("Failed to find process CR3");
        return;
      }
    }

    // Perform injection
    hidden_inject::injection_info_t info = {};
    auto result = hidden_inject::inject_hidden_dll(dll_data, target_cr3,
                                                   base_addr, false, &info);

    if (result == hidden_inject::inject_result_t::success) {
      console::success("DLL injected successfully!");
      std::println("");
      console::info("The DLL is now mapped in hidden memory.");
      console::info("It is INVISIBLE to the target process and OS.");
      console::info("Only visible when target CR3 is active.");
      std::println("");
      console::warn("Note: DllMain not called automatically.");
      console::info("To execute, create a remote thread at entry point.");
    } else {
      console::error(
          std::format("Injection failed with code: {}", (int)result));
    }

  } else if (*list_cmd) {
    auto dlls = hidden_inject::get_injected_dlls();

    std::println("");
    if (dlls.empty()) {
      console::info("No DLLs currently injected.");
    } else {
      console::separator("Injected DLLs");
      std::println("  {:>4}  {:>18}  {:>18}  {:>10}  {}", "ID", "IMAGE BASE",
                   "ENTRY POINT", "SIZE", "STATUS");
      console::separator();

      for (const auto &dll : dlls) {
        std::println("  {:>4}  0x{:016X}  0x{:016X}  {:>10}  {}", dll.region_id,
                     dll.image_base, dll.entry_point, dll.size_of_image,
                     dll.is_exposed ? "EXPOSED" : "HIDDEN");
      }
    }
    std::println("");

  } else if (*hide_cmd) {
    const std::uint64_t region_id =
        get_command_option<std::uint64_t>(hide_cmd, "region_id");

    auto result = hidden_inject::hide_dll(region_id);

    if (result == hidden_inject::inject_result_t::success) {
      console::success(
          std::format("DLL {} is now HIDDEN from all processes", region_id));
    } else {
      console::error("Failed to hide DLL");
    }

  } else if (*show_cmd) {
    const std::uint64_t region_id =
        get_command_option<std::uint64_t>(show_cmd, "region_id");
    const std::uint64_t cr3 =
        get_command_option<std::uint64_t>(show_cmd, "cr3");

    auto result = hidden_inject::expose_dll(region_id, cr3);

    if (result == hidden_inject::inject_result_t::success) {
      console::success(
          std::format("DLL {} is now EXPOSED to CR3 0x{:X}", region_id, cr3));
    } else {
      console::error("Failed to expose DLL");
    }

  } else if (*eject_cmd) {
    const std::uint64_t region_id =
        get_command_option<std::uint64_t>(eject_cmd, "region_id");

    auto result = hidden_inject::eject_dll(region_id);

    if (result == hidden_inject::inject_result_t::success) {
      console::success(
          std::format("DLL {} ejected and memory freed", region_id));
    } else {
      console::error("Failed to eject DLL");
    }

  } else if (*findcr3_cmd) {
    const std::string process_name =
        get_command_option<std::string>(findcr3_cmd, "process_name");

    std::println("");
    console::info(std::format("Searching for process: {}", process_name));
    console::info("Waiting for process to execute (timeout: 10s)...");
    std::println("");

    uint64_t cr3 = hidden_inject::find_process_cr3(process_name, 10000);

    if (cr3 != 0) {
      console::success(std::format("Found CR3: 0x{:X}", cr3));
      std::println("");
      console::info("Use this CR3 with 'inject dll' command:");
      std::println("  inject dll <path.dll> 0x{:X}", cr3);
    }
    std::println("");

  } else if (*inject->get_subcommand("exec")) {
    // Execute DLL via hook (no thread creation)
    auto *exec_cmd = inject->get_subcommand("exec");
    const std::uint64_t entry_point =
        get_command_option<std::uint64_t>(exec_cmd, "entry_point");
    const std::uint64_t base =
        get_command_option<std::uint64_t>(exec_cmd, "base");
    const std::uint64_t hook_func =
        get_command_option<std::uint64_t>(exec_cmd, "hook_func");
    const std::uint64_t cr3 =
        get_command_option<std::uint64_t>(exec_cmd, "cr3");

    std::println("");
    console::separator("Hook-Based DLL Execution");
    console::info("This method executes your DLL WITHOUT creating threads!");
    console::info(
        "Instead, it hooks a game function and runs your code when called.");
    std::println("");

    console::info(std::format("DLL Entry Point: 0x{:X}", entry_point));
    console::info(std::format("DLL Base:        0x{:X}", base));
    console::info(std::format("Hook Function:   0x{:X}", hook_func));
    console::info(std::format("Target CR3:      0x{:X}", cr3));
    std::println("");

    bool result = hook_exec::call_dll_entry(entry_point, base, hook_func, cr3);

    if (result) {
      console::success("Execution hook installed!");
      std::println("");
      console::info("Your DLL's DllMain will be called when the game");
      console::info("next calls the hooked function.");
      console::info("");
      console::warn("IMPORTANT: The hook function must be one that the game");
      console::warn("calls frequently (like a render function or game loop).");
    } else {
      console::error("Failed to install execution hook");
    }
    std::println("");
  }
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

  // Process CR3 tracking commands
  CLI::App *track = init_track(app);

  // Analysis commands
  CLI::App *hfpc = init_hfpc(app);
  CLI::App *lkm = init_lkm(app);
  CLI::App *kme = init_kme(app);
  CLI::App *dkm = init_dkm(app);
  CLI::App *gva = init_gva(app, aliases_transformer);

  // MSR Shadow commands (AMD only)
  CLI::App *msr = init_msr(app);

  // Hidden DLL injection commands
  CLI::App *inject = init_inject(app);

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

    // Process CR3 tracking
    d_process_command(track);

    // MSR Shadow (AMD only)
    d_process_command(msr);

    // Hidden DLL injection
    d_process_command(inject);

    // Analysis
    d_process_command(hfpc);
    d_process_command(lkm);
    d_process_command(kme);
    d_process_command(dkm);
    d_process_command(gva);
  } catch (const CLI::ParseError &error) {
    app.exit(error);
  }
}
