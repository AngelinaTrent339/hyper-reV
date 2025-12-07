#include <Windows.h>
#include <atomic>
#include <format>
#include <iostream>
#include <print>
#include <string>
#include <thread>


#include "commands/commands.h"
#include "hook/hook.h"
#include "system/system.h"
#include "util/console.h"

// Global flag for clean shutdown
std::atomic<bool> g_should_exit{false};
std::atomic<bool> g_cleanup_done{false};

void enable_ansi_colors() {
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD dwMode = 0;
  GetConsoleMode(hOut, &dwMode);
  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  SetConsoleMode(hOut, dwMode);
}

void enable_utf8_console() {
  // Set console output to UTF-8 for proper Unicode box-drawing characters
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);

  // Also set the console font to one that supports Unicode if possible
  CONSOLE_FONT_INFOEX cfi = {};
  cfi.cbSize = sizeof(cfi);
  cfi.nFont = 0;
  cfi.dwFontSize.X = 0;
  cfi.dwFontSize.Y = 16;
  cfi.FontFamily = FF_DONTCARE;
  cfi.FontWeight = FW_NORMAL;
  wcscpy_s(cfi.FaceName, L"Consolas");
  SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);
}

void do_cleanup() {
  if (g_cleanup_done.exchange(true) == false) {
    std::println("\n{}[!]{} Cleaning up hooks before exit...",
                 console::color::yellow, console::color::reset);
    sys::clean_up();
    std::println("{}[+]{} Cleanup complete. Safe to exit.",
                 console::color::green, console::color::reset);
  }
}

// Console control handler - catches Ctrl+C, Ctrl+Break, window close, etc.
BOOL WINAPI console_handler(DWORD ctrl_type) {
  switch (ctrl_type) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    // CRITICAL: Must clean up hooks before exit!
    // Otherwise kernel will jump to freed usermode memory -> BSOD
    do_cleanup();

    // For close/logoff/shutdown, we need to wait a bit for cleanup
    // and then allow the default handler to terminate
    if (ctrl_type != CTRL_C_EVENT && ctrl_type != CTRL_BREAK_EVENT) {
      Sleep(1000); // Give cleanup time to complete
    }

    g_should_exit = true;
    return TRUE; // We handled it

  default:
    return FALSE;
  }
}

std::int32_t main() {
  enable_ansi_colors();
  enable_utf8_console();

  // Register console control handler BEFORE setting up hooks
  if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
    console::error("Failed to set console control handler");
    console::warn("WARNING: Ctrl+C or closing window may crash the system!");
  }

  if (sys::set_up() == 0) {
    std::system("pause");
    return 1;
  }

  // Show minimal status on start
  console::info(std::format("CR3: 0x{:X} | Modules: {} | Type '?' for help",
                            sys::current_cr3,
                            sys::kernel::modules_list.size()));
  std::println("");
  console::warn(
      "Use 'exit' command or Ctrl+C to quit safely. DO NOT close window!");

  while (!g_should_exit) {
    // Minimal prompt with module count context
    std::print("{}hyper{} {}>{} ", console::color::cyan, console::color::reset,
               console::color::dim, console::color::reset);

    std::string command = {};

    // Handle Ctrl+C during input
    if (!std::getline(std::cin, command)) {
      if (g_should_exit)
        break;
      std::cin.clear();
      continue;
    }

    if (command == "exit" || command == "quit" || command == "q") {
      break;
    }

    if (command == "cls" || command == "clear") {
      std::system("cls");
      continue;
    }

    commands::process(command);

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }

  do_cleanup();

  return 0;
}
