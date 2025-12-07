#include <Windows.h>
#include <format>
#include <iostream>
#include <print>
#include <string>
#include <thread>

#include "commands/commands.h"
#include "hook/hook.h"
#include "system/system.h"
#include "util/console.h"

void enable_ansi_colors() {
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD dwMode = 0;
  GetConsoleMode(hOut, &dwMode);
  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  SetConsoleMode(hOut, dwMode);
}

std::int32_t main() {
  enable_ansi_colors();

  if (sys::set_up() == 0) {
    std::system("pause");
    return 1;
  }

  // Show minimal status on start
  console::info(std::format("CR3: 0x{:X} | Modules: {} | Type '?' for help",
                            sys::current_cr3,
                            sys::kernel::modules_list.size()));
  std::println("");

  while (true) {
    // Minimal prompt with module count context
    std::print("{}hyper{} {}>{} ", console::color::cyan, console::color::reset,
               console::color::dim, console::color::reset);

    std::string command = {};
    std::getline(std::cin, command);

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

  sys::clean_up();

  return 0;
}
