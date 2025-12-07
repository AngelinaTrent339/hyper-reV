#pragma once
#include <string>

namespace commands {
void process(std::string command);

// Cleanup syscall interception on exit (called by sys::clean_up)
void syscall_intercept_cleanup();
} // namespace commands
