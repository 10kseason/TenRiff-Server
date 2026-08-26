#include "tenriff_server/TcpServer.h"

#include <atomic>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

std::atomic_bool g_stop_requested{false};

#ifdef _WIN32
BOOL WINAPI console_handler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT ||
        event == CTRL_CLOSE_EVENT || event == CTRL_SHUTDOWN_EVENT) {
        g_stop_requested.store(true, std::memory_order_release);
        return TRUE;
    }
    return FALSE;
}
#else
void signal_handler(int) {
    g_stop_requested.store(true, std::memory_order_release);
}
#endif

void print_help() {
    std::cout
        << "TenRiff Server 0.1.0\n"
        << "Usage: tenriff-server [options]\n\n"
        << "  --bind <IPv4>   Listen address (default: 0.0.0.0)\n"
        << "  --port <port>   TCP port (default: 27300)\n"
        << "  --name <text>   Server handshake name (max 64 UTF-8 bytes)\n"
        << "  --help          Show this help\n";
}

bool parse_port(const std::string& text, std::uint16_t& port) {
    unsigned value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
        value == 0 || value > 65535u) {
        return false;
    }
    port = static_cast<std::uint16_t>(value);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    tenriff::server::ServerOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            print_help();
            return 0;
        }
        if ((argument == "--bind" || argument == "--port" ||
             argument == "--name") && index + 1 >= argc) {
            std::cerr << argument << " requires a value.\n";
            return 2;
        }
        if (argument == "--bind") {
            options.bind_address = argv[++index];
        } else if (argument == "--port") {
            if (!parse_port(argv[++index], options.port)) {
                std::cerr << "--port must be between 1 and 65535.\n";
                return 2;
            }
        } else if (argument == "--name") {
            options.name = argv[++index];
            if (options.name.empty() || options.name.size() > 64) {
                std::cerr << "--name must contain 1..64 UTF-8 bytes.\n";
                return 2;
            }
        } else {
            std::cerr << "Unknown option: " << argument << "\n";
            return 2;
        }
    }

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
#endif

    tenriff::server::TcpServer server(std::move(options));
    std::string error;
    if (!server.run(g_stop_requested, error)) {
        std::cerr << "TenRiff Server failed: " << error << "\n";
        return 1;
    }
    return 0;
}
