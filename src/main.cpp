#include "tenriff_server/TcpServer.h"
#include "tenriff_server/HttpApiServer.h"
#include "tenriff_server/OnlineRecordStore.h"

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
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
        << "TenRiff Server 0.2.0-dev\n"
        << "Usage: tenriff-server [options]\n\n"
        << "  --bind <IPv4>       Game/API listen address (default: 0.0.0.0)\n"
        << "  --port <port>       Game protocol TCP port (default: 27300)\n"
        << "  --api-port <port>   Read-only records HTTP port (default: 27302)\n"
        << "  --records <path>    Verified BMS records JSONL snapshot\n"
        << "  --name <text>       Server name (max 64 UTF-8 bytes)\n"
        << "  --help              Show this help\n";
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
    tenriff::server::HttpApiOptions api_options;
    std::string records_path;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            print_help();
            return 0;
        }
        if ((argument == "--bind" || argument == "--port" ||
             argument == "--api-port" || argument == "--records" ||
             argument == "--name") && index + 1 >= argc) {
            std::cerr << argument << " requires a value.\n";
            return 2;
        }
        if (argument == "--bind") {
            options.bind_address = argv[++index];
            api_options.bind_address = options.bind_address;
        } else if (argument == "--port") {
            if (!parse_port(argv[++index], options.port)) {
                std::cerr << "--port must be between 1 and 65535.\n";
                return 2;
            }
        } else if (argument == "--api-port") {
            if (!parse_port(argv[++index], api_options.port)) {
                std::cerr << "--api-port must be between 1 and 65535.\n";
                return 2;
            }
        } else if (argument == "--records") {
            records_path = argv[++index];
            if (records_path.empty()) {
                std::cerr << "--records must not be empty.\n";
                return 2;
            }
        } else if (argument == "--name") {
            options.name = argv[++index];
            if (options.name.empty() || options.name.size() > 64) {
                std::cerr << "--name must contain 1..64 UTF-8 bytes.\n";
                return 2;
            }
            api_options.server_name = options.name;
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

    tenriff::server::OnlineRecordStore records;
    std::string error;
    if (!records.load_json_lines(records_path, error)) {
        std::cerr << "TenRiff Server failed: " << error << "\n";
        return 1;
    }
    std::cout << "[TenRiff-Server] Loaded " << records.record_count()
              << " verified BMS records; ignored " << records.ignored_count()
              << " ineligible records.\n";

    tenriff::server::HttpApiServer api(std::move(api_options), records);
    bool api_ok = false;
    std::string api_error;
    std::atomic_bool api_finished{false};
    std::thread api_worker([&] {
        api_ok = api.run(g_stop_requested, api_error);
        api_finished.store(true, std::memory_order_release);
        if (!api_ok) g_stop_requested.store(true, std::memory_order_release);
    });
    const auto api_deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(5);
    while (api.bound_port() == 0 &&
           !api_finished.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < api_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (api.bound_port() == 0) {
        g_stop_requested.store(true, std::memory_order_release);
        api_worker.join();
        std::cerr << "TenRiff Server failed: "
                  << (api_error.empty() ? "Records API did not start." : api_error)
                  << "\n";
        return 1;
    }

    tenriff::server::TcpServer server(std::move(options));
    const bool game_ok = server.run(g_stop_requested, error);
    g_stop_requested.store(true, std::memory_order_release);
    api_worker.join();
    if (!game_ok) {
        std::cerr << "TenRiff Server failed: " << error << "\n";
        return 1;
    }
    if (!api_ok) {
        std::cerr << "TenRiff Server failed: " << api_error << "\n";
        return 1;
    }
    return 0;
}
