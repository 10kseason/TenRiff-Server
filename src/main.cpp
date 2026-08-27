#include "tenriff_server/BmsCatalog.h"
#include "tenriff_server/TcpServer.h"
#include "tenriff_server/HttpApiServer.h"
#include "tenriff_server/OnlineRecordStore.h"
#include "tenriff_server/RankedDatabase.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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
        << "TenRiff Server 1.1.3\n"
        << "Usage: tenriff-server [options]\n\n"
        << "  --bind <IPv4>       Game protocol listen address (default: 0.0.0.0)\n"
        << "  --api-bind <IPv4>   HTTP API listen address (default: 127.0.0.1)\n"
        << "  --port <port>       Game protocol TCP port (default: 27301)\n"
        << "  --api-port <port>   Account/records HTTP port (default: 27302)\n"
        << "  --records <path>    Verified BMS records JSONL snapshot\n"
        << "  --database <path>   SQLite ranked database\n"
        << "  --receipt-secret-file <path>  File containing 32+ byte receipt HMAC secret\n"
        << "  --verifier <path>   tenriff-replay-verifier executable\n"
        << "  --replay-staging <path>  Temporary replay evidence directory\n"
        << "  --approve-chart <sha256=path> Add/update approved BMS chart (repeatable)\n"
        << "  --approve-chart-file <path> Read SHA256=path catalog lines\n"
        << "  --catalog-file <path> Read lazy SHA256=path availability catalog\n"
        << "  --chart-root <path> Recursively catalog BMS files for lazy ranking\n"
        << "  --exclude-chart-file <path> SHA-256 denylist applied to --chart-root\n"
        << "  --provision-admin <name> Create or rotate an administrator account\n"
        << "  --admin-password-file <path> One-time password file for --provision-admin\n"
        << "  --provision-only    Exit after administrator provisioning\n"
        << "  --trust-proxy-client-ip Trust Caddy's overwritten client-IP header\n"
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
    std::string database_path;
    std::string receipt_secret_file;
    std::string chart_root;
    std::string excluded_chart_file;
    std::string provision_admin;
    std::string admin_password_file;
    bool provision_only = false;
    std::vector<std::pair<std::string, std::string>> approved_charts;
    std::vector<std::pair<std::string, std::string>> available_charts;
    bool available_catalog_requested = false;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            print_help();
            return 0;
        }
        if ((argument == "--bind" || argument == "--api-bind" || argument == "--port" ||
             argument == "--api-port" || argument == "--records" ||
             argument == "--database" || argument == "--receipt-secret-file" ||
             argument == "--verifier" || argument == "--replay-staging" ||
             argument == "--approve-chart" || argument == "--approve-chart-file" ||
             argument == "--catalog-file" ||
             argument == "--chart-root" || argument == "--exclude-chart-file" ||
             argument == "--provision-admin" || argument == "--admin-password-file" ||
             argument == "--name") && index + 1 >= argc) {
            std::cerr << argument << " requires a value.\n";
            return 2;
        }
        if (argument == "--bind") {
            options.bind_address = argv[++index];
        } else if (argument == "--api-bind") {
            api_options.bind_address = argv[++index];
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
        } else if (argument == "--database") {
            database_path = argv[++index];
        } else if (argument == "--receipt-secret-file") {
            receipt_secret_file = argv[++index];
        } else if (argument == "--verifier") {
            api_options.verifier_executable = argv[++index];
        } else if (argument == "--replay-staging") {
            api_options.replay_staging_directory = argv[++index];
        } else if (argument == "--approve-chart") {
            const std::string value = argv[++index];
            const auto equals = value.find('=');
            if (equals == std::string::npos || equals == 0 || equals + 1 >= value.size()) {
                std::cerr << "--approve-chart must be SHA256=local-path.\n";
                return 2;
            }
            approved_charts.emplace_back(value.substr(0, equals), value.substr(equals + 1));
        } else if (argument == "--approve-chart-file") {
            const std::string catalog_path = argv[++index];
            std::ifstream catalog(catalog_path);
            if (!catalog) {
                std::cerr << "Could not open approved chart catalog: " << catalog_path << "\n";
                return 2;
            }
            std::string line;
            while (std::getline(catalog, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line.front() == '#') continue;
                const auto equals = line.find('=');
                if (equals == std::string::npos || equals == 0 || equals + 1 >= line.size()) {
                    std::cerr << "Invalid approved chart catalog line: " << line << "\n";
                    return 2;
                }
                approved_charts.emplace_back(line.substr(0, equals), line.substr(equals + 1));
            }
        } else if (argument == "--catalog-file") {
            const std::string catalog_path = argv[++index];
            std::ifstream catalog(catalog_path);
            if (!catalog) {
                std::cerr << "Could not open BMS availability catalog: " << catalog_path << "\n";
                return 2;
            }
            available_catalog_requested = true;
            std::string line;
            while (std::getline(catalog, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line.front() == '#') continue;
                const auto equals = line.find('=');
                if (equals == std::string::npos || equals == 0 || equals + 1 >= line.size()) {
                    std::cerr << "Invalid BMS availability catalog line: " << line << "\n";
                    return 2;
                }
                available_charts.emplace_back(line.substr(0, equals), line.substr(equals + 1));
            }
        } else if (argument == "--chart-root") {
            chart_root = argv[++index];
        } else if (argument == "--exclude-chart-file") {
            excluded_chart_file = argv[++index];
        } else if (argument == "--provision-admin") {
            provision_admin = argv[++index];
        } else if (argument == "--admin-password-file") {
            admin_password_file = argv[++index];
        } else if (argument == "--provision-only") {
            provision_only = true;
        } else if (argument == "--trust-proxy-client-ip") {
            api_options.trust_proxy_client_ip = true;
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

    if (!excluded_chart_file.empty() && chart_root.empty()) {
        std::cerr << "--exclude-chart-file requires --chart-root.\n";
        return 2;
    }
    if (provision_admin.empty() != admin_password_file.empty()) {
        std::cerr << "--provision-admin and --admin-password-file must be supplied together.\n";
        return 2;
    }
    if (provision_only && provision_admin.empty()) {
        std::cerr << "--provision-only requires --provision-admin.\n";
        return 2;
    }

    if (api_options.bind_address.rfind("127.", 0) != 0 &&
        api_options.bind_address != "::1" &&
        !api_options.trust_proxy_client_ip) {
        std::cerr << "TenRiff Server failed: a non-loopback --api-bind requires "
                     "--trust-proxy-client-ip behind an HTTPS reverse proxy.\n";
        return 2;
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

    tenriff::server::RankedDatabase ranked_database;
    tenriff::server::RankedDatabase* ranked_database_ptr = nullptr;
    if (!database_path.empty() || !receipt_secret_file.empty() ||
        !api_options.verifier_executable.empty() || !approved_charts.empty() ||
        available_catalog_requested || !chart_root.empty() || !provision_admin.empty()) {
        if (database_path.empty() || receipt_secret_file.empty() ||
            (!provision_only && api_options.verifier_executable.empty())) {
            std::cerr << "TenRiff Server failed: --database and --receipt-secret-file are required; "
                         "--verifier is also required unless --provision-only is used.\n";
            return 2;
        }
        std::ifstream secret_input(receipt_secret_file, std::ios::binary);
        const std::string signing_secret((std::istreambuf_iterator<char>(secret_input)),
                                         std::istreambuf_iterator<char>());
        if (!secret_input && signing_secret.empty()) {
            std::cerr << "TenRiff Server failed: could not read receipt secret file.\n";
            return 1;
        }
        if (!ranked_database.open(database_path, signing_secret, error)) {
            std::cerr << "TenRiff Server failed: " << error << "\n";
            return 1;
        }
        if (!provision_admin.empty()) {
            std::ifstream password_input(admin_password_file, std::ios::binary);
            std::string password((std::istreambuf_iterator<char>(password_input)),
                                 std::istreambuf_iterator<char>());
            while (!password.empty() &&
                   (password.back() == '\r' || password.back() == '\n')) {
                password.pop_back();
            }
            if (!password_input && password.empty()) {
                std::cerr << "TenRiff Server failed: could not read administrator password file.\n";
                return 1;
            }
            if (!ranked_database.provision_admin_account(
                    provision_admin, password, error)) {
                std::fill(password.begin(), password.end(), '\0');
                std::cerr << "TenRiff Server failed: " << error << "\n";
                return 1;
            }
            std::fill(password.begin(), password.end(), '\0');
            std::cout << "[TenRiff-Server] Provisioned administrator account '"
                      << provision_admin << "'.\n";
            if (provision_only) return 0;
        }
        if (!chart_root.empty()) {
            tenriff::server::BmsCatalogLoadResult catalog;
            if (!tenriff::server::load_bms_catalog(
                    std::filesystem::u8path(chart_root),
                    excluded_chart_file.empty()
                        ? std::filesystem::path{}
                        : std::filesystem::u8path(excluded_chart_file),
                    catalog, error)) {
                std::cerr << "TenRiff Server failed: " << error << "\n";
                return 1;
            }
            available_charts.reserve(available_charts.size() + catalog.charts.size());
            for (const auto& chart : catalog.charts) {
                available_charts.emplace_back(chart.chart_sha256, chart.chart_path);
            }
            available_catalog_requested = true;
            std::cout << "[TenRiff-Server] Cataloged " << catalog.charts.size()
                      << " BMS files from " << chart_root << "; excluded "
                      << catalog.excluded_count << ", duplicate hashes "
                      << catalog.duplicate_count << ", skipped symlinks "
                      << catalog.skipped_symlink_count << ".\n";
        }
        if (available_catalog_requested &&
            !ranked_database.set_available_bms_catalog(available_charts, error)) {
            std::cerr << "TenRiff Server failed: " << error << "\n";
            return 1;
        }
        for (const auto& approved : approved_charts) {
            if (!ranked_database.approve_bms_chart(approved.first, approved.second, error)) {
                std::cerr << "TenRiff Server failed: " << error << "\n";
                return 1;
            }
        }
        ranked_database_ptr = &ranked_database;
        std::cout << "[TenRiff-Server] Ranked DB migrations applied; "
                  << available_charts.size() << " BMS files available, "
                  << ranked_database.registered_bms_chart_count()
                  << " materialized for leaderboards.\n";
    }

    const auto multiplayer_directory =
        std::make_shared<tenriff::server::MultiplayerDirectory>();
    options.multiplayer_directory = multiplayer_directory;
    api_options.multiplayer_directory = multiplayer_directory;
    tenriff::server::HttpApiServer api(std::move(api_options), records, ranked_database_ptr);
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
