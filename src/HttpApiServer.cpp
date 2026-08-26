#include "tenriff_server/HttpApiServer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <iostream>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tenriff::server {
namespace {

constexpr auto kPollInterval = std::chrono::milliseconds(25);
constexpr auto kClientTimeout = std::chrono::seconds(5);
constexpr std::size_t kMaximumRequestBytes = 16 * 1024;
constexpr std::size_t kMaximumLeaderboardLimit = 100;

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
using SocketLength = int;
int socket_error() { return WSAGetLastError(); }
bool would_block(int error) { return error == WSAEWOULDBLOCK; }
void close_socket(NativeSocket socket) { closesocket(socket); }
void shutdown_socket(NativeSocket socket) { shutdown(socket, SD_BOTH); }
class SocketRuntime {
public:
    SocketRuntime() {
        WSADATA data{};
        ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~SocketRuntime() { if (ok_) WSACleanup(); }
    [[nodiscard]] bool ok() const { return ok_; }
private:
    bool ok_ = false;
};
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
using SocketLength = socklen_t;
int socket_error() { return errno; }
bool would_block(int error) { return error == EAGAIN || error == EWOULDBLOCK; }
void close_socket(NativeSocket socket) { close(socket); }
void shutdown_socket(NativeSocket socket) { shutdown(socket, SHUT_RDWR); }
class SocketRuntime {
public:
    [[nodiscard]] bool ok() const { return true; }
};
#endif

std::string socket_error_text(const char* operation, int code) {
    std::ostringstream output;
    output << operation << " failed (socket error " << code << ").";
    return output.str();
}

class SocketHandle {
public:
    SocketHandle() = default;
    explicit SocketHandle(NativeSocket value) : value_(value) {}
    ~SocketHandle() { reset(); }
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;
    SocketHandle(SocketHandle&& other) noexcept
        : value_(std::exchange(other.value_, kInvalidSocket)) {}
    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, kInvalidSocket);
        }
        return *this;
    }
    [[nodiscard]] bool valid() const { return value_ != kInvalidSocket; }
    [[nodiscard]] NativeSocket get() const { return value_; }
    void reset() {
        if (valid()) close_socket(std::exchange(value_, kInvalidSocket));
    }
private:
    NativeSocket value_ = kInvalidSocket;
};

bool set_nonblocking(NativeSocket socket, std::string& error) {
#ifdef _WIN32
    u_long enabled = 1;
    if (ioctlsocket(socket, FIONBIO, &enabled) == SOCKET_ERROR) {
        error = socket_error_text("ioctlsocket", socket_error());
        return false;
    }
#else
    const int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        error = socket_error_text("fcntl", socket_error());
        return false;
    }
#endif
    return true;
}

std::string escape_json(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8);
    for (const unsigned char byte : value) {
        if (byte == '"') result += "\\\"";
        else if (byte == '\\') result += "\\\\";
        else if (byte == '\n') result += "\\n";
        else if (byte == '\r') result += "\\r";
        else if (byte == '\t') result += "\\t";
        else if (byte >= 0x20) result.push_back(static_cast<char>(byte));
    }
    return result;
}

std::string http_response(int status,
                          std::string_view status_text,
                          std::string body) {
    std::ostringstream output;
    output << "HTTP/1.1 " << status << ' ' << status_text << "\r\n"
           << "Content-Type: application/json; charset=utf-8\r\n"
           << "Cache-Control: no-store\r\n"
           << "X-Content-Type-Options: nosniff\r\n"
           << "Connection: close\r\n"
           << "Content-Length: " << body.size() << "\r\n\r\n"
           << body;
    return output.str();
}

std::string json_error(int status, std::string_view text, std::string_view message) {
    return http_response(status, text,
                         "{\"error\":\"" + escape_json(message) + "\"}");
}

std::size_t parse_limit(std::string_view query) {
    std::size_t limit = 50;
    while (!query.empty()) {
        const auto separator = query.find('&');
        const auto item = query.substr(0, separator);
        if (item.rfind("limit=", 0) == 0) {
            unsigned value = 0;
            const auto digits = item.substr(6);
            const auto parsed = std::from_chars(digits.data(),
                                                digits.data() + digits.size(),
                                                value);
            if (parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size() &&
                value > 0) {
                limit = std::min<std::size_t>(value, kMaximumLeaderboardLimit);
            }
        }
        if (separator == std::string_view::npos) break;
        query.remove_prefix(separator + 1);
    }
    return limit;
}

struct Client {
    SocketHandle socket;
    std::string request;
    std::string response;
    std::size_t sent = 0;
    std::chrono::steady_clock::time_point accepted_at =
        std::chrono::steady_clock::now();
};

}  // namespace

struct HttpApiServer::Impl {
    Impl(HttpApiOptions value, const OnlineRecordStore& value_records)
        : options(std::move(value)), records(value_records) {}

    HttpApiOptions options;
    const OnlineRecordStore& records;
    std::atomic<std::uint16_t> listening_port{0};

    SocketHandle create_listener(std::string& error) {
        SocketHandle listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!listener.valid()) {
            error = socket_error_text("socket", socket_error());
            return {};
        }
#ifdef _WIN32
        const int exclusive = 1;
        if (setsockopt(listener.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive),
                       static_cast<SocketLength>(sizeof(exclusive))) < 0) {
            error = socket_error_text("setsockopt(SO_EXCLUSIVEADDRUSE)",
                                      socket_error());
            return {};
        }
#else
        const int reuse = 1;
        if (setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &reuse,
                       static_cast<SocketLength>(sizeof(reuse))) < 0) {
            error = socket_error_text("setsockopt(SO_REUSEADDR)", socket_error());
            return {};
        }
#endif
        if (!set_nonblocking(listener.get(), error)) return {};
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(options.port);
        if (inet_pton(AF_INET, options.bind_address.c_str(), &address.sin_addr) != 1) {
            error = "HTTP API bind address must be an IPv4 address.";
            return {};
        }
        if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address),
                 static_cast<SocketLength>(sizeof(address))) < 0) {
            error = socket_error_text("bind", socket_error());
            return {};
        }
        if (listen(listener.get(), 32) < 0) {
            error = socket_error_text("listen", socket_error());
            return {};
        }
        sockaddr_in bound{};
        SocketLength bound_size = static_cast<SocketLength>(sizeof(bound));
        if (getsockname(listener.get(), reinterpret_cast<sockaddr*>(&bound),
                        &bound_size) < 0) {
            error = socket_error_text("getsockname", socket_error());
            return {};
        }
        listening_port.store(ntohs(bound.sin_port), std::memory_order_release);
        return listener;
    }

    std::string route(std::string_view request) const {
        const auto line_end = request.find("\r\n");
        if (line_end == std::string_view::npos) {
            return json_error(400, "Bad Request", "Malformed HTTP request.");
        }
        const auto first_line = request.substr(0, line_end);
        const auto first_space = first_line.find(' ');
        const auto second_space = first_line.find(' ', first_space + 1);
        if (first_space == std::string_view::npos ||
            second_space == std::string_view::npos) {
            return json_error(400, "Bad Request", "Malformed HTTP request line.");
        }
        if (first_line.substr(0, first_space) != "GET") {
            return json_error(405, "Method Not Allowed", "Only GET is supported.");
        }
        auto target = first_line.substr(first_space + 1,
                                        second_space - first_space - 1);
        const auto query_at = target.find('?');
        const auto path = target.substr(0, query_at);
        const auto query = query_at == std::string_view::npos
                               ? std::string_view{}
                               : target.substr(query_at + 1);
        if (path == "/healthz") {
            return http_response(200, "OK", "{\"status\":\"ok\"}");
        }
        if (path == "/v1/server-info") {
            return http_response(
                200, "OK",
                "{\"schema_version\":1,\"name\":\"" +
                    escape_json(options.server_name) +
                    "\",\"ranked_uploads\":false,\"ranked_formats\":[\"bms\"]}");
        }
        constexpr std::string_view prefix = "/v1/leaderboards/";
        if (path.rfind(prefix, 0) == 0) {
            const std::string hash(path.substr(prefix.size()));
            if (!is_sha256_hex(hash)) {
                return json_error(400, "Bad Request",
                                  "A 64-character SHA-256 chart hash is required.");
            }
            return http_response(200, "OK",
                                 online_records_json(
                                     hash, records.leaderboard(hash, parse_limit(query))));
        }
        return json_error(404, "Not Found", "Unknown endpoint.");
    }

    bool run(std::atomic_bool& stop_requested, std::string& error) {
        SocketRuntime runtime;
        if (!runtime.ok()) {
            error = "Could not initialize the HTTP socket runtime.";
            return false;
        }
        SocketHandle listener = create_listener(error);
        if (!listener.valid()) return false;
        std::cout << "[TenRiff-Server] Records API listening on "
                  << options.bind_address << ':' << listening_port.load()
                  << " (read-only, BMS online_verified only)." << std::endl;

        std::vector<Client> clients;
        clients.reserve(32);
        while (!stop_requested.load(std::memory_order_acquire)) {
            fd_set read_set;
            fd_set write_set;
            fd_set except_set;
            FD_ZERO(&read_set);
            FD_ZERO(&write_set);
            FD_ZERO(&except_set);
            FD_SET(listener.get(), &read_set);
            FD_SET(listener.get(), &except_set);
            NativeSocket maximum = listener.get();
            for (auto& client : clients) {
                if (client.response.empty()) FD_SET(client.socket.get(), &read_set);
                else FD_SET(client.socket.get(), &write_set);
                FD_SET(client.socket.get(), &except_set);
                maximum = std::max(maximum, client.socket.get());
            }
            timeval timeout{};
            timeout.tv_usec = static_cast<long>(
                std::chrono::duration_cast<std::chrono::microseconds>(kPollInterval)
                    .count());
            const int selected = select(
#ifdef _WIN32
                0,
#else
                maximum + 1,
#endif
                &read_set, &write_set, &except_set, &timeout);
            if (selected < 0) {
                error = socket_error_text("select", socket_error());
                listening_port.store(0, std::memory_order_release);
                return false;
            }

            if (FD_ISSET(listener.get(), &read_set)) {
                for (;;) {
                    sockaddr_in remote{};
                    SocketLength size = static_cast<SocketLength>(sizeof(remote));
                    SocketHandle accepted(accept(
                        listener.get(), reinterpret_cast<sockaddr*>(&remote), &size));
                    if (!accepted.valid()) {
                        const int code = socket_error();
                        if (would_block(code)) break;
                        error = socket_error_text("accept", code);
                        listening_port.store(0, std::memory_order_release);
                        return false;
                    }
                    std::string nonblocking_error;
                    if (!set_nonblocking(accepted.get(), nonblocking_error)) {
                        continue;
                    }
                    if (clients.size() >= 32) {
                        shutdown_socket(accepted.get());
                        continue;
                    }
                    Client client;
                    client.socket = std::move(accepted);
                    client.request.reserve(2048);
                    clients.push_back(std::move(client));
                }
            }

            const auto now = std::chrono::steady_clock::now();
            std::vector<std::size_t> remove;
            for (std::size_t index = 0; index < clients.size(); ++index) {
                auto& client = clients[index];
                bool drop = FD_ISSET(client.socket.get(), &except_set) != 0 ||
                            now - client.accepted_at >= kClientTimeout;
                if (!drop && client.response.empty() &&
                    FD_ISSET(client.socket.get(), &read_set)) {
                    std::array<char, 4096> buffer{};
                    const int received = recv(client.socket.get(), buffer.data(),
                                              static_cast<int>(buffer.size()), 0);
                    if (received <= 0) {
                        if (received == 0 || !would_block(socket_error())) drop = true;
                    } else {
                        client.request.append(buffer.data(),
                                              static_cast<std::size_t>(received));
                        if (client.request.size() > kMaximumRequestBytes) {
                            client.response = json_error(
                                413, "Payload Too Large", "HTTP request is too large.");
                        } else if (client.request.find("\r\n\r\n") !=
                                   std::string::npos) {
                            client.response = route(client.request);
                        }
                    }
                }
                if (!drop && !client.response.empty() &&
                    FD_ISSET(client.socket.get(), &write_set)) {
                    const auto remaining = client.response.size() - client.sent;
                    const int sent = send(
                        client.socket.get(), client.response.data() + client.sent,
                        static_cast<int>(remaining), 0);
                    if (sent > 0) {
                        client.sent += static_cast<std::size_t>(sent);
                        if (client.sent == client.response.size()) drop = true;
                    } else if (sent == 0 || !would_block(socket_error())) {
                        drop = true;
                    }
                }
                if (drop) remove.push_back(index);
            }
            for (auto iterator = remove.rbegin(); iterator != remove.rend(); ++iterator) {
                shutdown_socket(clients[*iterator].socket.get());
                clients.erase(clients.begin() + static_cast<std::ptrdiff_t>(*iterator));
            }
        }
        for (auto& client : clients) shutdown_socket(client.socket.get());
        listening_port.store(0, std::memory_order_release);
        std::cout << "[TenRiff-Server] Records API stopped." << std::endl;
        return true;
    }
};

HttpApiServer::HttpApiServer(HttpApiOptions options,
                             const OnlineRecordStore& records)
    : impl_(new Impl(std::move(options), records)) {}

HttpApiServer::~HttpApiServer() { delete impl_; }

bool HttpApiServer::run(std::atomic_bool& stop_requested, std::string& error) {
    return impl_->run(stop_requested, error);
}

std::uint16_t HttpApiServer::bound_port() const {
    return impl_->listening_port.load(std::memory_order_acquire);
}

}  // namespace tenriff::server
