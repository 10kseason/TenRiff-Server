#include "tenriff_server/HttpApiServer.h"
#include "tenriff_server/ReplayVerifierProcess.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>
#include <unordered_map>
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
constexpr std::size_t kMaximumRequestBytes = 8 * 1024 * 1024;
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

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
        return static_cast<char>(byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte);
    });
    return value;
}

std::optional<std::string> header_value(std::string_view request,
                                        std::string_view wanted) {
    const auto headers_end = request.find("\r\n\r\n");
    if (headers_end == std::string_view::npos) return std::nullopt;
    std::size_t cursor = request.find("\r\n") + 2;
    const std::string wanted_lower = lower_ascii(std::string(wanted));
    while (cursor < headers_end) {
        const auto end = request.find("\r\n", cursor);
        if (end == std::string_view::npos || end > headers_end) break;
        const auto line = request.substr(cursor, end - cursor);
        const auto colon = line.find(':');
        if (colon != std::string_view::npos &&
            lower_ascii(std::string(line.substr(0, colon))) == wanted_lower) {
            std::size_t begin = colon + 1;
            while (begin < line.size() && (line[begin] == ' ' || line[begin] == '\t')) ++begin;
            std::size_t finish = line.size();
            while (finish > begin && (line[finish - 1] == ' ' || line[finish - 1] == '\t')) --finish;
            return std::string(line.substr(begin, finish - begin));
        }
        cursor = end + 2;
    }
    return std::nullopt;
}

std::optional<std::size_t> request_content_length(std::string_view request) {
    const auto value = header_value(request, "content-length");
    if (!value.has_value()) return std::size_t{0};
    std::size_t length = 0;
    const auto parsed = std::from_chars(value->data(), value->data() + value->size(), length);
    if (parsed.ec != std::errc{} || parsed.ptr != value->data() + value->size()) {
        return std::nullopt;
    }
    return length;
}

bool complete_http_request(std::string_view request) {
    const auto headers_end = request.find("\r\n\r\n");
    if (headers_end == std::string_view::npos) return false;
    const auto length = request_content_length(request);
    return length.has_value() && request.size() >= headers_end + 4 + *length;
}

std::string_view request_body(std::string_view request) {
    const auto headers_end = request.find("\r\n\r\n");
    if (headers_end == std::string_view::npos) return {};
    const auto length = request_content_length(request);
    if (!length.has_value() || request.size() < headers_end + 4 + *length) return {};
    return request.substr(headers_end + 4, *length);
}

std::optional<std::string> json_string(std::string_view object,
                                       std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\"";
    std::size_t cursor = object.find(marker);
    if (cursor == std::string_view::npos) return std::nullopt;
    cursor = object.find(':', cursor + marker.size());
    if (cursor == std::string_view::npos) return std::nullopt;
    ++cursor;
    while (cursor < object.size() && std::isspace(static_cast<unsigned char>(object[cursor])) != 0) ++cursor;
    if (cursor >= object.size() || object[cursor++] != '"') return std::nullopt;
    std::string output;
    while (cursor < object.size()) {
        const unsigned char byte = static_cast<unsigned char>(object[cursor++]);
        if (byte == '"') return output;
        if (byte < 0x20) return std::nullopt;
        if (byte != '\\') {
            output.push_back(static_cast<char>(byte));
            continue;
        }
        if (cursor >= object.size()) return std::nullopt;
        switch (object[cursor++]) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            default: return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<double> json_number(std::string_view object, std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\"";
    std::size_t cursor = object.find(marker);
    if (cursor == std::string_view::npos) return std::nullopt;
    cursor = object.find(':', cursor + marker.size());
    if (cursor == std::string_view::npos) return std::nullopt;
    ++cursor;
    while (cursor < object.size() && std::isspace(static_cast<unsigned char>(object[cursor])) != 0) ++cursor;
    std::size_t end = cursor;
    while (end < object.size() && (std::isdigit(static_cast<unsigned char>(object[end])) != 0 ||
           object[end] == '-' || object[end] == '+' || object[end] == '.' ||
           object[end] == 'e' || object[end] == 'E')) ++end;
    if (end == cursor) return std::nullopt;
    try {
        std::size_t consumed = 0;
        const double value = std::stod(std::string(object.substr(cursor, end - cursor)), &consumed);
        if (consumed != end - cursor || !std::isfinite(value)) return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

bool json_true(std::string_view object, std::string_view key) {
    const std::string marker = "\"" + std::string(key) + "\"";
    const auto key_at = object.find(marker);
    if (key_at == std::string_view::npos) return false;
    const auto colon = object.find(':', key_at + marker.size());
    if (colon == std::string_view::npos) return false;
    std::size_t cursor = colon + 1;
    while (cursor < object.size() && std::isspace(static_cast<unsigned char>(object[cursor])) != 0) ++cursor;
    return object.substr(cursor, 4) == "true";
}

std::optional<std::string> bearer_token(std::string_view request) {
    const auto authorization = header_value(request, "authorization");
    if (!authorization.has_value() || authorization->size() <= 7 ||
        lower_ascii(authorization->substr(0, 7)) != "bearer ") return std::nullopt;
    return authorization->substr(7);
}

std::optional<std::vector<unsigned char>> decode_base64(std::string_view input) {
    static constexpr signed char invalid = -1;
    static const std::array<signed char, 256> table = [] {
        std::array<signed char, 256> value{};
        value.fill(invalid);
        const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (std::size_t index = 0; index < alphabet.size(); ++index) {
            value[static_cast<unsigned char>(alphabet[index])] = static_cast<signed char>(index);
        }
        return value;
    }();
    if (input.empty() || input.size() % 4 != 0) return std::nullopt;
    std::vector<unsigned char> output;
    output.reserve(input.size() / 4 * 3);
    for (std::size_t cursor = 0; cursor < input.size(); cursor += 4) {
        unsigned value = 0;
        int padding = 0;
        for (int index = 0; index < 4; ++index) {
            const unsigned char byte = static_cast<unsigned char>(input[cursor + index]);
            if (byte == '=') {
                ++padding;
                value <<= 6U;
            } else {
                if (padding != 0 || table[byte] == invalid) return std::nullopt;
                value = (value << 6U) | static_cast<unsigned>(table[byte]);
            }
        }
        output.push_back(static_cast<unsigned char>((value >> 16U) & 0xffU));
        if (padding < 2) output.push_back(static_cast<unsigned char>((value >> 8U) & 0xffU));
        if (padding < 1) output.push_back(static_cast<unsigned char>(value & 0xffU));
        if (padding > 2 || (padding != 0 && cursor + 4 != input.size())) return std::nullopt;
    }
    return output;
}

bool constant_time_equal(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        difference |= static_cast<unsigned char>(lhs[index] ^ rhs[index]);
    }
    return difference == 0;
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

std::int64_t parse_after_id(std::string_view query) {
    while (!query.empty()) {
        const auto separator = query.find('&');
        const auto item = query.substr(0, separator);
        if (item.rfind("after_id=", 0) == 0) {
            std::int64_t value = 0;
            const auto digits = item.substr(9);
            const auto parsed = std::from_chars(digits.data(),
                                                digits.data() + digits.size(), value);
            if (parsed.ec == std::errc{} && parsed.ptr == digits.data() + digits.size() &&
                value >= 0) {
                return value;
            }
        }
        if (separator == std::string_view::npos) break;
        query.remove_prefix(separator + 1);
    }
    return 0;
}

std::string global_chat_json(const std::vector<GlobalChatMessage>& messages) {
    std::string body = "{\"messages\":[";
    for (std::size_t index = 0; index < messages.size(); ++index) {
        if (index != 0) body.push_back(',');
        const auto& message = messages[index];
        body += "{\"id\":" + std::to_string(message.id) +
                ",\"username\":\"" + escape_json(message.username) +
                "\",\"role\":\"" + escape_json(message.role) +
                "\",\"text\":\"" + escape_json(message.text) +
                "\",\"created_at_utc\":\"" + escape_json(message.created_at_utc) + "\"}";
    }
    body += "]}";
    return body;
}

struct Client {
    SocketHandle socket;
    std::string request;
    std::string response;
    std::size_t sent = 0;
    std::string remote_address;
    std::chrono::steady_clock::time_point accepted_at =
        std::chrono::steady_clock::now();
};

}  // namespace

struct HttpApiServer::Impl {
    Impl(HttpApiOptions value,
         const OnlineRecordStore& value_records,
         RankedDatabase* value_ranked_database)
        : options(std::move(value)), records(value_records),
          ranked_database(value_ranked_database) {}

    HttpApiOptions options;
    const OnlineRecordStore& records;
    RankedDatabase* ranked_database = nullptr;
    std::atomic<std::uint16_t> listening_port{0};
    struct RateBucket {
        std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
        int requests = 0;
    };
    std::unordered_map<std::string, RateBucket> rate_buckets;

    bool consume_rate_bucket(const std::string& key, int limit) {
        const auto now = std::chrono::steady_clock::now();
        if (rate_buckets.size() > 4096) {
            for (auto iterator = rate_buckets.begin(); iterator != rate_buckets.end();) {
                if (now - iterator->second.started >= std::chrono::minutes(2)) {
                    iterator = rate_buckets.erase(iterator);
                } else {
                    ++iterator;
                }
            }
        }
        auto& bucket = rate_buckets[key];
        if (now - bucket.started >= std::chrono::minutes(1)) {
            bucket.started = now;
            bucket.requests = 0;
        }
        return ++bucket.requests <= limit;
    }

    bool allow_request(const std::string& remote, std::string_view request) {
        const bool sensitive = request.find(" /v1/accounts/") != std::string_view::npos ||
                               request.find(" /v1/challenges") != std::string_view::npos ||
                               request.find(" /v1/replays") != std::string_view::npos;
        return consume_rate_bucket(
            "address:" + remote + (sensitive ? ":sensitive" : ":general"),
            sensitive ? 20 : 180);
    }

    std::string rate_limit_address(const std::string& socket_remote,
                                   std::string_view request) const {
        if (!options.trust_proxy_client_ip) return socket_remote;
        const auto forwarded = header_value(request, "x-tenriff-client-ip");
        if (!forwarded.has_value()) return socket_remote;
        in_addr parsed{};
        return inet_pton(AF_INET, forwarded->c_str(), &parsed) == 1
                   ? *forwarded
                   : socket_remote;
    }

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

    std::string route(std::string_view request) {
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
        const std::string method(first_line.substr(0, first_space));
        auto target = first_line.substr(first_space + 1,
                                        second_space - first_space - 1);
        const auto query_at = target.find('?');
        const auto path = target.substr(0, query_at);
        const auto query = query_at == std::string_view::npos
                               ? std::string_view{}
                               : target.substr(query_at + 1);
        if (method == "POST") {
            if (!header_value(request, "content-length").has_value()) {
                return json_error(411, "Length Required", "POST requests require Content-Length.");
            }
            const auto content_type = header_value(request, "content-type");
            if (!content_type.has_value() ||
                lower_ascii(*content_type).rfind("application/json", 0) != 0) {
                return json_error(415, "Unsupported Media Type", "POST requests require application/json.");
            }
        }
        const bool ranked_ready = ranked_database && ranked_database->ready() &&
                                  !options.verifier_executable.empty();
        if (method == "GET" && path == "/healthz") {
            return http_response(200, "OK", "{\"status\":\"ok\"}");
        }
        if (method == "GET" && path == "/v1/server-info") {
            return http_response(
                200, "OK",
                "{\"schema_version\":1,\"name\":\"" +
                    escape_json(options.server_name) +
                    "\",\"ranked_uploads\":" + (ranked_ready ? "true" : "false") +
                    ",\"ranked_formats\":[\"bms\"],\"tls_required\":true,"
                    "\"replay_verification\":\"server_rerun\"}");
        }
        if (method == "GET" && path == "/v1/multiplayer/rooms") {
            if (!ranked_database || !ranked_database->ready()) {
                return json_error(503, "Service Unavailable",
                                  "Multiplayer account sessions are not configured.");
            }
            const auto token = bearer_token(request);
            if (!token.has_value()) {
                return json_error(401, "Unauthorized", "Bearer token is required.");
            }
            std::string username;
            std::string error;
            if (!ranked_database->validate_session(*token, username, error)) {
                return json_error(401, "Unauthorized", error);
            }
            const MultiplayerRoomStatus room = options.multiplayer_directory
                                                     ? options.multiplayer_directory->snapshot()
                                                     : MultiplayerRoomStatus{};
            if (room.tcp_port == 0) {
                return http_response(200, "OK",
                                     "{\"schema_version\":1,\"rooms\":[]}");
            }
            return http_response(
                200, "OK",
                "{\"schema_version\":1,\"rooms\":[{\"id\":\"" +
                    escape_json(room.id) + "\",\"name\":\"" +
                    escape_json(room.name) + "\",\"tcp_port\":" +
                    std::to_string(room.tcp_port) + ",\"player_count\":" +
                    std::to_string(room.player_count) + ",\"max_players\":" +
                    std::to_string(room.max_players) + ",\"accepting_players\":" +
                    (room.accepting_players ? "true" : "false") +
                    ",\"round_active\":" + (room.round_active ? "true" : "false") +
                    ",\"revision\":" + std::to_string(room.revision) + "}]}");
        }
        constexpr std::string_view prefix = "/v1/leaderboards/";
        if (method == "GET" && path.rfind(prefix, 0) == 0) {
            const std::string hash(path.substr(prefix.size()));
            if (!is_sha256_hex(hash)) {
                return json_error(400, "Bad Request",
                                  "A 64-character SHA-256 chart hash is required.");
            }
            const auto ranked_records = ranked_database && ranked_database->ready()
                                            ? ranked_database->leaderboard(hash, parse_limit(query))
                                            : records.leaderboard(hash, parse_limit(query));
            return http_response(200, "OK", online_records_json(hash, ranked_records));
        }
        if (method == "POST" && path == "/v1/accounts/register") {
            if (!ranked_database || !ranked_database->ready()) {
                return json_error(503, "Service Unavailable", "Ranked accounts are not configured.");
            }
            const auto username = json_string(request_body(request), "username");
            const auto password = json_string(request_body(request), "password");
            if (!username.has_value() || !password.has_value()) {
                return json_error(400, "Bad Request", "username and password strings are required.");
            }
            if (!consume_rate_bucket("account:" + lower_ascii(*username), 10)) {
                return json_error(429, "Too Many Requests", "Per-account request limit exceeded.");
            }
            AccountSession session;
            std::string error;
            if (!ranked_database->register_account(*username, *password, session, error)) {
                const int status = error.find("already") != std::string::npos ? 409 : 422;
                return json_error(status, status == 409 ? "Conflict" : "Unprocessable Content", error);
            }
            return http_response(201, "Created",
                "{\"username\":\"" + escape_json(session.username) +
                "\",\"role\":\"" + escape_json(session.role) +
                "\",\"token\":\"" + session.bearer_token +
                "\",\"expires_at_utc\":\"" + session.expires_at_utc + "\"}");
        }
        if (method == "POST" && path == "/v1/accounts/login") {
            if (!ranked_database || !ranked_database->ready()) {
                return json_error(503, "Service Unavailable", "Ranked accounts are not configured.");
            }
            const auto username = json_string(request_body(request), "username");
            const auto password = json_string(request_body(request), "password");
            if (!username.has_value() || !password.has_value()) {
                return json_error(400, "Bad Request", "username and password strings are required.");
            }
            if (!consume_rate_bucket("account:" + lower_ascii(*username), 10)) {
                return json_error(429, "Too Many Requests", "Per-account request limit exceeded.");
            }
            AccountSession session;
            std::string error;
            if (!ranked_database->login(*username, *password, session, error)) {
                return json_error(401, "Unauthorized", error);
            }
            return http_response(200, "OK",
                "{\"username\":\"" + escape_json(session.username) +
                "\",\"role\":\"" + escape_json(session.role) +
                "\",\"token\":\"" + session.bearer_token +
                "\",\"expires_at_utc\":\"" + session.expires_at_utc + "\"}");
        }
        if (method == "GET" && path == "/v1/chat/messages") {
            if (!ranked_database || !ranked_database->ready()) {
                return json_error(503, "Service Unavailable", "Global chat is not configured.");
            }
            const auto token = bearer_token(request);
            if (!token.has_value()) {
                return json_error(401, "Unauthorized", "Bearer token is required.");
            }
            std::string error;
            const auto messages = ranked_database->global_chat_messages(
                *token, parse_after_id(query), parse_limit(query), error);
            if (!error.empty()) return json_error(401, "Unauthorized", error);
            return http_response(200, "OK", global_chat_json(messages));
        }
        if (method == "POST" && path == "/v1/chat/messages") {
            if (!ranked_database || !ranked_database->ready()) {
                return json_error(503, "Service Unavailable", "Global chat is not configured.");
            }
            const auto token = bearer_token(request);
            const auto text = json_string(request_body(request), "text");
            if (!token.has_value()) {
                return json_error(401, "Unauthorized", "Bearer token is required.");
            }
            if (!text.has_value()) {
                return json_error(400, "Bad Request", "text is required.");
            }
            GlobalChatMessage message;
            std::string error;
            if (!ranked_database->send_global_chat(*token, *text, message, error)) {
                const int status = error.find("wait") != std::string::npos ? 429 :
                                   (error.find("session") != std::string::npos ? 401 : 422);
                return json_error(status,
                                  status == 429 ? "Too Many Requests" :
                                  (status == 401 ? "Unauthorized" : "Unprocessable Content"),
                                  error);
            }
            return http_response(201, "Created", global_chat_json({message}));
        }
        if (method == "POST" && path == "/v1/challenges") {
            if (!ranked_ready) {
                return json_error(503, "Service Unavailable", "Ranked replay verification is not configured.");
            }
            const auto token = bearer_token(request);
            const auto hash = json_string(request_body(request), "chart_sha256");
            if (!token.has_value()) return json_error(401, "Unauthorized", "Bearer token is required.");
            if (!hash.has_value()) return json_error(400, "Bad Request", "chart_sha256 is required.");
            ReplayChallenge challenge;
            std::string error;
            if (!ranked_database->create_challenge(*token, *hash, challenge, error)) {
                const int status = error.find("Authentication") != std::string::npos ? 401 : 422;
                return json_error(status, status == 401 ? "Unauthorized" : "Unprocessable Content", error);
            }
            return http_response(201, "Created",
                "{\"challenge_id\":\"" + challenge.id +
                "\",\"nonce\":\"" + challenge.nonce +
                "\",\"chart_sha256\":\"" + challenge.chart_sha256 +
                "\",\"expires_at_utc\":\"" + challenge.expires_at_utc + "\"}");
        }
        if (method == "POST" && path == "/v1/replays") {
            if (!ranked_ready) {
                return json_error(503, "Service Unavailable", "Ranked replay verification is not configured.");
            }
            const auto token = bearer_token(request);
            const auto challenge_id = json_string(request_body(request), "challenge_id");
            const auto challenge_nonce = json_string(request_body(request), "challenge_nonce");
            const auto replay_base64 = json_string(request_body(request), "replay_base64");
            if (!token.has_value()) return json_error(401, "Unauthorized", "Bearer token is required.");
            if (!challenge_id.has_value() || !challenge_nonce.has_value() || !replay_base64.has_value()) {
                return json_error(400, "Bad Request", "challenge_id, challenge_nonce, and replay_base64 are required.");
            }
            ReplayChallenge challenge;
            std::string error;
            if (!ranked_database->inspect_challenge(*token, *challenge_id, challenge, error)) {
                return json_error(error.find("Authentication") != std::string::npos ? 401 : 409,
                                  error.find("Authentication") != std::string::npos ? "Unauthorized" : "Conflict", error);
            }
            if (!constant_time_equal(*challenge_nonce, challenge.nonce)) {
                return json_error(409, "Conflict", "Replay challenge nonce does not match.");
            }
            const auto replay_bytes = decode_base64(*replay_base64);
            if (!replay_bytes.has_value() || replay_bytes->empty() || replay_bytes->size() > 6 * 1024 * 1024) {
                return json_error(413, "Payload Too Large", "Replay must be valid base64 and at most 6 MiB.");
            }
            std::error_code filesystem_error;
            const std::filesystem::path staging = std::filesystem::u8path(options.replay_staging_directory);
            std::filesystem::create_directories(staging, filesystem_error);
            if (filesystem_error) return json_error(500, "Internal Server Error", "Could not prepare replay staging directory.");
            const std::filesystem::path replay_path = staging / (*challenge_id + ".replay.json");
            {
                std::ofstream output(replay_path, std::ios::binary | std::ios::trunc);
                if (!output) return json_error(500, "Internal Server Error", "Could not stage replay evidence.");
                output.write(reinterpret_cast<const char*>(replay_bytes->data()),
                             static_cast<std::streamsize>(replay_bytes->size()));
                if (!output) return json_error(500, "Internal Server Error", "Could not write replay evidence.");
            }
            const auto cleanup = [&] {
                std::error_code ignored;
                std::filesystem::remove(replay_path, ignored);
            };
            const VerifierProcessResult verification = run_replay_verifier(
                options.verifier_executable, replay_path.u8string(), challenge.chart_path,
                challenge.id, challenge.nonce);
            cleanup();
            if (!verification.launched || verification.timed_out) {
                return json_error(503, "Service Unavailable",
                                  verification.error.empty() ? "Replay verifier failed to launch." : verification.error);
            }
            const auto json_at = verification.output.rfind('{');
            const std::string_view verifier_json = json_at == std::string::npos
                                                       ? std::string_view{}
                                                       : std::string_view(verification.output).substr(json_at);
            const auto status = json_string(verifier_json, "status");
            const auto chart_hash = json_string(verifier_json, "chart_sha256");
            const auto replay_hash = json_string(verifier_json, "replay_sha256");
            const auto score = json_number(verifier_json, "score");
            const auto accuracy = json_number(verifier_json, "accuracy");
            const auto max_combo = json_number(verifier_json, "max_combo");
            const auto clear_status = json_string(verifier_json, "clear_status");
            const auto ruleset_id = json_string(verifier_json, "ruleset_id");
            if (verification.exit_code != 0 || !status.has_value() || *status != "verified" ||
                !json_true(verifier_json, "official_eligible") || !chart_hash.has_value() ||
                !replay_hash.has_value() || !score.has_value() || !accuracy.has_value() ||
                !max_combo.has_value() || !clear_status.has_value() || !ruleset_id.has_value() ||
                *score < 0.0 || *score > static_cast<double>((std::numeric_limits<std::uint64_t>::max)()) ||
                *max_combo < 0.0 || *max_combo > static_cast<double>((std::numeric_limits<std::uint32_t>::max)())) {
                return json_error(422, "Unprocessable Content", "Server replay rerun rejected the evidence.");
            }
            VerifiedReplayRecord record;
            record.chart_sha256 = *chart_hash;
            record.replay_sha256 = *replay_hash;
            record.score = static_cast<std::uint64_t>(*score);
            record.accuracy = *accuracy;
            record.max_combo = static_cast<std::uint32_t>(*max_combo);
            record.clear_status = *clear_status;
            record.ruleset_id = *ruleset_id;
            std::string receipt;
            if (!ranked_database->commit_verified_replay(*token, *challenge_id, record, receipt, error)) {
                return json_error(409, "Conflict", error);
            }
            return http_response(201, "Created",
                "{\"verification_status\":\"online_verified\",\"receipt\":\"" + receipt +
                "\",\"chart_sha256\":\"" + record.chart_sha256 +
                "\",\"replay_sha256\":\"" + record.replay_sha256 +
                "\",\"score\":" + std::to_string(record.score) + "}");
        }
        if (method != "GET" && method != "POST") {
            return json_error(405, "Method Not Allowed", "Only GET and POST are supported.");
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
        std::cout << "[TenRiff-Server] API listening on "
                  << options.bind_address << ':' << listening_port.load()
                  << (ranked_database && ranked_database->ready()
                          ? " (accounts + BMS server-rerun verification)."
                          : " (read-only BMS records).") << std::endl;

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
                    std::array<char, INET_ADDRSTRLEN> remote_text{};
                    if (inet_ntop(AF_INET, &remote.sin_addr, remote_text.data(),
                                  static_cast<SocketLength>(remote_text.size()))) {
                        client.remote_address = remote_text.data();
                    }
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
                        } else if (client.request.find("\r\n\r\n") != std::string::npos &&
                                   !request_content_length(client.request).has_value()) {
                            client.response = json_error(
                                400, "Bad Request", "Content-Length is invalid.");
                        } else if (complete_http_request(client.request)) {
                            const std::string rate_address =
                                rate_limit_address(client.remote_address, client.request);
                            client.response = allow_request(rate_address, client.request)
                                                  ? route(client.request)
                                                  : json_error(429, "Too Many Requests",
                                                               "Per-address request limit exceeded.");
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
                             const OnlineRecordStore& records,
                             RankedDatabase* ranked_database)
    : impl_(new Impl(std::move(options), records, ranked_database)) {}

HttpApiServer::~HttpApiServer() { delete impl_; }

bool HttpApiServer::run(std::atomic_bool& stop_requested, std::string& error) {
    return impl_->run(stop_requested, error);
}

std::uint16_t HttpApiServer::bound_port() const {
    return impl_->listening_port.load(std::memory_order_acquire);
}

}  // namespace tenriff::server
