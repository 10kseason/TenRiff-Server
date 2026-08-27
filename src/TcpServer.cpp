#include "tenriff_server/TcpServer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <utility>
#include <vector>

#include "tenriff_server/Coordinator.h"
#include "tenriff_server/Protocol.h"

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
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace tenriff::server {

namespace {

using Clock = std::chrono::steady_clock;
constexpr auto kPollInterval = std::chrono::milliseconds(20);
constexpr auto kHandshakeTimeout = std::chrono::seconds(5);
constexpr auto kHeartbeatInterval = std::chrono::seconds(2);
constexpr auto kPeerTimeout = std::chrono::seconds(10);
constexpr auto kGracefulClose = std::chrono::milliseconds(250);
constexpr std::size_t kMaxWireBytes = 128 * 1024;
constexpr std::size_t kMaxReceiveBytes =
    2 * protocol::kMaxPayloadSize + protocol::kFrameHeaderSize;
constexpr std::size_t kMaxAcceptedConnections = 32;
constexpr std::size_t kMaxConnectionsPerAddress = 4;
constexpr int kMaxAcceptsPerPoll = 16;

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
using SocketLength = int;

int socket_error() { return WSAGetLastError(); }
bool would_block(int error) { return error == WSAEWOULDBLOCK; }
bool descriptor_exhausted(int error) { return error == WSAEMFILE; }
void close_socket(NativeSocket socket) { closesocket(socket); }
void shutdown_socket(NativeSocket socket) { shutdown(socket, SD_BOTH); }

class SocketRuntime {
public:
    SocketRuntime() {
        WSADATA data{};
        ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~SocketRuntime() {
        if (ok_) WSACleanup();
    }
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
bool descriptor_exhausted(int error) { return error == EMFILE || error == ENFILE; }
void close_socket(NativeSocket socket) { close(socket); }
void shutdown_socket(NativeSocket socket) { shutdown(socket, SHUT_RDWR); }

class SocketRuntime {
public:
    [[nodiscard]] bool ok() const { return true; }
};
#endif

std::string socket_error_text(const char* operation, int code) {
    std::ostringstream stream;
    stream << operation << " failed (socket error " << code << ").";
    return stream.str();
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

bool configure_peer(NativeSocket socket, std::string& error) {
    if (!set_nonblocking(socket, error)) return false;
    const int enabled = 1;
    if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
#ifdef _WIN32
                   reinterpret_cast<const char*>(&enabled),
#else
                   &enabled,
#endif
                   static_cast<SocketLength>(sizeof(enabled))) < 0) {
        error = socket_error_text("setsockopt(TCP_NODELAY)", socket_error());
        return false;
    }
    return true;
}

struct WireQueue {
    std::deque<std::vector<std::uint8_t>> frames;
    std::size_t front_offset = 0;
    std::size_t bytes = 0;

    [[nodiscard]] bool empty() const { return frames.empty(); }

    bool push(const protocol::Message& message, std::string& error) {
        auto frame = protocol::encode(message, &error);
        if (frame.empty()) return false;
        if (bytes > kMaxWireBytes - frame.size()) {
            error = "Connection send queue exceeded its byte limit.";
            return false;
        }
        bytes += frame.size();
        frames.push_back(std::move(frame));
        return true;
    }

    bool flush(NativeSocket socket, std::string& error) {
        int sent_frames = 0;
        while (!frames.empty() && sent_frames < 64) {
            auto& frame = frames.front();
            const auto remaining = frame.size() - front_offset;
            const int sent = send(
                socket,
#ifdef _WIN32
                reinterpret_cast<const char*>(frame.data() + front_offset),
#else
                frame.data() + front_offset,
#endif
                static_cast<int>(remaining), 0);
            if (sent > 0) {
                front_offset += static_cast<std::size_t>(sent);
                bytes -= static_cast<std::size_t>(sent);
                if (front_offset == frame.size()) {
                    frames.pop_front();
                    front_offset = 0;
                    ++sent_frames;
                }
                continue;
            }
            if (sent < 0 && would_block(socket_error())) return true;
            error = socket_error_text("send", sent == 0 ? 0 : socket_error());
            return false;
        }
        return true;
    }
};

struct Link {
    SocketHandle socket;
    ConnectionId connection = 0;
    WireQueue wire;
    std::vector<std::uint8_t> received;
    bool handshake_complete = false;
    bool close_after_flush = false;
    std::string name;
    std::string remote_address;
    Clock::time_point accepted_at = Clock::now();
    Clock::time_point last_received = Clock::now();
    Clock::time_point last_ping_sent = Clock::now() - kHeartbeatInterval;
    std::uint64_t ping_nonce = 0;
    std::uint64_t common_generation = 0;
    std::size_t common_cursor = 0;
    int common_stage = 0;
};

void log_line(const std::string& message) {
    std::cout << "[TenRiff-Server] " << message << std::endl;
}

}  // namespace

struct TcpServer::Impl {
    explicit Impl(ServerOptions value) : options(std::move(value)) {}

    ServerOptions options;
    RoomCoordinator coordinator;
    mutable std::mutex snapshot_mutex;
    std::atomic<std::uint16_t> listening_port{0};
    std::atomic<std::size_t> players{0};
    ConnectionId next_connection = 1;
    std::uint64_t next_ping_nonce = 1;

    void publish_multiplayer_directory() {
        if (!options.multiplayer_directory) return;
        const RoomSnapshot room = coordinator.snapshot();
        options.multiplayer_directory->update(
            options.name,
            listening_port.load(std::memory_order_acquire),
            static_cast<std::uint8_t>((std::min)(
                coordinator.player_count(),
                static_cast<std::size_t>(protocol::kMaxPlayers))),
            static_cast<std::uint8_t>(protocol::kMaxPlayers),
            room.active_round_nonce != 0);
    }

    SocketHandle create_listener(std::string& error) {
        SocketHandle listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!listener.valid()) {
            error = socket_error_text("socket", socket_error());
            return {};
        }
#ifndef _WIN32
        if (listener.get() >= FD_SETSIZE) {
            error = "Game listener descriptor exceeds select capacity.";
            return {};
        }
#endif
#ifdef _WIN32
        const int exclusive = 1;
        if (setsockopt(listener.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive),
                       static_cast<SocketLength>(sizeof(exclusive))) < 0) {
            error = socket_error_text("setsockopt(SO_EXCLUSIVEADDRUSE)", socket_error());
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
            error = "--bind must be an IPv4 address.";
            return {};
        }
        if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address),
                 static_cast<SocketLength>(sizeof(address))) < 0) {
            error = socket_error_text("bind", socket_error());
            return {};
        }
        if (listen(listener.get(), 16) < 0) {
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

    static bool receive_frames(Link& link,
                               std::vector<protocol::Message>& messages,
                               bool& closed,
                               std::string& error) {
        closed = false;
        std::array<std::uint8_t, 8192> chunk{};
        for (;;) {
            const int read = recv(
                link.socket.get(),
#ifdef _WIN32
                reinterpret_cast<char*>(chunk.data()),
#else
                chunk.data(),
#endif
                static_cast<int>(chunk.size()), 0);
            if (read > 0) {
                const auto count = static_cast<std::size_t>(read);
                if (link.received.size() > kMaxReceiveBytes - count) {
                    error = "Connection receive buffer exceeded its byte limit.";
                    return false;
                }
                link.received.insert(link.received.end(), chunk.begin(),
                                     chunk.begin() + read);
                continue;
            }
            if (read == 0) {
                closed = true;
                break;
            }
            const int code = socket_error();
            if (would_block(code)) break;
            error = socket_error_text("recv", code);
            return false;
        }

        int processed = 0;
        while (!link.received.empty() && processed < 64) {
            protocol::Message message;
            std::size_t consumed = 0;
            std::string decode_error;
            const auto status = protocol::decode(
                link.received, message, consumed, decode_error);
            if (status == protocol::DecodeStatus::Incomplete) break;
            if (status == protocol::DecodeStatus::Error) {
                error = std::move(decode_error);
                return false;
            }
            link.received.erase(
                link.received.begin(),
                link.received.begin() + static_cast<std::ptrdiff_t>(consumed));
            messages.push_back(std::move(message));
            link.last_received = Clock::now();
            ++processed;
        }
        return true;
    }

    static Link* find_link(std::vector<Link>& links, ConnectionId connection) {
        for (auto& link : links) {
            if (link.connection == connection) return &link;
        }
        return nullptr;
    }

    void deliver(std::vector<Link>& links, const CoordinatorResult& result) {
        for (const auto& delivery : result.deliveries) {
            for (auto& link : links) {
                if (!link.handshake_complete || link.close_after_flush) continue;
                if (delivery.target != kBroadcast &&
                    delivery.target != link.connection) continue;
                std::string error;
                if (!link.wire.push(delivery.message, error)) {
                    link.close_after_flush = true;
                }
            }
        }
        players.store(coordinator.player_count(), std::memory_order_release);
        publish_multiplayer_directory();
    }

    void queue_disconnect(Link& link, const std::string& reason) {
        protocol::Message disconnected;
        disconnected.type = protocol::MessageType::Disconnect;
        disconnected.text = reason.substr(0, 1024);
        std::string ignored;
        (void)link.wire.push(disconnected, ignored);
        link.close_after_flush = true;
    }

    bool process_message(std::vector<Link>& links,
                         Link& link,
                         const protocol::Message& message) {
        if (!link.handshake_complete) {
            if (message.type != protocol::MessageType::Hello) {
                queue_disconnect(link, "Player handshake is invalid.");
                return true;
            }
            auto result = coordinator.join(link.connection, message.text);
            if (!result.success()) {
                queue_disconnect(link, result.error);
                return true;
            }
            link.name = normalize_display_text(message.text, 64);
            link.handshake_complete = true;
            log_line(link.name + " joined (" +
                     std::to_string(coordinator.player_count()) + "/8). ");
            deliver(links, result);
            return true;
        }

        if (message.type == protocol::MessageType::Ping) {
            protocol::Message pong;
            pong.type = protocol::MessageType::Pong;
            pong.nonce = message.nonce;
            std::string error;
            if (!link.wire.push(pong, error)) queue_disconnect(link, error);
            return true;
        }
        if (message.type == protocol::MessageType::Pong) {
            if (link.ping_nonce == 0 || message.nonce != link.ping_nonce) {
                queue_disconnect(link, "Heartbeat response is invalid.");
            } else {
                link.ping_nonce = 0;
            }
            return true;
        }

        auto result = coordinator.handle(link.connection, message);
        if (!result.success()) {
            log_line("Rejected " + link.name + ": " + result.error);
            queue_disconnect(link, result.error);
        }
        deliver(links, result);
        if (result.disconnect_source) link.close_after_flush = true;
        return true;
    }

    void feed_common_library(Link& link) {
        if (!link.handshake_complete || link.close_after_flush ||
            !coordinator.common_library_ready()) return;
        const auto generation = coordinator.common_library_generation();
        if (link.common_generation != generation) {
            link.common_generation = generation;
            link.common_cursor = 0;
            link.common_stage = 0;
        }
        if (link.common_stage == 2 || link.wire.bytes >= kMaxWireBytes / 2) return;

        protocol::Message message;
        std::string error;
        const auto& common = coordinator.common_library();
        if (link.common_stage == 0) {
            message.type = protocol::MessageType::CommonLibraryBegin;
            message.library_count = static_cast<std::uint32_t>(common.size());
            if (link.wire.push(message, error)) link.common_stage = 1;
        } else if (link.common_cursor < common.size()) {
            const auto end = std::min(
                common.size(), link.common_cursor + protocol::kLibraryHashesPerChunk);
            message.type = protocol::MessageType::CommonLibraryChunk;
            message.chart_sha256.assign(common.begin() +
                                            static_cast<std::ptrdiff_t>(link.common_cursor),
                                        common.begin() +
                                            static_cast<std::ptrdiff_t>(end));
            if (link.wire.push(message, error)) link.common_cursor = end;
        } else {
            message.type = protocol::MessageType::CommonLibraryEnd;
            if (link.wire.push(message, error)) link.common_stage = 2;
        }
        if (!error.empty()) queue_disconnect(link, error);
    }

    bool run(std::atomic_bool& stop_requested, std::string& error) {
        options.name = normalize_display_text(options.name, 64);
        if (options.name.empty()) {
            error = "Server name is empty or invalid UTF-8.";
            return false;
        }
        SocketRuntime runtime;
        if (!runtime.ok()) {
            error = "Could not initialize the socket runtime.";
            return false;
        }
        SocketHandle listener = create_listener(error);
        if (!listener.valid()) return false;
        log_line("Listening on " + options.bind_address + ":" +
                 std::to_string(listening_port.load()) +
                 " (protocol v5, max 8 players). ");
        publish_multiplayer_directory();

        std::vector<Link> links;
        links.reserve(protocol::kMaxPlayers + 4);
        bool shutdown_announced = false;
        auto shutdown_deadline = Clock::time_point::max();

        while (true) {
            const auto now = Clock::now();
            if (stop_requested.load(std::memory_order_acquire) && !shutdown_announced) {
                for (auto& link : links) {
                    if (link.handshake_complete) {
                        queue_disconnect(link, "Server is shutting down.");
                    } else {
                        link.close_after_flush = true;
                    }
                }
                shutdown_announced = true;
                shutdown_deadline = now + kGracefulClose;
            }
            if (shutdown_announced && now >= shutdown_deadline) break;

            for (auto& link : links) {
                feed_common_library(link);
                if (link.handshake_complete && !link.close_after_flush &&
                    now - link.last_ping_sent >= kHeartbeatInterval) {
                    protocol::Message ping;
                    ping.type = protocol::MessageType::Ping;
                    ping.nonce = next_ping_nonce++;
                    link.ping_nonce = ping.nonce;
                    std::string push_error;
                    if (!link.wire.push(ping, push_error)) {
                        queue_disconnect(link, push_error);
                    }
                    link.last_ping_sent = now;
                }
            }
            if (shutdown_announced && links.empty()) break;

            fd_set read_set;
            fd_set write_set;
            fd_set except_set;
            FD_ZERO(&read_set);
            FD_ZERO(&write_set);
            FD_ZERO(&except_set);
            NativeSocket maximum = 0;
            if (!shutdown_announced) {
                FD_SET(listener.get(), &read_set);
                FD_SET(listener.get(), &except_set);
                maximum = listener.get();
            }
            for (auto& link : links) {
                FD_SET(link.socket.get(), &read_set);
                FD_SET(link.socket.get(), &except_set);
                if (!link.wire.empty()) FD_SET(link.socket.get(), &write_set);
                maximum = std::max(maximum, link.socket.get());
            }
            timeval timeout{};
            timeout.tv_usec = static_cast<long>(
                std::chrono::duration_cast<std::chrono::microseconds>(kPollInterval).count());
            const int selected = select(
#ifdef _WIN32
                0,
#else
                maximum + 1,
#endif
                &read_set, &write_set, &except_set, &timeout);
            if (selected < 0) {
                error = socket_error_text("select", socket_error());
                return false;
            }

            if (!shutdown_announced && FD_ISSET(listener.get(), &read_set)) {
                for (int accepted_this_poll = 0;
                     accepted_this_poll < kMaxAcceptsPerPoll;
                     ++accepted_this_poll) {
                    sockaddr_in remote{};
                    SocketLength remote_size = static_cast<SocketLength>(sizeof(remote));
                    SocketHandle accepted(accept(
                        listener.get(), reinterpret_cast<sockaddr*>(&remote), &remote_size));
                    if (!accepted.valid()) {
                        const int code = socket_error();
                        if (would_block(code) || descriptor_exhausted(code)) break;
                        error = socket_error_text("accept", code);
                        return false;
                    }
#ifndef _WIN32
                    if (accepted.get() >= FD_SETSIZE) {
                        shutdown_socket(accepted.get());
                        continue;
                    }
#endif
                    std::array<char, INET_ADDRSTRLEN> remote_text{};
                    const char* remote_value = inet_ntop(
                        AF_INET, &remote.sin_addr, remote_text.data(),
                        static_cast<SocketLength>(remote_text.size()));
                    const std::string remote_address =
                        remote_value ? std::string(remote_value) : std::string("unknown");
                    const std::size_t from_address = static_cast<std::size_t>(
                        std::count_if(links.begin(), links.end(), [&](const Link& link) {
                            return link.remote_address == remote_address;
                        }));
                    if (links.size() >= kMaxAcceptedConnections ||
                        from_address >= kMaxConnectionsPerAddress) {
                        shutdown_socket(accepted.get());
                        continue;
                    }
                    std::string peer_error;
                    if (!configure_peer(accepted.get(), peer_error)) {
                        shutdown_socket(accepted.get());
                        continue;
                    }
                    Link link;
                    link.socket = std::move(accepted);
                    link.connection = next_connection++;
                    link.remote_address = remote_address;
                    link.received.reserve(16 * 1024);
                    protocol::Message hello;
                    hello.type = protocol::MessageType::Hello;
                    hello.text = options.name;
                    if (!link.wire.push(hello, error)) return false;
                    links.push_back(std::move(link));
                }
            }

            std::vector<std::size_t> remove;
            for (std::size_t index = 0; index < links.size(); ++index) {
                auto& link = links[index];
                bool drop = FD_ISSET(link.socket.get(), &except_set) != 0;
                std::string link_error;
                if (!drop && !link.wire.empty() &&
                    FD_ISSET(link.socket.get(), &write_set)) {
                    if (!link.wire.flush(link.socket.get(), link_error)) drop = true;
                }
                if (!drop && FD_ISSET(link.socket.get(), &read_set)) {
                    std::vector<protocol::Message> messages;
                    bool closed = false;
                    if (!receive_frames(link, messages, closed, link_error)) {
                        drop = true;
                    } else {
                        drop = closed;
                        for (const auto& message : messages) {
                            if (drop) break;
                            process_message(links, link, message);
                        }
                    }
                }
                if (!drop && !link.handshake_complete &&
                    now - link.accepted_at >= kHandshakeTimeout) drop = true;
                if (!drop && link.handshake_complete &&
                    now - link.last_received >= kPeerTimeout) drop = true;
                if (!drop && link.close_after_flush && link.wire.empty()) drop = true;
                if (drop) remove.push_back(index);
            }
            for (auto iterator = remove.rbegin(); iterator != remove.rend(); ++iterator) {
                auto& link = links[*iterator];
                const auto connection = link.connection;
                const auto name = link.name;
                shutdown_socket(link.socket.get());
                const bool registered = coordinator.contains(connection);
                links.erase(links.begin() + static_cast<std::ptrdiff_t>(*iterator));
                if (registered) {
                    auto result = coordinator.leave(connection);
                    deliver(links, result);
                    log_line((name.empty() ? "Player" : name) + " disconnected (" +
                             std::to_string(coordinator.player_count()) + "/8). ");
                }
            }
        }

        for (auto& link : links) shutdown_socket(link.socket.get());
        players.store(0, std::memory_order_release);
        listening_port.store(0, std::memory_order_release);
        publish_multiplayer_directory();
        log_line("Stopped.");
        return true;
    }
};

TcpServer::TcpServer(ServerOptions options) : impl_(new Impl(std::move(options))) {}

TcpServer::~TcpServer() { delete impl_; }

bool TcpServer::run(std::atomic_bool& stop_requested, std::string& error) {
    return impl_->run(stop_requested, error);
}

std::uint16_t TcpServer::bound_port() const {
    return impl_->listening_port.load(std::memory_order_acquire);
}

std::size_t TcpServer::player_count() const {
    return impl_->players.load(std::memory_order_acquire);
}

}  // namespace tenriff::server
