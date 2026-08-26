#include "tenriff_server/Coordinator.h"
#include "tenriff_server/Protocol.h"
#include "tenriff_server/TcpServer.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
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
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::cerr << __FILE__ << ':' << __LINE__                            \
                      << " check failed: " #condition "\n";                   \
            ++failures;                                                        \
        }                                                                       \
    } while (false)

using tenriff::server::ConnectionId;
using tenriff::server::RoomCoordinator;
namespace protocol = tenriff::server::protocol;

protocol::Message make_library_begin(std::uint32_t count) {
    protocol::Message message;
    message.type = protocol::MessageType::LibraryBegin;
    message.library_count = count;
    return message;
}

protocol::Message make_library_chunk(std::vector<std::string> hashes) {
    protocol::Message message;
    message.type = protocol::MessageType::LibraryChunk;
    message.chart_sha256 = std::move(hashes);
    return message;
}

protocol::Message make_type(protocol::MessageType type) {
    protocol::Message message;
    message.type = type;
    return message;
}

void test_protocol_golden_vector() {
    protocol::Message hello;
    hello.type = protocol::MessageType::Hello;
    hello.text = "Test";
    std::string error;
    const auto encoded = protocol::encode(hello, &error);
    const std::vector<std::uint8_t> expected = {
        0x54, 0x52, 0x50, 0x31, 0x00, 0x05, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x54, 0x65,
        0x73, 0x74,
    };
    CHECK(error.empty());
    CHECK(encoded == expected);

    protocol::Message decoded;
    std::size_t consumed = 0;
    CHECK(protocol::decode(encoded, decoded, consumed, error) ==
          protocol::DecodeStatus::Complete);
    CHECK(consumed == encoded.size());
    CHECK(decoded.type == protocol::MessageType::Hello);
    CHECK(decoded.text == "Test");

    auto bad = encoded;
    bad[5] = 0x04;
    CHECK(protocol::decode(bad, decoded, consumed, error) ==
          protocol::DecodeStatus::Error);
    CHECK(!error.empty());
}

void test_protocol_bounds() {
    protocol::Message score;
    score.type = protocol::MessageType::FinalScore;
    score.nonce = 7;
    score.score.score = protocol::kMaximumClaimedScore + 1;
    std::string error;
    CHECK(protocol::encode(score, &error).empty());

    protocol::Message chunk;
    chunk.type = protocol::MessageType::LibraryChunk;
    chunk.chart_sha256 = {"not-a-hash"};
    CHECK(protocol::encode(chunk, &error).empty());
}

void test_coordinator_full_round() {
    constexpr ConnectionId alice = 101;
    constexpr ConnectionId bob = 202;
    const std::string hash_a(64, 'a');
    const std::string hash_b(64, 'b');
    const std::string hash_c(64, 'c');

    RoomCoordinator room;
    auto result = room.join(alice, "Alice");
    CHECK(result.success());
    CHECK(room.snapshot().leader_id == 1);
    CHECK(room.player_count() == 1);
    result = room.join(bob, "Bob");
    CHECK(result.success());
    CHECK(room.player_count() == 2);

    CHECK(room.handle(alice, make_library_begin(2)).success());
    CHECK(room.handle(alice, make_library_chunk({hash_a, hash_b})).success());
    CHECK(room.handle(alice, make_type(protocol::MessageType::LibraryEnd)).success());
    CHECK(room.handle(bob, make_library_begin(2)).success());
    CHECK(room.handle(bob, make_library_chunk({hash_a, hash_c})).success());
    CHECK(room.handle(bob, make_type(protocol::MessageType::LibraryEnd)).success());
    CHECK(room.common_library_ready());
    CHECK(room.common_library() == std::vector<std::string>{hash_a});

    protocol::Message chart;
    chart.type = protocol::MessageType::Chart;
    chart.player_id = 8;  // Spoofed ID must be ignored.
    chart.chart_hash = 0x1234;
    chart.chart_size = 55;
    chart.text = "Shared chart";
    CHECK(room.handle(alice, chart).success());
    CHECK(room.handle(bob, chart).success());

    protocol::Message ready;
    ready.type = protocol::MessageType::Ready;
    ready.ready = true;
    CHECK(room.handle(alice, ready).success());
    CHECK(room.handle(bob, ready).success());

    protocol::Message launch;
    launch.type = protocol::MessageType::Launch;
    launch.chart_hash = 0x9999;  // Coordinator replaces this with the selection.
    launch.nonce = 9001;
    result = room.handle(alice, launch);
    CHECK(result.success());
    CHECK(room.snapshot().active_round_nonce == 9001);
    CHECK(!result.deliveries.empty());
    CHECK(result.deliveries.front().message.chart_hash == 0x1234);

    protocol::Message loaded;
    loaded.type = protocol::MessageType::Loaded;
    loaded.nonce = 9001;
    CHECK(room.handle(alice, loaded).success());
    CHECK(room.handle(bob, loaded).success());

    protocol::Message begin;
    begin.type = protocol::MessageType::Begin;
    begin.nonce = 9001;
    begin.delay_ms = 1500;
    CHECK(room.handle(alice, begin).success());
    CHECK(room.snapshot().begin_sent);

    protocol::Message final_score;
    final_score.type = protocol::MessageType::FinalScore;
    final_score.nonce = 9001;
    final_score.score.score = 8000;
    final_score.score.max_combo = 10;
    final_score.score.combo = 10;
    final_score.score.perfect = 10;
    final_score.score.gauge_milli = 75000;
    final_score.score.finished = true;
    CHECK(room.handle(alice, final_score).success());
    final_score.score.score = 7000;
    CHECK(room.handle(bob, final_score).success());

    protocol::Message reset;
    reset.type = protocol::MessageType::RoundReset;
    reset.nonce = 9001;
    CHECK(room.handle(alice, reset).success());
    CHECK(room.handle(bob, reset).success());
    const auto snapshot = room.snapshot();
    CHECK(snapshot.active_round_nonce == 0);
    CHECK(snapshot.leader_id == 2);
    CHECK(!snapshot.participants[0].ready);
    CHECK(snapshot.participants[0].chart_hash == 0);
}

void test_coordinator_rejections_and_attribution() {
    RoomCoordinator room;
    CHECK(!room.join(1, std::string("bad\xff", 4)).success());
    CHECK(room.join(1, "One").success());
    CHECK(room.join(2, "Two").success());

    protocol::Message chart;
    chart.type = protocol::MessageType::Chart;
    chart.chart_hash = 10;
    chart.chart_size = 20;
    chart.text = "A";
    CHECK(room.handle(1, chart).success());
    chart.chart_hash = 11;
    CHECK(!room.handle(2, chart).success());

    protocol::Message chat;
    chat.type = protocol::MessageType::Chat;
    chat.player_id = 7;
    chat.text = "hello";
    const auto chat_result = room.handle(2, chat);
    CHECK(chat_result.success());
    CHECK(chat_result.deliveries.size() == 1);
    CHECK(chat_result.deliveries[0].message.player_id == 2);
}

#ifdef _WIN32
using TestSocket = SOCKET;
constexpr TestSocket kInvalidTestSocket = INVALID_SOCKET;
void close_test_socket(TestSocket socket) { closesocket(socket); }
struct TestSocketRuntime {
    TestSocketRuntime() { WSADATA data{}; ok = WSAStartup(MAKEWORD(2, 2), &data) == 0; }
    ~TestSocketRuntime() { if (ok) WSACleanup(); }
    bool ok = false;
};
#else
using TestSocket = int;
constexpr TestSocket kInvalidTestSocket = -1;
void close_test_socket(TestSocket socket) { close(socket); }
struct TestSocketRuntime { bool ok = true; };
#endif

struct TestClient {
    TestSocket socket = kInvalidTestSocket;
    std::vector<std::uint8_t> received;
    ~TestClient() { if (socket != kInvalidTestSocket) close_test_socket(socket); }
};

bool connect_client(TestClient& client, std::uint16_t port) {
    client.socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client.socket == kInvalidTestSocket) return false;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    return connect(client.socket, reinterpret_cast<const sockaddr*>(&address),
                   static_cast<int>(sizeof(address))) == 0;
}

bool send_message(TestClient& client, const protocol::Message& message) {
    const auto frame = protocol::encode(message);
    std::size_t sent_total = 0;
    while (sent_total < frame.size()) {
        const int sent = send(
            client.socket,
#ifdef _WIN32
            reinterpret_cast<const char*>(frame.data() + sent_total),
#else
            frame.data() + sent_total,
#endif
            static_cast<int>(frame.size() - sent_total), 0);
        if (sent <= 0) return false;
        sent_total += static_cast<std::size_t>(sent);
    }
    return true;
}

bool receive_type(TestClient& client,
                  protocol::MessageType wanted,
                  protocol::Message& output,
                  std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        while (!client.received.empty()) {
            protocol::Message decoded;
            std::size_t consumed = 0;
            std::string error;
            const auto status = protocol::decode(client.received, decoded, consumed, error);
            if (status == protocol::DecodeStatus::Error) return false;
            if (status == protocol::DecodeStatus::Incomplete) break;
            client.received.erase(
                client.received.begin(),
                client.received.begin() + static_cast<std::ptrdiff_t>(consumed));
            if (decoded.type == protocol::MessageType::Ping) {
                protocol::Message pong;
                pong.type = protocol::MessageType::Pong;
                pong.nonce = decoded.nonce;
                if (!send_message(client, pong)) return false;
            }
            if (decoded.type == wanted) {
                output = std::move(decoded);
                return true;
            }
        }

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(client.socket, &read_set);
        timeval wait{};
        wait.tv_sec = 0;
        wait.tv_usec = 50'000;
        const int selected = select(
#ifdef _WIN32
            0,
#else
            client.socket + 1,
#endif
            &read_set, nullptr, nullptr, &wait);
        if (selected <= 0) continue;
        std::uint8_t chunk[4096];
        const int count = recv(
            client.socket,
#ifdef _WIN32
            reinterpret_cast<char*>(chunk),
#else
            chunk,
#endif
            static_cast<int>(sizeof(chunk)), 0);
        if (count <= 0) return false;
        client.received.insert(client.received.end(), chunk, chunk + count);
    }
    return false;
}

void test_tcp_handshake_and_common_library() {
    TestSocketRuntime sockets;
    CHECK(sockets.ok);
    if (!sockets.ok) return;

    tenriff::server::ServerOptions options;
    options.bind_address = "127.0.0.1";
    options.port = 0;
    options.name = "Test Server";
    tenriff::server::TcpServer server(options);
    std::atomic_bool stop{false};
    std::string server_error;
    bool server_ok = false;
    std::thread worker([&] { server_ok = server.run(stop, server_error); });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (server.bound_port() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(server.bound_port() != 0);

    TestClient alice;
    TestClient bob;
    protocol::Message received;
    CHECK(connect_client(alice, server.bound_port()));
    CHECK(receive_type(alice, protocol::MessageType::Hello, received));
    CHECK(received.text == "Test Server");
    protocol::Message hello;
    hello.type = protocol::MessageType::Hello;
    hello.text = "Alice";
    CHECK(send_message(alice, hello));
    CHECK(receive_type(alice, protocol::MessageType::RoomWelcome, received));
    CHECK(received.player_id == 1);
    CHECK(received.leader_id == 1);

    CHECK(connect_client(bob, server.bound_port()));
    CHECK(receive_type(bob, protocol::MessageType::Hello, received));
    hello.text = "Bob";
    CHECK(send_message(bob, hello));
    CHECK(receive_type(bob, protocol::MessageType::RoomWelcome, received));
    CHECK(received.player_id == 2);
    CHECK(received.leader_id == 1);

    const std::string shared_hash(64, 'd');
    for (auto* client : {&alice, &bob}) {
        CHECK(send_message(*client, make_library_begin(1)));
        CHECK(send_message(*client, make_library_chunk({shared_hash})));
        CHECK(send_message(*client, make_type(protocol::MessageType::LibraryEnd)));
    }
    CHECK(receive_type(alice, protocol::MessageType::CommonLibraryBegin, received));
    CHECK(received.library_count == 1);
    CHECK(receive_type(alice, protocol::MessageType::CommonLibraryChunk, received));
    CHECK(received.chart_sha256 == std::vector<std::string>{shared_hash});
    CHECK(receive_type(alice, protocol::MessageType::CommonLibraryEnd, received));

    stop.store(true, std::memory_order_release);
    worker.join();
    CHECK(server_ok);
    CHECK(server_error.empty());
}

}  // namespace

int main() {
    test_protocol_golden_vector();
    test_protocol_bounds();
    test_coordinator_full_round();
    test_coordinator_rejections_and_attribution();
    test_tcp_handshake_and_common_library();
    if (failures != 0) {
        std::cerr << failures << " test checks failed.\n";
        return 1;
    }
    std::cout << "All TenRiff Server tests passed.\n";
    return 0;
}
