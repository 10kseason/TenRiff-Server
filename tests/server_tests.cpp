#include "tenriff_server/BmsCatalog.h"
#include "tenriff_server/Coordinator.h"
#include "tenriff_server/HttpApiServer.h"
#include "tenriff_server/OnlineRecordStore.h"
#include "tenriff_server/RankedDatabase.h"
#include "tenriff_server/Protocol.h"
#include "tenriff_server/TcpServer.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
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
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
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

void test_online_record_store_filters_and_sorts() {
    const auto path = std::filesystem::temp_directory_path() /
                      "tenriff_server_records_test.jsonl";
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output
            << "{\"chart_sha256\":\"" << std::string(64, 'a')
            << "\",\"chart_format\":\"bms\",\"player_name\":\"Second\","
               "\"score\":800000,\"accuracy\":98.0,\"max_combo\":500,"
               "\"clear_status\":\"CLEAR\",\"ruleset_id\":\"ranked-v1\","
               "\"verification_status\":\"online_verified\","
               "\"verified_at_utc\":\"2026-08-26T00:00:01Z\"}\n"
            << "{\"chart_sha256\":\"" << std::string(64, 'a')
            << "\",\"chart_format\":\"bms\",\"player_name\":\"First\","
               "\"score\":900000,\"accuracy\":97.0,\"max_combo\":400,"
               "\"clear_status\":\"HARD\",\"ruleset_id\":\"ranked-v1\","
               "\"verification_status\":\"online_verified\","
               "\"verified_at_utc\":\"2026-08-26T00:00:02Z\"}\n"
            << "{\"chart_sha256\":\"" << std::string(64, 'a')
            << "\",\"chart_format\":\"osu\",\"player_name\":\"Foreign\","
               "\"score\":999999,\"accuracy\":100.0,\"max_combo\":999,"
               "\"clear_status\":\"CLEAR\",\"ruleset_id\":\"foreign\","
               "\"verification_status\":\"online_verified\","
               "\"verified_at_utc\":\"2026-08-26T00:00:03Z\"}\n"
            << "{\"chart_sha256\":\"" << std::string(64, 'a')
            << "\",\"chart_format\":\"bms\",\"player_name\":\"Claim\","
               "\"score\":999999,\"accuracy\":100.0,\"max_combo\":999,"
               "\"clear_status\":\"CLEAR\",\"ruleset_id\":\"ranked-v1\","
               "\"verification_status\":\"client_claim\","
               "\"verified_at_utc\":\"2026-08-26T00:00:04Z\"}\n";
    }
    tenriff::server::OnlineRecordStore store;
    std::string error;
    CHECK(store.load_json_lines(path.string(), error));
    CHECK(error.empty());
    CHECK(store.record_count() == 2);
    CHECK(store.ignored_count() == 2);
    const auto records = store.leaderboard(std::string(64, 'A'), 10);
    CHECK(records.size() == 2);
    CHECK(records[0].player_name == "First");
    CHECK(records[1].player_name == "Second");
    const auto json = tenriff::server::online_records_json(
        std::string(64, 'a'), records);
    CHECK(json.find("\"rank\":1") != std::string::npos);
    CHECK(json.find("Foreign") == std::string::npos);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void test_bms_catalog_default_allow_and_exclusions() {
    const auto root = std::filesystem::temp_directory_path() /
                      "tenriff_server_bms_catalog_test";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "nested", ignored);
    {
        std::ofstream(root / "a.bms", std::ios::binary) << "abc";
        std::ofstream(root / "nested" / "b.BME", std::ios::binary) << "def";
        std::ofstream(root / "duplicate.pms", std::ios::binary) << "abc";
        std::ofstream(root / "ignored.osu", std::ios::binary) << "ghi";
        std::ofstream(root / "excluded-charts.txt", std::ios::binary) << "# none\n";
    }

    tenriff::server::BmsCatalogLoadResult catalog;
    std::string error;
    CHECK(tenriff::server::load_bms_catalog(
        root, root / "excluded-charts.txt", catalog, error));
    CHECK(error.empty());
    CHECK(catalog.charts.size() == 2);
    CHECK(catalog.duplicate_count == 1);

    const std::string abc_sha256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    {
        std::ofstream(root / "excluded-charts.txt", std::ios::binary | std::ios::trunc)
            << abc_sha256 << " # operator exclusion\n";
    }
    CHECK(tenriff::server::load_bms_catalog(
        root, root / "excluded-charts.txt", catalog, error));
    CHECK(catalog.charts.size() == 1);
    CHECK(catalog.excluded_count == 2);

    {
        std::ofstream(root / "excluded-charts.txt", std::ios::binary | std::ios::trunc)
            << "not-a-sha256\n";
    }
    CHECK(!tenriff::server::load_bms_catalog(
        root, root / "excluded-charts.txt", catalog, error));
    CHECK(!error.empty());
    std::filesystem::remove_all(root, ignored);
}

void test_ranked_database_accounts_challenges_and_verified_records() {
    const auto path = std::filesystem::temp_directory_path() /
                      "tenriff_server_ranked_test.sqlite3";
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);

    tenriff::server::RankedDatabase database;
    std::string error;
    CHECK(database.open(path.string(), std::string(48, 's'), error));
    CHECK(error.empty());

    tenriff::server::AccountSession registered;
    tenriff::server::AccountSession invalid;
    CHECK(!database.register_account(std::string("bad\xff", 4),
                                     "correct horse battery", invalid, error));
    CHECK(database.register_account("ranked-player", "correct horse battery", registered, error));
    CHECK(!registered.bearer_token.empty());
    CHECK(registered.role == "user");
    tenriff::server::AccountSession duplicate;
    CHECK(!database.register_account("ranked-player", "another long password", duplicate, error));

    tenriff::server::AccountSession login;
    CHECK(!database.login("ranked-player", "wrong password value", login, error));
    CHECK(database.login("RANKED-PLAYER", "correct horse battery", login, error));
    CHECK(!login.bearer_token.empty());
    CHECK(login.role == "user");

    tenriff::server::AccountSession pre_admin_session;
    CHECK(database.register_account("ryui", "old regular password", pre_admin_session, error));
    const std::string admin_password = "admin password value only for tests";
    CHECK(database.provision_admin_account("ryui", admin_password, error));
    tenriff::server::GlobalChatMessage revoked_message;
    CHECK(!database.send_global_chat(pre_admin_session.bearer_token,
                                     "must be rejected", revoked_message, error));
    tenriff::server::AccountSession admin;
    CHECK(database.login("RYUI", admin_password, admin, error));
    CHECK(admin.username == "ryui");
    CHECK(admin.role == "admin");
    sqlite3* inspect = nullptr;
    CHECK(sqlite3_open_v2(path.string().c_str(), &inspect, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    if (inspect) {
        sqlite3_stmt* statement = nullptr;
        CHECK(sqlite3_prepare_v2(
                  inspect,
                  "SELECT password_salt,password_hash,password_iterations,role FROM users WHERE username='ryui'",
                  -1, &statement, nullptr) == SQLITE_OK);
        if (statement && sqlite3_step(statement) == SQLITE_ROW) {
            const std::string salt = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
            const std::string hash = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1));
            const std::string role = reinterpret_cast<const char*>(sqlite3_column_text(statement, 3));
            CHECK(salt.size() == 32);
            CHECK(hash.size() == 64);
            CHECK(hash != admin_password);
            CHECK(sqlite3_column_int(statement, 2) == 600000);
            CHECK(role == "admin");
        } else {
            CHECK(false);
        }
        if (statement) sqlite3_finalize(statement);
        sqlite3_close(inspect);
    }

    tenriff::server::GlobalChatMessage chat_message;
    error.clear();
    CHECK(database.send_global_chat(admin.bearer_token,
                                    "  [NP] Test Song - Test Artist  ",
                                    chat_message, error));
    CHECK(error.empty());
    CHECK(chat_message.username == "ryui");
    CHECK(chat_message.role == "admin");
    CHECK(chat_message.text == "[NP] Test Song - Test Artist");
    CHECK(chat_message.id > 0);
    error.clear();
    const auto chat_messages = database.global_chat_messages(
        login.bearer_token, 0, 100, error);
    CHECK(error.empty());
    CHECK(chat_messages.size() == 1);
    if (!chat_messages.empty()) {
        CHECK(chat_messages[0].id == chat_message.id);
        CHECK(chat_messages[0].username == "ryui");
        CHECK(chat_messages[0].role == "admin");
        CHECK(chat_messages[0].text == "[NP] Test Song - Test Artist");
    }
    error.clear();
    CHECK(database.global_chat_messages("invalid-token", 0, 100, error).empty());
    CHECK(!error.empty());

    const std::string chart_hash(64, 'b');
    CHECK(database.approve_bms_chart(chart_hash, "catalog/chart.bms", error));
    tenriff::server::ReplayChallenge challenge;
    CHECK(database.create_challenge(login.bearer_token, chart_hash, challenge, error));
    CHECK(challenge.chart_sha256 == chart_hash);
    CHECK(challenge.chart_path == "catalog/chart.bms");

    tenriff::server::ReplayChallenge inspected;
    CHECK(database.inspect_challenge(login.bearer_token, challenge.id, inspected, error));
    CHECK(inspected.nonce == challenge.nonce);

    tenriff::server::VerifiedReplayRecord verified;
    verified.chart_sha256 = chart_hash;
    verified.replay_sha256 = std::string(64, 'c');
    verified.score = 9876;
    verified.accuracy = 98.76;
    verified.max_combo = 321;
    verified.clear_status = "HARD";
    verified.ruleset_id = "tenriff-native-score-v2-ruleset-1";
    std::string receipt;
    CHECK(database.commit_verified_replay(login.bearer_token, challenge.id,
                                          verified, receipt, error));
    CHECK(receipt.rfind("v1.", 0) == 0);
    CHECK(!database.inspect_challenge(login.bearer_token, challenge.id, inspected, error));
    const auto leaderboard = database.leaderboard(chart_hash, 10);
    CHECK(leaderboard.size() == 1);
    if (!leaderboard.empty()) {
        CHECK(leaderboard[0].player_name == "ranked-player");
        CHECK(leaderboard[0].score == 9876);
        CHECK(leaderboard[0].verification_status == "online_verified");
    }

    tenriff::server::ReplayChallenge lower_challenge;
    CHECK(database.create_challenge(login.bearer_token, chart_hash,
                                    lower_challenge, error));
    verified.replay_sha256 = std::string(64, 'd');
    verified.score = 9000;
    verified.accuracy = 99.0;
    CHECK(database.commit_verified_replay(login.bearer_token,
                                          lower_challenge.id,
                                          verified, receipt, error));
    auto best_records = database.leaderboard(chart_hash, 10);
    CHECK(best_records.size() == 1);
    CHECK(!best_records.empty() && best_records[0].score == 9876);

    tenriff::server::ReplayChallenge better_challenge;
    CHECK(database.create_challenge(login.bearer_token, chart_hash,
                                    better_challenge, error));
    verified.replay_sha256 = std::string(64, 'f');
    verified.score = 10000;
    verified.accuracy = 97.0;
    CHECK(database.commit_verified_replay(login.bearer_token,
                                          better_challenge.id,
                                          verified, receipt, error));
    best_records = database.leaderboard(chart_hash, 10);
    CHECK(best_records.size() == 1);
    CHECK(!best_records.empty() && best_records[0].score == 10000);

    tenriff::server::ReplayChallenge overflow_challenge;
    CHECK(database.create_challenge(login.bearer_token, chart_hash,
                                    overflow_challenge, error));
    verified.replay_sha256 = std::string(64, 'e');
    verified.score = (std::numeric_limits<std::uint64_t>::max)();
    CHECK(!database.commit_verified_replay(login.bearer_token,
                                           overflow_challenge.id,
                                           verified, receipt, error));
    CHECK(database.inspect_challenge(login.bearer_token,
                                     overflow_challenge.id, inspected, error));

    CHECK(database.sync_bms_catalog({}, error));
    tenriff::server::ReplayChallenge disabled;
    CHECK(!database.create_challenge(login.bearer_token, chart_hash,
                                     disabled, error));
    CHECK(!database.inspect_challenge(login.bearer_token,
                                      overflow_challenge.id, inspected, error));
    CHECK(database.leaderboard(chart_hash, 10).empty());

    CHECK(database.sync_bms_catalog({{chart_hash, "catalog/chart.bms"}}, error));
    CHECK(database.leaderboard(chart_hash, 10).size() == 1);
    CHECK(database.create_challenge(login.bearer_token, chart_hash,
                                    disabled, error));
}

void test_ranked_database_materializes_available_charts_lazily() {
    const auto path = std::filesystem::temp_directory_path() /
                      "tenriff_server_lazy_catalog_test.sqlite3";
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);

    tenriff::server::RankedDatabase database;
    std::string error;
    CHECK(database.open(path.string(), std::string(48, 'l'), error));
    tenriff::server::AccountSession account;
    CHECK(database.register_account("lazy-player", "correct horse battery", account, error));

    const std::string chart_hash(64, 'a');
    CHECK(database.set_available_bms_catalog(
        {{chart_hash, "catalog/lazy-chart.bms"}}, error));
    CHECK(database.registered_bms_chart_count() == 0);
    CHECK(database.leaderboard(chart_hash, 10).empty());

    tenriff::server::ReplayChallenge challenge;
    CHECK(database.create_challenge(account.bearer_token, chart_hash, challenge, error));
    CHECK(challenge.chart_path == "catalog/lazy-chart.bms");
    CHECK(database.registered_bms_chart_count() == 1);

    CHECK(database.set_available_bms_catalog({}, error));
    tenriff::server::ReplayChallenge rejected;
    CHECK(!database.create_challenge(account.bearer_token, chart_hash, rejected, error));
    CHECK(!database.inspect_challenge(account.bearer_token, challenge.id, rejected, error));
    CHECK(database.leaderboard(chart_hash, 10).empty());
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

bool send_raw(TestClient& client, const std::string& data) {
    std::size_t sent_total = 0;
    while (sent_total < data.size()) {
        const int sent = send(client.socket, data.data() + sent_total,
                              static_cast<int>(data.size() - sent_total), 0);
        if (sent <= 0) return false;
        sent_total += static_cast<std::size_t>(sent);
    }
    return true;
}

std::string receive_http(TestClient& client) {
    std::string response;
    for (;;) {
        char buffer[4096];
        const int count = recv(client.socket, buffer, static_cast<int>(sizeof(buffer)), 0);
        if (count <= 0) break;
        response.append(buffer, static_cast<std::size_t>(count));
        if (response.size() > 128 * 1024) break;
    }
    return response;
}

std::string response_json_string(const std::string& response,
                                 const std::string& key) {
    const std::string marker = "\"" + key + "\":\"";
    const auto begin = response.find(marker);
    if (begin == std::string::npos) return {};
    const auto value_begin = begin + marker.size();
    const auto end = response.find('"', value_begin);
    return end == std::string::npos ? std::string{} : response.substr(value_begin, end - value_begin);
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

void test_http_records_api() {
    TestSocketRuntime sockets;
    CHECK(sockets.ok);
    if (!sockets.ok) return;

    tenriff::server::OnlineRecordStore store;
    std::string load_error;
    CHECK(store.load_json_lines("", load_error));
    tenriff::server::HttpApiOptions options;
    options.bind_address = "127.0.0.1";
    options.port = 0;
    options.server_name = "API Test";
    tenriff::server::HttpApiServer api(options, store);
    std::atomic_bool stop{false};
    std::string api_error;
    bool api_ok = false;
    std::thread worker([&] { api_ok = api.run(stop, api_error); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (api.bound_port() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(api.bound_port() != 0);

    TestClient health;
    CHECK(connect_client(health, api.bound_port()));
    CHECK(send_raw(health, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    const auto health_response = receive_http(health);
    CHECK(health_response.find("HTTP/1.1 200 OK") != std::string::npos);
    CHECK(health_response.find("\"status\":\"ok\"") != std::string::npos);

    TestClient leaderboard;
    CHECK(connect_client(leaderboard, api.bound_port()));
    CHECK(send_raw(leaderboard,
                   "GET /v1/leaderboards/" + std::string(64, 'a') +
                       "?limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    const auto leaderboard_response = receive_http(leaderboard);
    CHECK(leaderboard_response.find("HTTP/1.1 200 OK") != std::string::npos);
    CHECK(leaderboard_response.find("\"records\":[]") != std::string::npos);

    TestClient missing_length;
    CHECK(connect_client(missing_length, api.bound_port()));
    CHECK(send_raw(missing_length,
                   "POST /v1/accounts/login HTTP/1.1\r\nHost: localhost\r\n"
                   "Content-Type: application/json\r\n\r\n"));
    const auto missing_length_response = receive_http(missing_length);
    CHECK(missing_length_response.find("HTTP/1.1 411 Length Required") !=
          std::string::npos);

    stop.store(true, std::memory_order_release);
    worker.join();
    CHECK(api_ok);
    CHECK(api_error.empty());
}

void test_http_account_and_bms_challenge_api() {
    TestSocketRuntime sockets;
    CHECK(sockets.ok);
    if (!sockets.ok) return;

    const auto database_path = std::filesystem::temp_directory_path() /
                               "tenriff_server_http_ranked.sqlite3";
    std::error_code ignored;
    std::filesystem::remove(database_path, ignored);
    std::filesystem::remove(database_path.string() + "-wal", ignored);
    std::filesystem::remove(database_path.string() + "-shm", ignored);

    tenriff::server::RankedDatabase database;
    std::string database_error;
    CHECK(database.open(database_path.string(), std::string(48, 'h'), database_error));
    const std::string chart_hash(64, 'd');
    CHECK(database.approve_bms_chart(chart_hash, "catalog/ranked.bms", database_error));

    tenriff::server::OnlineRecordStore store;
    std::string load_error;
    CHECK(store.load_json_lines("", load_error));
    tenriff::server::HttpApiOptions options;
    options.bind_address = "127.0.0.1";
    options.port = 0;
    options.verifier_executable = TENRIFF_TEST_VERIFIER_PATH;
    options.multiplayer_directory =
        std::make_shared<tenriff::server::MultiplayerDirectory>();
    options.multiplayer_directory->update("API Test Room", 27301, 2, 8, false);
    tenriff::server::HttpApiServer api(options, store, &database);
    std::atomic_bool stop{false};
    std::string api_error;
    bool api_ok = false;
    std::thread worker([&] { api_ok = api.run(stop, api_error); });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (api.bound_port() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(api.bound_port() != 0);

    const std::string account_body =
        "{\"username\":\"http-player\",\"password\":\"safe password value\"}";
    TestClient account;
    CHECK(connect_client(account, api.bound_port()));
    CHECK(send_raw(account,
        "POST /v1/accounts/register HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(account_body.size()) + "\r\n\r\n" + account_body));
    const std::string account_response = receive_http(account);
    CHECK(account_response.find("HTTP/1.1 201 Created") != std::string::npos);
    CHECK(account_response.find("\"role\":\"user\"") != std::string::npos);
    const std::string token = response_json_string(account_response, "token");
    CHECK(!token.empty());

    const std::string chat_body = "{\"text\":\"hello global chat\"}";
    TestClient chat_send;
    CHECK(connect_client(chat_send, api.bound_port()));
    CHECK(send_raw(chat_send,
        "POST /v1/chat/messages HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(chat_body.size()) + "\r\n\r\n" + chat_body));
    const std::string chat_send_response = receive_http(chat_send);
    CHECK(chat_send_response.find("HTTP/1.1 201 Created") != std::string::npos);
    CHECK(chat_send_response.find("\"text\":\"hello global chat\"") != std::string::npos);

    TestClient chat_fetch;
    CHECK(connect_client(chat_fetch, api.bound_port()));
    CHECK(send_raw(chat_fetch,
        "GET /v1/chat/messages?after_id=0&limit=100 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " +
        token + "\r\n\r\n"));
    const std::string chat_fetch_response = receive_http(chat_fetch);
    CHECK(chat_fetch_response.find("HTTP/1.1 200 OK") != std::string::npos);
    CHECK(chat_fetch_response.find("\"username\":\"http-player\"") != std::string::npos);
    CHECK(chat_fetch_response.find("\"text\":\"hello global chat\"") != std::string::npos);

    TestClient rooms_fetch;
    CHECK(connect_client(rooms_fetch, api.bound_port()));
    CHECK(send_raw(rooms_fetch,
        "GET /v1/multiplayer/rooms HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " +
        token + "\r\n\r\n"));
    const std::string rooms_fetch_response = receive_http(rooms_fetch);
    CHECK(rooms_fetch_response.find("HTTP/1.1 200 OK") != std::string::npos);
    CHECK(rooms_fetch_response.find("\"name\":\"API Test Room\"") != std::string::npos);
    CHECK(rooms_fetch_response.find("\"tcp_port\":27301") != std::string::npos);
    CHECK(rooms_fetch_response.find("\"player_count\":2") != std::string::npos);
    CHECK(rooms_fetch_response.find("\"accepting_players\":true") != std::string::npos);

    TestClient rooms_unauthorized;
    CHECK(connect_client(rooms_unauthorized, api.bound_port()));
    CHECK(send_raw(rooms_unauthorized,
        "GET /v1/multiplayer/rooms HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    CHECK(receive_http(rooms_unauthorized).find("HTTP/1.1 401 Unauthorized") !=
          std::string::npos);

    TestClient chat_unauthorized;
    CHECK(connect_client(chat_unauthorized, api.bound_port()));
    CHECK(send_raw(chat_unauthorized,
        "GET /v1/chat/messages HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    CHECK(receive_http(chat_unauthorized).find("HTTP/1.1 401 Unauthorized") !=
          std::string::npos);

    const std::string challenge_body =
        "{\"chart_sha256\":\"" + chart_hash + "\"}";
    TestClient challenge;
    CHECK(connect_client(challenge, api.bound_port()));
    CHECK(send_raw(challenge,
        "POST /v1/challenges HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(challenge_body.size()) + "\r\n\r\n" + challenge_body));
    const std::string challenge_response = receive_http(challenge);
    CHECK(challenge_response.find("HTTP/1.1 201 Created") != std::string::npos);
    CHECK(!response_json_string(challenge_response, "challenge_id").empty());
    CHECK(!response_json_string(challenge_response, "nonce").empty());
    const std::string challenge_id = response_json_string(challenge_response, "challenge_id");
    const std::string nonce = response_json_string(challenge_response, "nonce");

    const std::string replay_body =
        "{\"challenge_id\":\"" + challenge_id +
        "\",\"challenge_nonce\":\"" + nonce +
        "\",\"replay_base64\":\"e30=\"}";
    TestClient replay;
    CHECK(connect_client(replay, api.bound_port()));
    CHECK(send_raw(replay,
        "POST /v1/replays HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(replay_body.size()) + "\r\n\r\n" + replay_body));
    const std::string replay_response = receive_http(replay);
    CHECK(replay_response.find("HTTP/1.1 201 Created") != std::string::npos);
    CHECK(replay_response.find("online_verified") != std::string::npos);
    CHECK(!response_json_string(replay_response, "receipt").empty());

    const std::string osu_body =
        "{\"chart_sha256\":\"" + std::string(64, 'e') + "\"}";
    TestClient osu;
    CHECK(connect_client(osu, api.bound_port()));
    CHECK(send_raw(osu,
        "POST /v1/challenges HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nContent-Type: application/json\r\nContent-Length: " +
        std::to_string(osu_body.size()) + "\r\n\r\n" + osu_body));
    const std::string osu_response = receive_http(osu);
    CHECK(osu_response.find("HTTP/1.1 422 Unprocessable Content") != std::string::npos);

    stop.store(true, std::memory_order_release);
    worker.join();
    CHECK(api_ok);
    CHECK(api_error.empty());
}

}  // namespace

int main() {
    test_protocol_golden_vector();
    test_protocol_bounds();
    test_coordinator_full_round();
    test_coordinator_rejections_and_attribution();
    test_online_record_store_filters_and_sorts();
    test_bms_catalog_default_allow_and_exclusions();
    test_ranked_database_accounts_challenges_and_verified_records();
    test_ranked_database_materializes_available_charts_lazily();
    test_tcp_handshake_and_common_library();
    test_http_records_api();
    test_http_account_and_bms_challenge_api();
    if (failures != 0) {
        std::cerr << failures << " test checks failed.\n";
        return 1;
    }
    std::cout << "All TenRiff Server tests passed.\n";
    return 0;
}
