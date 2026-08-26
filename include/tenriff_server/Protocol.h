#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tenriff::server::protocol {

constexpr std::uint16_t kVersion = 5;
constexpr std::uint8_t kMaxPlayers = 8;
constexpr std::size_t kChatMaxBytes = 256;
constexpr std::size_t kLibraryHashesPerChunk = 512;
constexpr std::size_t kLibraryMaxCharts = 250'000;
constexpr std::size_t kFrameHeaderSize = 12;
constexpr std::size_t kMaxPayloadSize = 64 * 1024;
constexpr std::int64_t kMaximumClaimedScore = 10'000;
constexpr int kMaximumJudgementCount = 10'000'000;

enum class MessageType : std::uint16_t {
    Hello = 1,
    Chart = 2,
    Ready = 3,
    Launch = 4,
    Loaded = 5,
    Begin = 6,
    Score = 7,
    FinalScore = 8,
    Ping = 9,
    Pong = 10,
    Disconnect = 11,
    RoundReset = 12,
    RoundCancel = 13,
    RoundCancelAck = 14,
    LibraryBegin = 15,
    LibraryChunk = 16,
    LibraryEnd = 17,
    RoomWelcome = 18,
    RoomRoster = 19,
    CommonLibraryBegin = 20,
    CommonLibraryChunk = 21,
    CommonLibraryEnd = 22,
    Chat = 23,
};

struct Score {
    std::int64_t score = 0;
    std::int64_t current_sample = 0;
    int combo = 0;
    int max_combo = 0;
    int perfect = 0;
    int great = 0;
    int good = 0;
    int bad = 0;
    int poor = 0;
    int gauge_milli = 0;
    bool finished = false;
    bool game_over = false;
    bool aborted = false;
};

[[nodiscard]] bool score_claim_is_sane(const Score& score);

struct Participant {
    std::uint8_t player_id = 0;
    std::string name;
    bool ready = false;
    bool loaded = false;
    bool round_reset = false;
    std::uint64_t chart_hash = 0;
    std::uint64_t chart_size = 0;
    std::string chart_name;
};

struct Message {
    MessageType type = MessageType::Hello;
    std::string text;
    std::uint64_t chart_hash = 0;
    std::uint64_t chart_size = 0;
    std::uint64_t nonce = 0;
    std::uint32_t delay_ms = 0;
    bool ready = false;
    std::uint8_t player_id = 0;
    std::uint8_t leader_id = 0;
    bool round_active = false;
    Score score;
    std::uint32_t library_count = 0;
    std::vector<std::string> chart_sha256;
    std::vector<Participant> participants;
};

enum class DecodeStatus {
    Complete,
    Incomplete,
    Error,
};

[[nodiscard]] std::vector<std::uint8_t> encode(const Message& message,
                                               std::string* error = nullptr);

[[nodiscard]] DecodeStatus decode(const std::vector<std::uint8_t>& bytes,
                                  Message& message,
                                  std::size_t& consumed,
                                  std::string& error);

}  // namespace tenriff::server::protocol
