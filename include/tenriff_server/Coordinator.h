#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "tenriff_server/Protocol.h"

namespace tenriff::server {

using ConnectionId = std::uint64_t;
inline constexpr ConnectionId kBroadcast = 0;

struct Delivery {
    ConnectionId target = kBroadcast;
    protocol::Message message;
};

struct CoordinatorResult {
    std::vector<Delivery> deliveries;
    bool disconnect_source = false;
    std::string error;

    [[nodiscard]] bool success() const { return error.empty(); }
};

struct RoomSnapshot {
    std::uint8_t leader_id = 0;
    std::uint64_t active_round_nonce = 0;
    bool begin_sent = false;
    std::vector<protocol::Participant> participants;
};

class RoomCoordinator {
public:
    [[nodiscard]] CoordinatorResult join(ConnectionId connection,
                                         std::string player_name);
    [[nodiscard]] CoordinatorResult leave(ConnectionId connection);
    [[nodiscard]] CoordinatorResult handle(ConnectionId connection,
                                           protocol::Message message);

    [[nodiscard]] bool contains(ConnectionId connection) const;
    [[nodiscard]] std::size_t player_count() const;
    [[nodiscard]] RoomSnapshot snapshot() const;

    [[nodiscard]] bool common_library_ready() const;
    [[nodiscard]] std::uint64_t common_library_generation() const;
    [[nodiscard]] const std::vector<std::string>& common_library() const;

private:
    struct PlayerState {
        ConnectionId connection = 0;
        protocol::Participant wire;
        bool has_final_score = false;
        protocol::Score latest_score;
    };

    struct LibraryState {
        bool receiving = false;
        bool ready = false;
        std::uint32_t expected = 0;
        std::vector<std::string> builder;
        std::vector<std::string> hashes;
    };

    [[nodiscard]] PlayerState* player(ConnectionId connection);
    [[nodiscard]] const PlayerState* player(ConnectionId connection) const;
    [[nodiscard]] PlayerState* player_by_id(std::uint8_t player_id);
    [[nodiscard]] const PlayerState* player_by_id(std::uint8_t player_id) const;
    [[nodiscard]] std::uint8_t next_available_id() const;
    [[nodiscard]] std::uint8_t next_leader(std::uint8_t current) const;

    [[nodiscard]] protocol::Message make_roster() const;
    void append_roster(CoordinatorResult& result) const;
    void recompute_common_library();
    void clear_round(bool rotate_leader);
    void cancel_launch();

    [[nodiscard]] bool all_ready() const;
    [[nodiscard]] bool all_loaded() const;
    [[nodiscard]] bool all_reset() const;
    [[nodiscard]] bool chart_matches(const protocol::Participant& participant) const;

    std::vector<PlayerState> players_;
    std::vector<std::uint8_t> join_order_;
    std::unordered_map<ConnectionId, LibraryState> libraries_;
    std::uint8_t leader_id_ = 0;
    std::uint64_t active_round_nonce_ = 0;
    std::uint64_t last_closed_round_nonce_ = 0;
    bool begin_sent_ = false;
    std::uint64_t selected_chart_hash_ = 0;
    std::uint64_t selected_chart_size_ = 0;
    std::string selected_chart_name_;

    bool common_ready_ = false;
    std::uint64_t common_generation_ = 1;
    std::vector<std::string> common_library_;
};

[[nodiscard]] bool valid_utf8(const std::string& value);
[[nodiscard]] std::string normalize_display_text(const std::string& value,
                                                 std::size_t max_bytes);

}  // namespace tenriff::server
