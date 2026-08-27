#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

namespace tenriff::server {

struct MultiplayerRoomStatus {
    std::string id = "main";
    std::string name;
    std::uint16_t tcp_port = 0;
    std::uint8_t player_count = 0;
    std::uint8_t max_players = 8;
    bool accepting_players = false;
    bool round_active = false;
    std::uint64_t revision = 0;
};

class MultiplayerDirectory {
public:
    void update(std::string name,
                std::uint16_t tcp_port,
                std::uint8_t player_count,
                std::uint8_t max_players,
                bool round_active) {
        std::lock_guard<std::mutex> lock(mutex_);
        status_.name = std::move(name);
        status_.tcp_port = tcp_port;
        status_.player_count = player_count;
        status_.max_players = max_players;
        status_.round_active = round_active;
        status_.accepting_players = tcp_port != 0 && !round_active &&
                                    player_count < max_players;
        ++status_.revision;
    }

    [[nodiscard]] MultiplayerRoomStatus snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return status_;
    }

private:
    mutable std::mutex mutex_;
    MultiplayerRoomStatus status_{};
};

}  // namespace tenriff::server
