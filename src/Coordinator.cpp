#include "tenriff_server/Coordinator.h"

#include <algorithm>
#include <unordered_set>
#include <utility>

namespace tenriff::server {

namespace {

CoordinatorResult failed(std::string error, bool disconnect = true) {
    CoordinatorResult result;
    result.error = std::move(error);
    result.disconnect_source = disconnect;
    return result;
}

bool normalize_sha256(std::string& value) {
    if (value.size() != 64u) return false;
    for (char& ch : value) {
        if (ch >= '0' && ch <= '9') continue;
        if (ch >= 'a' && ch <= 'f') continue;
        if (ch >= 'A' && ch <= 'F') {
            ch = static_cast<char>(ch - 'A' + 'a');
            continue;
        }
        return false;
    }
    return true;
}

}  // namespace

bool valid_utf8(const std::string& value) {
    std::size_t cursor = 0;
    while (cursor < value.size()) {
        const auto lead = static_cast<unsigned char>(value[cursor]);
        if (lead <= 0x7fu) {
            ++cursor;
            continue;
        }
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        if (lead >= 0xc2u && lead <= 0xdfu) {
            length = 2;
            codepoint = lead & 0x1fu;
        } else if (lead >= 0xe0u && lead <= 0xefu) {
            length = 3;
            codepoint = lead & 0x0fu;
        } else if (lead >= 0xf0u && lead <= 0xf4u) {
            length = 4;
            codepoint = lead & 0x07u;
        } else {
            return false;
        }
        if (cursor + length > value.size()) return false;
        for (std::size_t index = 1; index < length; ++index) {
            const auto continuation =
                static_cast<unsigned char>(value[cursor + index]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6u) | (continuation & 0x3fu);
        }
        if ((length == 3 && codepoint < 0x800u) ||
            (length == 4 && codepoint < 0x10000u) ||
            codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
            return false;
        }
        cursor += length;
    }
    return true;
}

std::string normalize_display_text(const std::string& value,
                                   std::size_t max_bytes) {
    if (!valid_utf8(value)) return {};
    std::string result;
    result.reserve(std::min(value.size(), max_bytes));
    std::size_t cursor = 0;
    while (cursor < value.size() && cursor < max_bytes) {
        const auto lead = static_cast<unsigned char>(value[cursor]);
        std::size_t length = 1;
        if ((lead & 0xe0u) == 0xc0u) length = 2;
        else if ((lead & 0xf0u) == 0xe0u) length = 3;
        else if ((lead & 0xf8u) == 0xf0u) length = 4;
        if (cursor + length > max_bytes) break;
        if (length == 1 && lead < 0x20u && lead != '\t') {
            result.push_back(' ');
        } else if (length == 1 && lead == 0x7fu) {
            result.push_back(' ');
        } else {
            result.append(value, cursor, length);
        }
        cursor += length;
    }
    const auto first = result.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = result.find_last_not_of(" \t\r\n");
    return result.substr(first, last - first + 1);
}

RoomCoordinator::PlayerState* RoomCoordinator::player(ConnectionId connection) {
    for (auto& entry : players_) {
        if (entry.connection == connection) return &entry;
    }
    return nullptr;
}

const RoomCoordinator::PlayerState* RoomCoordinator::player(
    ConnectionId connection) const {
    for (const auto& entry : players_) {
        if (entry.connection == connection) return &entry;
    }
    return nullptr;
}

RoomCoordinator::PlayerState* RoomCoordinator::player_by_id(
    std::uint8_t player_id) {
    for (auto& entry : players_) {
        if (entry.wire.player_id == player_id) return &entry;
    }
    return nullptr;
}

const RoomCoordinator::PlayerState* RoomCoordinator::player_by_id(
    std::uint8_t player_id) const {
    for (const auto& entry : players_) {
        if (entry.wire.player_id == player_id) return &entry;
    }
    return nullptr;
}

std::uint8_t RoomCoordinator::next_available_id() const {
    for (std::uint8_t id = 1; id <= protocol::kMaxPlayers; ++id) {
        if (!player_by_id(id)) return id;
    }
    return 0;
}

std::uint8_t RoomCoordinator::next_leader(std::uint8_t current) const {
    if (join_order_.empty()) return 0;
    const auto found = std::find(join_order_.begin(), join_order_.end(), current);
    const std::size_t start =
        found == join_order_.end()
            ? 0
            : static_cast<std::size_t>(found - join_order_.begin() + 1);
    for (std::size_t offset = 0; offset < join_order_.size(); ++offset) {
        const auto candidate = join_order_[(start + offset) % join_order_.size()];
        if (player_by_id(candidate)) return candidate;
    }
    return join_order_.front();
}

protocol::Message RoomCoordinator::make_roster() const {
    protocol::Message roster;
    roster.type = protocol::MessageType::RoomRoster;
    roster.leader_id = leader_id_;
    roster.round_active = active_round_nonce_ != 0;
    roster.nonce = active_round_nonce_;
    roster.participants.reserve(players_.size());
    for (const auto& entry : players_) roster.participants.push_back(entry.wire);
    return roster;
}

void RoomCoordinator::append_roster(CoordinatorResult& result) const {
    if (players_.empty()) return;
    result.deliveries.push_back(Delivery{kBroadcast, make_roster()});
}

bool RoomCoordinator::chart_matches(const protocol::Participant& participant) const {
    return selected_chart_hash_ != 0 &&
           participant.chart_hash == selected_chart_hash_ &&
           participant.chart_size == selected_chart_size_;
}

bool RoomCoordinator::all_ready() const {
    return players_.size() >= 2 && selected_chart_hash_ != 0 &&
           std::all_of(players_.begin(), players_.end(), [this](const auto& entry) {
               return entry.wire.ready && chart_matches(entry.wire);
           });
}

bool RoomCoordinator::all_loaded() const {
    return players_.size() >= 2 &&
           std::all_of(players_.begin(), players_.end(), [](const auto& entry) {
               return entry.wire.loaded;
           });
}

bool RoomCoordinator::all_reset() const {
    return !players_.empty() &&
           std::all_of(players_.begin(), players_.end(), [](const auto& entry) {
               return entry.wire.round_reset;
           });
}

void RoomCoordinator::clear_round(bool rotate_leader) {
    if (active_round_nonce_ != 0) last_closed_round_nonce_ = active_round_nonce_;
    active_round_nonce_ = 0;
    begin_sent_ = false;
    if (rotate_leader && players_.size() > 1) {
        leader_id_ = next_leader(leader_id_);
    }
    selected_chart_hash_ = 0;
    selected_chart_size_ = 0;
    selected_chart_name_.clear();
    for (auto& entry : players_) {
        entry.wire.ready = false;
        entry.wire.loaded = false;
        entry.wire.round_reset = false;
        entry.wire.chart_hash = 0;
        entry.wire.chart_size = 0;
        entry.wire.chart_name.clear();
        entry.has_final_score = false;
        entry.latest_score = {};
    }
}

void RoomCoordinator::cancel_launch() {
    if (active_round_nonce_ != 0) last_closed_round_nonce_ = active_round_nonce_;
    active_round_nonce_ = 0;
    begin_sent_ = false;
    for (auto& entry : players_) {
        entry.wire.ready = false;
        entry.wire.loaded = false;
        entry.wire.round_reset = false;
        entry.has_final_score = false;
        entry.latest_score = {};
    }
}

void RoomCoordinator::recompute_common_library() {
    bool ready = players_.size() >= 2;
    for (const auto& entry : players_) {
        const auto found = libraries_.find(entry.connection);
        ready = ready && found != libraries_.end() && found->second.ready;
    }
    if (!ready) {
        if (common_ready_ || !common_library_.empty()) {
            common_ready_ = false;
            common_library_.clear();
            ++common_generation_;
        }
        return;
    }

    std::unordered_set<std::string> intersection;
    if (!players_.empty()) {
        const auto& first = libraries_.at(players_.front().connection).hashes;
        intersection.insert(first.begin(), first.end());
    }
    for (std::size_t index = 1; index < players_.size() && !intersection.empty(); ++index) {
        const auto& hashes = libraries_.at(players_[index].connection).hashes;
        const std::unordered_set<std::string> lookup(hashes.begin(), hashes.end());
        for (auto iterator = intersection.begin(); iterator != intersection.end();) {
            if (lookup.find(*iterator) == lookup.end()) iterator = intersection.erase(iterator);
            else ++iterator;
        }
    }
    std::vector<std::string> sorted(intersection.begin(), intersection.end());
    std::sort(sorted.begin(), sorted.end());
    if (!common_ready_ || sorted != common_library_) {
        common_ready_ = true;
        common_library_ = std::move(sorted);
        ++common_generation_;
    }
}

CoordinatorResult RoomCoordinator::join(ConnectionId connection,
                                        std::string player_name) {
    if (connection == 0 || contains(connection)) {
        return failed("Connection is already registered.");
    }
    player_name = normalize_display_text(player_name, 64);
    if (player_name.empty()) return failed("Player name is empty or invalid UTF-8.");
    if (active_round_nonce_ != 0) return failed("Room is currently playing.");
    if (players_.size() >= protocol::kMaxPlayers) return failed("Room is full (8/8).");
    const auto id = next_available_id();
    if (id == 0) return failed("Room has no available player slot.");

    PlayerState state;
    state.connection = connection;
    state.wire.player_id = id;
    state.wire.name = std::move(player_name);
    players_.push_back(std::move(state));
    join_order_.push_back(id);
    libraries_[connection] = {};
    if (leader_id_ == 0) leader_id_ = id;
    recompute_common_library();

    CoordinatorResult result;
    protocol::Message welcome;
    welcome.type = protocol::MessageType::RoomWelcome;
    welcome.player_id = id;
    welcome.leader_id = leader_id_;
    result.deliveries.push_back(Delivery{connection, std::move(welcome)});
    append_roster(result);
    return result;
}

CoordinatorResult RoomCoordinator::leave(ConnectionId connection) {
    CoordinatorResult result;
    const auto found = std::find_if(players_.begin(), players_.end(),
                                    [connection](const auto& entry) {
                                        return entry.connection == connection;
                                    });
    if (found == players_.end()) return result;
    const auto removed_id = found->wire.player_id;
    const bool was_leader = removed_id == leader_id_;
    const auto order = std::find(join_order_.begin(), join_order_.end(), removed_id);
    const std::size_t removed_index =
        order == join_order_.end()
            ? 0
            : static_cast<std::size_t>(order - join_order_.begin());
    if (order != join_order_.end()) join_order_.erase(order);
    players_.erase(found);
    libraries_.erase(connection);

    if (players_.empty()) {
        leader_id_ = 0;
        clear_round(false);
    } else {
        if (was_leader) {
            leader_id_ = join_order_[removed_index % join_order_.size()];
            if (active_round_nonce_ == 0) clear_round(false);
        }
        if (players_.size() < 2) clear_round(false);
        else if (active_round_nonce_ != 0 && all_reset()) clear_round(true);
    }
    recompute_common_library();
    append_roster(result);
    return result;
}

CoordinatorResult RoomCoordinator::handle(ConnectionId connection,
                                          protocol::Message message) {
    auto* source = player(connection);
    if (!source) return failed("Action came from an unknown player.");
    message.player_id = source->wire.player_id;

    switch (message.type) {
        case protocol::MessageType::Disconnect: {
            auto result = leave(connection);
            result.disconnect_source = true;
            return result;
        }
        case protocol::MessageType::Chat: {
            message.text = normalize_display_text(message.text, protocol::kChatMaxBytes);
            if (message.text.empty()) return failed("Chat message is empty or invalid.");
            CoordinatorResult result;
            result.deliveries.push_back(Delivery{kBroadcast, std::move(message)});
            return result;
        }
        case protocol::MessageType::LibraryBegin: {
            auto& library = libraries_[connection];
            library.receiving = true;
            library.ready = false;
            library.expected = message.library_count;
            library.builder.clear();
            library.builder.reserve(message.library_count);
            recompute_common_library();
            return {};
        }
        case protocol::MessageType::LibraryChunk: {
            auto& library = libraries_[connection];
            if (!library.receiving ||
                library.builder.size() + message.chart_sha256.size() > library.expected) {
                return failed("Player library chunk is out of sequence.");
            }
            for (auto hash : message.chart_sha256) {
                if (!normalize_sha256(hash)) return failed("Player library hash is invalid.");
                library.builder.push_back(std::move(hash));
            }
            return {};
        }
        case protocol::MessageType::LibraryEnd: {
            auto& library = libraries_[connection];
            if (!library.receiving || library.builder.size() != library.expected) {
                return failed("Player library transfer is incomplete.");
            }
            std::sort(library.builder.begin(), library.builder.end());
            library.builder.erase(
                std::unique(library.builder.begin(), library.builder.end()),
                library.builder.end());
            library.hashes = std::move(library.builder);
            library.builder.clear();
            library.receiving = false;
            library.ready = true;
            recompute_common_library();
            return {};
        }
        case protocol::MessageType::Chart: {
            if (active_round_nonce_ != 0) return {};
            if (source->wire.player_id != leader_id_ &&
                (selected_chart_hash_ == 0 ||
                 message.chart_hash != selected_chart_hash_ ||
                 message.chart_size != selected_chart_size_)) {
                return failed("Non-leader chart does not match the room selection.");
            }
            source->wire.chart_hash = message.chart_hash;
            source->wire.chart_size = message.chart_size;
            source->wire.chart_name = normalize_display_text(message.text, 1024);
            if (source->wire.player_id == leader_id_) {
                selected_chart_hash_ = message.chart_hash;
                selected_chart_size_ = message.chart_size;
                selected_chart_name_ = source->wire.chart_name;
                for (auto& entry : players_) {
                    entry.wire.ready = false;
                    entry.wire.loaded = false;
                    entry.wire.round_reset = false;
                    entry.has_final_score = false;
                    entry.latest_score = {};
                    if (entry.wire.player_id != source->wire.player_id) {
                        entry.wire.chart_hash = 0;
                        entry.wire.chart_size = 0;
                        entry.wire.chart_name.clear();
                    }
                }
            } else {
                source->wire.ready = false;
            }
            CoordinatorResult result;
            append_roster(result);
            return result;
        }
        case protocol::MessageType::Ready: {
            if (active_round_nonce_ != 0) {
                if (!begin_sent_ && !message.ready) {
                    cancel_launch();
                    CoordinatorResult result;
                    append_roster(result);
                    return result;
                }
                return {};
            }
            if (message.ready && !chart_matches(source->wire)) {
                return failed("Ready requires the selected chart and an idle room.");
            }
            source->wire.ready = message.ready;
            if (!message.ready) source->wire.loaded = false;
            CoordinatorResult result;
            append_roster(result);
            return result;
        }
        case protocol::MessageType::Launch: {
            if (source->wire.player_id != leader_id_ || active_round_nonce_ != 0) {
                return failed("Only the current leader can launch an idle room.");
            }
            if (!all_ready()) {
                CoordinatorResult result;
                append_roster(result);
                return result;
            }
            if (message.nonce == last_closed_round_nonce_) {
                return failed("Round nonce was already used.");
            }
            active_round_nonce_ = message.nonce;
            begin_sent_ = false;
            for (auto& entry : players_) {
                entry.wire.loaded = false;
                entry.wire.round_reset = false;
                entry.has_final_score = false;
                entry.latest_score = {};
            }
            message.chart_hash = selected_chart_hash_;
            CoordinatorResult result;
            result.deliveries.push_back(Delivery{kBroadcast, std::move(message)});
            append_roster(result);
            return result;
        }
        case protocol::MessageType::Loaded: {
            if (active_round_nonce_ == 0 || message.nonce != active_round_nonce_) {
                if (message.nonce == last_closed_round_nonce_) return {};
                return failed("Loaded belongs to an unknown round.");
            }
            source->wire.loaded = true;
            CoordinatorResult result;
            append_roster(result);
            return result;
        }
        case protocol::MessageType::Begin: {
            if (source->wire.player_id != leader_id_ ||
                message.nonce != active_round_nonce_ || begin_sent_ || !all_loaded()) {
                return failed("Begin requires the leader and all loaded players.");
            }
            begin_sent_ = true;
            CoordinatorResult result;
            result.deliveries.push_back(Delivery{kBroadcast, std::move(message)});
            return result;
        }
        case protocol::MessageType::Score:
        case protocol::MessageType::FinalScore: {
            if (message.nonce != active_round_nonce_) {
                if (message.nonce == last_closed_round_nonce_) return {};
                return failed("Score belongs to an unknown round.");
            }
            if (!protocol::score_claim_is_sane(message.score)) {
                return failed("Score claim is outside wire safety limits.");
            }
            source->latest_score = message.score;
            source->has_final_score = message.type == protocol::MessageType::FinalScore &&
                                      message.score.finished;
            CoordinatorResult result;
            result.deliveries.push_back(Delivery{kBroadcast, std::move(message)});
            return result;
        }
        case protocol::MessageType::RoundReset: {
            if (message.nonce != active_round_nonce_) {
                if (message.nonce == last_closed_round_nonce_) return {};
                return failed("Round reset belongs to an unknown round.");
            }
            if (!source->has_final_score) {
                return failed("Player reset before sending a final score.");
            }
            source->wire.round_reset = true;
            source->wire.ready = false;
            source->wire.loaded = false;
            if (all_reset()) clear_round(true);
            CoordinatorResult result;
            append_roster(result);
            return result;
        }
        case protocol::MessageType::Ping:
        case protocol::MessageType::Pong:
            return {};
        default:
            return failed("Unsupported player action.");
    }
}

bool RoomCoordinator::contains(ConnectionId connection) const {
    return player(connection) != nullptr;
}

std::size_t RoomCoordinator::player_count() const {
    return players_.size();
}

RoomSnapshot RoomCoordinator::snapshot() const {
    RoomSnapshot result;
    result.leader_id = leader_id_;
    result.active_round_nonce = active_round_nonce_;
    result.begin_sent = begin_sent_;
    result.participants.reserve(players_.size());
    for (const auto& entry : players_) result.participants.push_back(entry.wire);
    return result;
}

bool RoomCoordinator::common_library_ready() const { return common_ready_; }

std::uint64_t RoomCoordinator::common_library_generation() const {
    return common_generation_;
}

const std::vector<std::string>& RoomCoordinator::common_library() const {
    return common_library_;
}

}  // namespace tenriff::server
