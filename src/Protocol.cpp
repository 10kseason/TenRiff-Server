#include "tenriff_server/Protocol.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace tenriff::server::protocol {

namespace {

constexpr std::uint32_t kFrameMagic = 0x54525031u;  // "TRP1"
constexpr std::size_t kMaxTextBytes = 1024;

void set_error(std::string* target, std::string value) {
    if (target) *target = std::move(value);
}

void append_u8(std::vector<std::uint8_t>& out, std::uint8_t value) {
    out.push_back(value);
}

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(
            (value >> static_cast<unsigned>(shift)) & 0xffu));
    }
}

void append_i32(std::vector<std::uint8_t>& out, int value) {
    append_u32(out, static_cast<std::uint32_t>(static_cast<std::int32_t>(value)));
}

void append_i64(std::vector<std::uint8_t>& out, std::int64_t value) {
    append_u64(out, static_cast<std::uint64_t>(value));
}

bool append_string(std::vector<std::uint8_t>& out,
                   const std::string& value,
                   std::string* error) {
    if (value.size() > kMaxTextBytes ||
        value.size() > std::numeric_limits<std::uint16_t>::max()) {
        set_error(error, "Protocol text field is too long.");
        return false;
    }
    append_u16(out, static_cast<std::uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
    return true;
}

int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

bool append_sha256(std::vector<std::uint8_t>& out,
                   const std::string& value,
                   std::string* error) {
    if (value.size() != 64u) {
        set_error(error, "Library SHA-256 values must contain 64 hex characters.");
        return false;
    }
    for (std::size_t index = 0; index < value.size(); index += 2) {
        const int high = hex_nibble(value[index]);
        const int low = hex_nibble(value[index + 1]);
        if (high < 0 || low < 0) {
            set_error(error, "Library SHA-256 values must be hexadecimal.");
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return true;
}

class Reader {
public:
    Reader(const std::vector<std::uint8_t>& bytes,
           std::size_t offset,
           std::size_t limit)
        : bytes_(bytes), cursor_(offset), limit_(limit) {}

    bool read_u8(std::uint8_t& value) {
        if (cursor_ + 1 > limit_) return false;
        value = bytes_[cursor_++];
        return true;
    }

    bool read_u16(std::uint16_t& value) {
        if (cursor_ + 2 > limit_) return false;
        value = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes_[cursor_]) << 8u) |
            static_cast<std::uint16_t>(bytes_[cursor_ + 1]));
        cursor_ += 2;
        return true;
    }

    bool read_u32(std::uint32_t& value) {
        if (cursor_ + 4 > limit_) return false;
        value = (static_cast<std::uint32_t>(bytes_[cursor_]) << 24u) |
                (static_cast<std::uint32_t>(bytes_[cursor_ + 1]) << 16u) |
                (static_cast<std::uint32_t>(bytes_[cursor_ + 2]) << 8u) |
                static_cast<std::uint32_t>(bytes_[cursor_ + 3]);
        cursor_ += 4;
        return true;
    }

    bool read_u64(std::uint64_t& value) {
        if (cursor_ + 8 > limit_) return false;
        value = 0;
        for (int index = 0; index < 8; ++index) {
            value = (value << 8u) |
                    static_cast<std::uint64_t>(
                        bytes_[cursor_ + static_cast<std::size_t>(index)]);
        }
        cursor_ += 8;
        return true;
    }

    bool read_i32(int& value) {
        std::uint32_t encoded = 0;
        if (!read_u32(encoded)) return false;
        value = static_cast<std::int32_t>(encoded);
        return true;
    }

    bool read_i64(std::int64_t& value) {
        std::uint64_t encoded = 0;
        if (!read_u64(encoded)) return false;
        value = static_cast<std::int64_t>(encoded);
        return true;
    }

    bool read_string(std::string& value) {
        std::uint16_t size = 0;
        if (!read_u16(size) || size > kMaxTextBytes || cursor_ + size > limit_) {
            return false;
        }
        value.assign(reinterpret_cast<const char*>(bytes_.data() + cursor_), size);
        cursor_ += size;
        return true;
    }

    bool read_sha256(std::string& value) {
        constexpr char kHex[] = "0123456789abcdef";
        constexpr std::size_t kHashBytes = 32;
        if (cursor_ + kHashBytes > limit_) return false;
        value.resize(kHashBytes * 2);
        for (std::size_t index = 0; index < kHashBytes; ++index) {
            const std::uint8_t byte = bytes_[cursor_++];
            value[index * 2] = kHex[(byte >> 4u) & 0x0fu];
            value[index * 2 + 1] = kHex[byte & 0x0fu];
        }
        return true;
    }

    [[nodiscard]] bool at_end() const { return cursor_ == limit_; }

private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t cursor_ = 0;
    std::size_t limit_ = 0;
};

bool is_known_type(std::uint16_t raw) {
    return raw >= static_cast<std::uint16_t>(MessageType::Hello) &&
           raw <= static_cast<std::uint16_t>(MessageType::Chat);
}

bool decode_score(Reader& reader, Score& score) {
    std::uint8_t flags = 0;
    if (!reader.read_i64(score.score) ||
        !reader.read_i64(score.current_sample) ||
        !reader.read_i32(score.combo) ||
        !reader.read_i32(score.max_combo) ||
        !reader.read_i32(score.perfect) ||
        !reader.read_i32(score.great) ||
        !reader.read_i32(score.good) ||
        !reader.read_i32(score.bad) ||
        !reader.read_i32(score.poor) ||
        !reader.read_i32(score.gauge_milli) ||
        !reader.read_u8(flags)) {
        return false;
    }
    score.finished = (flags & 0x01u) != 0u;
    score.game_over = (flags & 0x02u) != 0u;
    score.aborted = (flags & 0x04u) != 0u;
    return score_claim_is_sane(score);
}

}  // namespace

bool score_claim_is_sane(const Score& score) {
    constexpr std::int64_t kMaximumAbsoluteSample = 10'000'000'000'000ll;
    if (score.score < 0 || score.score > kMaximumClaimedScore ||
        score.current_sample < -kMaximumAbsoluteSample ||
        score.current_sample > kMaximumAbsoluteSample ||
        score.combo < 0 || score.max_combo < 0 || score.combo > score.max_combo ||
        score.max_combo > kMaximumJudgementCount ||
        score.perfect < 0 || score.great < 0 || score.good < 0 ||
        score.bad < 0 || score.poor < 0 ||
        score.perfect > kMaximumJudgementCount ||
        score.great > kMaximumJudgementCount ||
        score.good > kMaximumJudgementCount ||
        score.bad > kMaximumJudgementCount ||
        score.poor > kMaximumJudgementCount ||
        score.gauge_milli < 0 || score.gauge_milli > 100'000) {
        return false;
    }
    const std::int64_t judged = static_cast<std::int64_t>(score.perfect) +
                                score.great + score.good + score.bad + score.poor;
    return judged <= kMaximumJudgementCount;
}

std::vector<std::uint8_t> encode(const Message& message, std::string* error) {
    if (error) error->clear();
    std::vector<std::uint8_t> payload;

    switch (message.type) {
        case MessageType::Hello:
        case MessageType::Disconnect:
            if (!append_string(payload, message.text, error)) return {};
            break;
        case MessageType::Chat:
            if (message.text.empty() || message.text.size() > kChatMaxBytes) {
                set_error(error, "Chat message is empty or too long.");
                return {};
            }
            append_u8(payload, message.player_id);
            if (!append_string(payload, message.text, error)) return {};
            break;
        case MessageType::Chart:
            if (message.chart_hash == 0) {
                set_error(error, "Chart messages require a non-zero fingerprint.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u64(payload, message.chart_hash);
            append_u64(payload, message.chart_size);
            if (!append_string(payload, message.text, error)) return {};
            break;
        case MessageType::Ready:
            append_u8(payload, message.player_id);
            append_u8(payload, message.ready ? 1u : 0u);
            break;
        case MessageType::Launch:
            if (message.chart_hash == 0 || message.nonce == 0) {
                set_error(error, "Launch requires a non-zero fingerprint and round nonce.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u64(payload, message.chart_hash);
            append_u64(payload, message.nonce);
            break;
        case MessageType::Loaded:
            if (message.nonce == 0) {
                set_error(error, "Loaded requires a non-zero round nonce.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u64(payload, message.nonce);
            break;
        case MessageType::Begin:
            if (message.nonce == 0) {
                set_error(error, "Begin requires a non-zero round nonce.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u64(payload, message.nonce);
            append_u32(payload, message.delay_ms);
            break;
        case MessageType::Score:
        case MessageType::FinalScore: {
            if (message.nonce == 0) {
                set_error(error, "Score requires a non-zero round nonce.");
                return {};
            }
            if (!score_claim_is_sane(message.score)) {
                set_error(error, "Score claim is outside wire safety limits.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u64(payload, message.nonce);
            append_i64(payload, message.score.score);
            append_i64(payload, message.score.current_sample);
            append_i32(payload, message.score.combo);
            append_i32(payload, message.score.max_combo);
            append_i32(payload, message.score.perfect);
            append_i32(payload, message.score.great);
            append_i32(payload, message.score.good);
            append_i32(payload, message.score.bad);
            append_i32(payload, message.score.poor);
            append_i32(payload, message.score.gauge_milli);
            const std::uint8_t flags = (message.score.finished ? 0x01u : 0u) |
                                       (message.score.game_over ? 0x02u : 0u) |
                                       (message.score.aborted ? 0x04u : 0u);
            append_u8(payload, flags);
            break;
        }
        case MessageType::Ping:
        case MessageType::Pong:
            append_u64(payload, message.nonce);
            break;
        case MessageType::RoundReset:
        case MessageType::RoundCancel:
        case MessageType::RoundCancelAck:
            if (message.nonce == 0) {
                set_error(error, "Round control requires a non-zero round nonce.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u64(payload, message.nonce);
            break;
        case MessageType::LibraryBegin:
        case MessageType::CommonLibraryBegin:
            if (message.library_count > kLibraryMaxCharts) {
                set_error(error, "Library exceeds the chart limit.");
                return {};
            }
            append_u32(payload, message.library_count);
            break;
        case MessageType::LibraryChunk:
        case MessageType::CommonLibraryChunk:
            if (message.chart_sha256.empty() ||
                message.chart_sha256.size() > kLibraryHashesPerChunk) {
                set_error(error, "Library chunk has an invalid hash count.");
                return {};
            }
            append_u16(payload,
                       static_cast<std::uint16_t>(message.chart_sha256.size()));
            for (const auto& sha256 : message.chart_sha256) {
                if (!append_sha256(payload, sha256, error)) return {};
            }
            break;
        case MessageType::LibraryEnd:
        case MessageType::CommonLibraryEnd:
            break;
        case MessageType::RoomWelcome:
            if (message.player_id == 0 || message.player_id > kMaxPlayers ||
                message.leader_id == 0 || message.leader_id > kMaxPlayers) {
                set_error(error, "Room welcome contains an invalid player id.");
                return {};
            }
            append_u8(payload, message.player_id);
            append_u8(payload, message.leader_id);
            break;
        case MessageType::RoomRoster:
            if (message.leader_id == 0 || message.leader_id > kMaxPlayers ||
                message.participants.empty() ||
                message.participants.size() > kMaxPlayers) {
                set_error(error, "Room roster has invalid player metadata.");
                return {};
            }
            append_u8(payload, message.leader_id);
            append_u8(payload, message.round_active ? 1u : 0u);
            append_u64(payload, message.nonce);
            append_u8(payload,
                      static_cast<std::uint8_t>(message.participants.size()));
            for (const auto& participant : message.participants) {
                if (participant.player_id == 0 ||
                    participant.player_id > kMaxPlayers) {
                    set_error(error, "Room roster contains an invalid player id.");
                    return {};
                }
                append_u8(payload, participant.player_id);
                const std::uint8_t flags = (participant.ready ? 0x01u : 0u) |
                                           (participant.loaded ? 0x02u : 0u) |
                                           (participant.round_reset ? 0x04u : 0u) |
                                           (participant.chart_hash != 0 ? 0x08u : 0u);
                append_u8(payload, flags);
                if (!append_string(payload, participant.name, error)) return {};
                if (participant.chart_hash != 0) {
                    append_u64(payload, participant.chart_hash);
                    append_u64(payload, participant.chart_size);
                    if (!append_string(payload, participant.chart_name, error)) return {};
                }
            }
            break;
        default:
            set_error(error, "Unknown protocol message type.");
            return {};
    }

    if (payload.size() > kMaxPayloadSize) {
        set_error(error, "Protocol payload exceeds the size limit.");
        return {};
    }
    std::vector<std::uint8_t> frame;
    frame.reserve(kFrameHeaderSize + payload.size());
    append_u32(frame, kFrameMagic);
    append_u16(frame, kVersion);
    append_u16(frame, static_cast<std::uint16_t>(message.type));
    append_u32(frame, static_cast<std::uint32_t>(payload.size()));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

DecodeStatus decode(const std::vector<std::uint8_t>& bytes,
                    Message& message,
                    std::size_t& consumed,
                    std::string& error) {
    consumed = 0;
    error.clear();
    if (bytes.size() < kFrameHeaderSize) return DecodeStatus::Incomplete;

    Reader header(bytes, 0, kFrameHeaderSize);
    std::uint32_t magic = 0;
    std::uint16_t version = 0;
    std::uint16_t raw_type = 0;
    std::uint32_t payload_size = 0;
    if (!header.read_u32(magic) || !header.read_u16(version) ||
        !header.read_u16(raw_type) || !header.read_u32(payload_size)) {
        error = "Malformed protocol header.";
        return DecodeStatus::Error;
    }
    if (magic != kFrameMagic) {
        error = "Protocol magic does not match.";
        return DecodeStatus::Error;
    }
    if (version != kVersion) {
        error = "Protocol version does not match.";
        return DecodeStatus::Error;
    }
    if (!is_known_type(raw_type)) {
        error = "Protocol message type is unknown.";
        return DecodeStatus::Error;
    }
    if (payload_size > kMaxPayloadSize) {
        error = "Protocol payload exceeds the size limit.";
        return DecodeStatus::Error;
    }

    const std::size_t frame_size =
        kFrameHeaderSize + static_cast<std::size_t>(payload_size);
    if (bytes.size() < frame_size) return DecodeStatus::Incomplete;

    Message decoded;
    decoded.type = static_cast<MessageType>(raw_type);
    Reader payload(bytes, kFrameHeaderSize, frame_size);
    bool valid = true;
    switch (decoded.type) {
        case MessageType::Hello:
        case MessageType::Disconnect:
            valid = payload.read_string(decoded.text);
            break;
        case MessageType::Chat:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_string(decoded.text) &&
                    !decoded.text.empty() && decoded.text.size() <= kChatMaxBytes;
            break;
        case MessageType::Chart:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u64(decoded.chart_hash) && decoded.chart_hash != 0 &&
                    payload.read_u64(decoded.chart_size) &&
                    payload.read_string(decoded.text);
            break;
        case MessageType::Ready: {
            std::uint8_t value = 0;
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u8(value) && value <= 1;
            decoded.ready = value != 0;
            break;
        }
        case MessageType::Launch:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u64(decoded.chart_hash) && decoded.chart_hash != 0 &&
                    payload.read_u64(decoded.nonce) && decoded.nonce != 0;
            break;
        case MessageType::Loaded:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u64(decoded.nonce) && decoded.nonce != 0;
            break;
        case MessageType::Begin:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u64(decoded.nonce) && decoded.nonce != 0 &&
                    payload.read_u32(decoded.delay_ms);
            break;
        case MessageType::Score:
        case MessageType::FinalScore:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u64(decoded.nonce) && decoded.nonce != 0 &&
                    decode_score(payload, decoded.score);
            if (decoded.type == MessageType::FinalScore) decoded.score.finished = true;
            break;
        case MessageType::Ping:
        case MessageType::Pong:
            valid = payload.read_u64(decoded.nonce);
            break;
        case MessageType::RoundReset:
        case MessageType::RoundCancel:
        case MessageType::RoundCancelAck:
            valid = payload.read_u8(decoded.player_id) &&
                    payload.read_u64(decoded.nonce) && decoded.nonce != 0;
            break;
        case MessageType::LibraryBegin:
        case MessageType::CommonLibraryBegin:
            valid = payload.read_u32(decoded.library_count) &&
                    decoded.library_count <= kLibraryMaxCharts;
            break;
        case MessageType::LibraryChunk:
        case MessageType::CommonLibraryChunk: {
            std::uint16_t count = 0;
            valid = payload.read_u16(count) && count > 0 &&
                    count <= kLibraryHashesPerChunk;
            if (valid) decoded.chart_sha256.reserve(count);
            for (std::uint16_t index = 0; valid && index < count; ++index) {
                std::string sha256;
                valid = payload.read_sha256(sha256);
                if (valid) decoded.chart_sha256.push_back(std::move(sha256));
            }
            break;
        }
        case MessageType::LibraryEnd:
        case MessageType::CommonLibraryEnd:
            break;
        case MessageType::RoomWelcome:
            valid = payload.read_u8(decoded.player_id) &&
                    decoded.player_id > 0 && decoded.player_id <= kMaxPlayers &&
                    payload.read_u8(decoded.leader_id) &&
                    decoded.leader_id > 0 && decoded.leader_id <= kMaxPlayers;
            break;
        case MessageType::RoomRoster: {
            std::uint8_t active = 0;
            std::uint8_t count = 0;
            valid = payload.read_u8(decoded.leader_id) &&
                    decoded.leader_id > 0 && decoded.leader_id <= kMaxPlayers &&
                    payload.read_u8(active) && active <= 1 &&
                    payload.read_u64(decoded.nonce) &&
                    payload.read_u8(count) && count > 0 && count <= kMaxPlayers;
            decoded.round_active = active != 0;
            if (valid) decoded.participants.reserve(count);
            for (std::uint8_t index = 0; valid && index < count; ++index) {
                Participant participant;
                std::uint8_t flags = 0;
                valid = payload.read_u8(participant.player_id) &&
                        participant.player_id > 0 &&
                        participant.player_id <= kMaxPlayers &&
                        payload.read_u8(flags) &&
                        payload.read_string(participant.name);
                participant.ready = (flags & 0x01u) != 0u;
                participant.loaded = (flags & 0x02u) != 0u;
                participant.round_reset = (flags & 0x04u) != 0u;
                if (valid && (flags & 0x08u) != 0u) {
                    valid = payload.read_u64(participant.chart_hash) &&
                            participant.chart_hash != 0 &&
                            payload.read_u64(participant.chart_size) &&
                            payload.read_string(participant.chart_name);
                }
                if (valid) decoded.participants.push_back(std::move(participant));
            }
            break;
        }
        default:
            valid = false;
            break;
    }
    if (!valid || !payload.at_end()) {
        error = "Malformed protocol payload.";
        return DecodeStatus::Error;
    }
    message = std::move(decoded);
    consumed = frame_size;
    return DecodeStatus::Complete;
}

}  // namespace tenriff::server::protocol
