#include "tenriff_server/OnlineRecordStore.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>
#include <unordered_map>

#include "tenriff_server/Coordinator.h"

namespace tenriff::server {
namespace {

constexpr std::size_t kMaximumRecords = 100'000;
constexpr std::size_t kMaximumLineBytes = 64 * 1024;

enum class JsonFieldType { String, Number, Literal };

struct JsonField {
    JsonFieldType type = JsonFieldType::Literal;
    std::string value;
};

using JsonObject = std::unordered_map<std::string, JsonField>;

void skip_space(std::string_view input, std::size_t& cursor) {
    while (cursor < input.size() &&
           (input[cursor] == ' ' || input[cursor] == '\t' ||
            input[cursor] == '\r' || input[cursor] == '\n')) {
        ++cursor;
    }
}

bool append_utf8(std::string& output, unsigned codepoint) {
    if (codepoint <= 0x7f) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else if (codepoint >= 0xd800 && codepoint <= 0xdfff) {
        return false;
    } else if (codepoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else {
        return false;
    }
    return true;
}

bool parse_json_string(std::string_view input,
                       std::size_t& cursor,
                       std::string& output) {
    if (cursor >= input.size() || input[cursor++] != '"') return false;
    output.clear();
    while (cursor < input.size()) {
        const unsigned char value = static_cast<unsigned char>(input[cursor++]);
        if (value == '"') return true;
        if (value < 0x20) return false;
        if (value != '\\') {
            output.push_back(static_cast<char>(value));
            continue;
        }
        if (cursor >= input.size()) return false;
        const char escaped = input[cursor++];
        switch (escaped) {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        case 'u': {
            if (cursor + 4 > input.size()) return false;
            unsigned codepoint = 0;
            for (int index = 0; index < 4; ++index) {
                const char digit = input[cursor++];
                codepoint <<= 4;
                if (digit >= '0' && digit <= '9') codepoint |= digit - '0';
                else if (digit >= 'a' && digit <= 'f') codepoint |= digit - 'a' + 10;
                else if (digit >= 'A' && digit <= 'F') codepoint |= digit - 'A' + 10;
                else return false;
            }
            if (!append_utf8(output, codepoint)) return false;
            break;
        }
        default: return false;
        }
    }
    return false;
}

bool parse_flat_object(std::string_view input,
                       JsonObject& output,
                       std::string& error) {
    std::size_t cursor = 0;
    skip_space(input, cursor);
    if (cursor >= input.size() || input[cursor++] != '{') {
        error = "record must be a JSON object";
        return false;
    }
    output.clear();
    for (;;) {
        skip_space(input, cursor);
        if (cursor < input.size() && input[cursor] == '}') {
            ++cursor;
            break;
        }
        std::string key;
        if (!parse_json_string(input, cursor, key)) {
            error = "record contains an invalid JSON key";
            return false;
        }
        skip_space(input, cursor);
        if (cursor >= input.size() || input[cursor++] != ':') {
            error = "record key is missing ':'";
            return false;
        }
        skip_space(input, cursor);
        JsonField field;
        if (cursor < input.size() && input[cursor] == '"') {
            field.type = JsonFieldType::String;
            if (!parse_json_string(input, cursor, field.value)) {
                error = "record contains an invalid JSON string";
                return false;
            }
        } else {
            const auto begin = cursor;
            while (cursor < input.size() && input[cursor] != ',' &&
                   input[cursor] != '}' && input[cursor] != ' ' &&
                   input[cursor] != '\t' && input[cursor] != '\r' &&
                   input[cursor] != '\n') {
                ++cursor;
            }
            field.value = std::string(input.substr(begin, cursor - begin));
            if (field.value.empty()) {
                error = "record contains an empty JSON value";
                return false;
            }
            field.type = (field.value == "true" || field.value == "false" ||
                          field.value == "null")
                             ? JsonFieldType::Literal
                             : JsonFieldType::Number;
        }
        if (!output.emplace(std::move(key), std::move(field)).second) {
            error = "record contains a duplicate key";
            return false;
        }
        skip_space(input, cursor);
        if (cursor >= input.size()) {
            error = "record JSON is incomplete";
            return false;
        }
        if (input[cursor] == ',') {
            ++cursor;
            continue;
        }
        if (input[cursor] == '}') {
            ++cursor;
            break;
        }
        error = "record contains an unsupported nested JSON value";
        return false;
    }
    skip_space(input, cursor);
    if (cursor != input.size()) {
        error = "record contains trailing JSON data";
        return false;
    }
    return true;
}

bool get_string(const JsonObject& object,
                const char* key,
                std::string& output) {
    const auto found = object.find(key);
    if (found == object.end() || found->second.type != JsonFieldType::String) {
        return false;
    }
    output = found->second.value;
    return true;
}

template <typename Integer>
bool get_integer(const JsonObject& object, const char* key, Integer& output) {
    const auto found = object.find(key);
    if (found == object.end() || found->second.type != JsonFieldType::Number ||
        found->second.value.empty() || found->second.value.front() == '-') {
        return false;
    }
    unsigned long long value = 0;
    const auto parsed = std::from_chars(found->second.value.data(),
                                        found->second.value.data() +
                                            found->second.value.size(),
                                        value);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != found->second.value.data() + found->second.value.size() ||
        value > std::numeric_limits<Integer>::max()) {
        return false;
    }
    output = static_cast<Integer>(value);
    return true;
}

bool get_double(const JsonObject& object, const char* key, double& output) {
    const auto found = object.find(key);
    if (found == object.end() || found->second.type != JsonFieldType::Number) {
        return false;
    }
    try {
        std::size_t consumed = 0;
        output = std::stod(found->second.value, &consumed);
        return consumed == found->second.value.size() && std::isfinite(output);
    } catch (...) {
        return false;
    }
}

bool record_from_object(const JsonObject& object, OnlineRecord& record) {
    return get_string(object, "chart_sha256", record.chart_sha256) &&
           get_string(object, "chart_format", record.chart_format) &&
           get_string(object, "player_name", record.player_name) &&
           get_integer(object, "score", record.score) &&
           get_double(object, "accuracy", record.accuracy) &&
           get_integer(object, "max_combo", record.max_combo) &&
           get_string(object, "clear_status", record.clear_status) &&
           get_string(object, "ruleset_id", record.ruleset_id) &&
           get_string(object, "verification_status", record.verification_status) &&
           get_string(object, "verified_at_utc", record.verified_at_utc);
}

bool is_rankable(const OnlineRecord& record) {
    return is_sha256_hex(record.chart_sha256) && record.chart_format == "bms" &&
           record.verification_status == "online_verified" &&
           valid_utf8(record.player_name) && valid_utf8(record.clear_status) &&
           valid_utf8(record.ruleset_id) && valid_utf8(record.verified_at_utc) &&
           !record.player_name.empty() && record.player_name.size() <= 64 &&
           record.score <= 1'000'000'000ULL && record.accuracy >= 0.0 &&
           record.accuracy <= 100.0 && record.clear_status.size() <= 32 &&
           !record.ruleset_id.empty() && record.ruleset_id.size() <= 64 &&
           !record.verified_at_utc.empty() && record.verified_at_utc.size() <= 64;
}

std::string escape_json(std::string_view value) {
    std::ostringstream stream;
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"': stream << "\\\""; break;
        case '\\': stream << "\\\\"; break;
        case '\b': stream << "\\b"; break;
        case '\f': stream << "\\f"; break;
        case '\n': stream << "\\n"; break;
        case '\r': stream << "\\r"; break;
        case '\t': stream << "\\t"; break;
        default:
            if (byte < 0x20) {
                stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                       << static_cast<unsigned>(byte) << std::dec;
            } else {
                stream << static_cast<char>(byte);
            }
        }
    }
    return stream.str();
}

}  // namespace

bool is_sha256_hex(const std::string& value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char byte) {
               return (byte >= '0' && byte <= '9') ||
                      (byte >= 'a' && byte <= 'f') ||
                      (byte >= 'A' && byte <= 'F');
           });
}

bool OnlineRecordStore::load_json_lines(const std::string& path,
                                        std::string& error) {
    records_.clear();
    ignored_count_ = 0;
    error.clear();
    if (path.empty()) return true;

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Could not open online records file: " + path;
        return false;
    }
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line_number == 1 && line.size() >= 3 &&
            static_cast<unsigned char>(line[0]) == 0xef &&
            static_cast<unsigned char>(line[1]) == 0xbb &&
            static_cast<unsigned char>(line[2]) == 0xbf) {
            line.erase(0, 3);
        }
        if (line.empty()) continue;
        if (line.size() > kMaximumLineBytes) {
            error = "Online records line " + std::to_string(line_number) +
                    " exceeds 64 KiB.";
            records_.clear();
            return false;
        }
        JsonObject object;
        std::string parse_error;
        if (!parse_flat_object(line, object, parse_error)) {
            error = "Online records line " + std::to_string(line_number) +
                    ": " + parse_error;
            records_.clear();
            return false;
        }
        OnlineRecord record;
        if (!record_from_object(object, record)) {
            error = "Online records line " + std::to_string(line_number) +
                    " is missing a required field or has a wrong field type.";
            records_.clear();
            return false;
        }
        std::transform(record.chart_sha256.begin(), record.chart_sha256.end(),
                       record.chart_sha256.begin(), [](unsigned char byte) {
                           return static_cast<char>(std::tolower(byte));
                       });
        if (!is_rankable(record)) {
            ++ignored_count_;
            continue;
        }
        if (records_.size() >= kMaximumRecords) {
            error = "Online records file exceeds 100000 accepted records.";
            records_.clear();
            return false;
        }
        records_.push_back(std::move(record));
    }
    if (!input.eof()) {
        error = "Could not read the complete online records file.";
        records_.clear();
        return false;
    }
    std::stable_sort(records_.begin(), records_.end(),
                     [](const OnlineRecord& left, const OnlineRecord& right) {
        if (left.chart_sha256 != right.chart_sha256) {
            return left.chart_sha256 < right.chart_sha256;
        }
        if (left.score != right.score) return left.score > right.score;
        if (left.accuracy != right.accuracy) return left.accuracy > right.accuracy;
        if (left.max_combo != right.max_combo) return left.max_combo > right.max_combo;
        return left.verified_at_utc < right.verified_at_utc;
    });
    return true;
}

std::vector<OnlineRecord> OnlineRecordStore::leaderboard(
    const std::string& chart_sha256,
    std::size_t limit) const {
    std::string normalized = chart_sha256;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char byte) {
                       return static_cast<char>(std::tolower(byte));
                   });
    std::vector<OnlineRecord> result;
    result.reserve(std::min(limit, records_.size()));
    for (const auto& record : records_) {
        if (record.chart_sha256 == normalized) {
            result.push_back(record);
            if (result.size() >= limit) break;
        }
    }
    return result;
}

std::size_t OnlineRecordStore::record_count() const { return records_.size(); }
std::size_t OnlineRecordStore::ignored_count() const { return ignored_count_; }

std::string online_records_json(const std::string& chart_sha256,
                                const std::vector<OnlineRecord>& records) {
    std::ostringstream output;
    output << "{\"schema_version\":1,\"chart_sha256\":\""
           << escape_json(chart_sha256) << "\",\"records\":[";
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto& record = records[index];
        if (index != 0) output << ',';
        output << "{\"rank\":" << (index + 1)
               << ",\"player_name\":\"" << escape_json(record.player_name)
               << "\",\"score\":" << record.score
               << ",\"accuracy\":" << std::fixed << std::setprecision(6)
               << record.accuracy
               << ",\"max_combo\":" << record.max_combo
               << ",\"clear_status\":\"" << escape_json(record.clear_status)
               << "\",\"ruleset_id\":\"" << escape_json(record.ruleset_id)
               << "\",\"verification_status\":\"online_verified\""
               << ",\"verified_at_utc\":\""
               << escape_json(record.verified_at_utc) << "\"}";
    }
    output << "]}";
    return output.str();
}

}  // namespace tenriff::server
