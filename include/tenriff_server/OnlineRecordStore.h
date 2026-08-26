#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tenriff::server {

struct OnlineRecord {
    std::string chart_sha256;
    std::string chart_format;
    std::string player_name;
    std::uint64_t score = 0;
    double accuracy = 0.0;
    std::uint32_t max_combo = 0;
    std::string clear_status;
    std::string ruleset_id;
    std::string verification_status;
    std::string verified_at_utc;
};

class OnlineRecordStore {
public:
    // An empty path creates a valid, empty read-only store.
    [[nodiscard]] bool load_json_lines(const std::string& path,
                                       std::string& error);

    [[nodiscard]] std::vector<OnlineRecord> leaderboard(
        const std::string& chart_sha256,
        std::size_t limit) const;
    [[nodiscard]] std::size_t record_count() const;
    [[nodiscard]] std::size_t ignored_count() const;

private:
    std::vector<OnlineRecord> records_;
    std::size_t ignored_count_ = 0;
};

[[nodiscard]] bool is_sha256_hex(const std::string& value);
[[nodiscard]] std::string online_records_json(
    const std::string& chart_sha256,
    const std::vector<OnlineRecord>& records);

}  // namespace tenriff::server
