#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "tenriff_server/OnlineRecordStore.h"

struct sqlite3;

namespace tenriff::server {

struct AccountSession {
    std::string username;
    std::string bearer_token;
    std::string expires_at_utc;
};

struct ReplayChallenge {
    std::string id;
    std::string nonce;
    std::string chart_sha256;
    std::string chart_path;
    std::string expires_at_utc;
};

struct VerifiedReplayRecord {
    std::string chart_sha256;
    std::string replay_sha256;
    std::uint64_t score = 0;
    double accuracy = 0.0;
    std::uint32_t max_combo = 0;
    std::string clear_status;
    std::string ruleset_id;
};

class RankedDatabase {
public:
    RankedDatabase();
    ~RankedDatabase();
    RankedDatabase(const RankedDatabase&) = delete;
    RankedDatabase& operator=(const RankedDatabase&) = delete;

    [[nodiscard]] bool open(const std::string& path,
                            const std::string& receipt_signing_secret,
                            std::string& error);
    [[nodiscard]] bool register_account(const std::string& username,
                                        const std::string& password,
                                        AccountSession& session,
                                        std::string& error);
    [[nodiscard]] bool login(const std::string& username,
                             const std::string& password,
                             AccountSession& session,
                             std::string& error);
    [[nodiscard]] bool approve_bms_chart(const std::string& chart_sha256,
                                         const std::string& chart_path,
                                         std::string& error);
    [[nodiscard]] bool create_challenge(const std::string& bearer_token,
                                        const std::string& chart_sha256,
                                        ReplayChallenge& challenge,
                                        std::string& error);
    [[nodiscard]] bool inspect_challenge(const std::string& bearer_token,
                                         const std::string& challenge_id,
                                         ReplayChallenge& challenge,
                                         std::string& error);
    [[nodiscard]] bool commit_verified_replay(const std::string& bearer_token,
                                              const std::string& challenge_id,
                                              const VerifiedReplayRecord& record,
                                              std::string& receipt,
                                              std::string& error);
    [[nodiscard]] std::vector<OnlineRecord> leaderboard(
        const std::string& chart_sha256,
        std::size_t limit) const;
    [[nodiscard]] bool ready() const;

private:
    sqlite3* database_ = nullptr;
    std::string signing_secret_;
    mutable std::mutex mutex_;
};

}  // namespace tenriff::server
