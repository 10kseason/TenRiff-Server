#pragma once

#include <chrono>
#include <string>

namespace tenriff::server {

struct VerifierProcessResult {
    bool launched = false;
    bool timed_out = false;
    int exit_code = -1;
    std::string output;
    std::string error;
};

[[nodiscard]] VerifierProcessResult run_replay_verifier(
    const std::string& executable,
    const std::string& replay_path,
    const std::string& chart_path,
    const std::string& challenge_id,
    const std::string& challenge_nonce,
    std::chrono::milliseconds timeout = std::chrono::seconds(30));

}  // namespace tenriff::server
