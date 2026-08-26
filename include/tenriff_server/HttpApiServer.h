#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "tenriff_server/OnlineRecordStore.h"
#include "tenriff_server/RankedDatabase.h"

namespace tenriff::server {

struct HttpApiOptions {
    std::string bind_address = "0.0.0.0";
    std::uint16_t port = 27302;
    std::string server_name = "TenRiff Headless Server";
    std::string verifier_executable;
    std::string replay_staging_directory = "data/replay-staging";
};

class HttpApiServer {
public:
    HttpApiServer(HttpApiOptions options,
                  const OnlineRecordStore& records,
                  RankedDatabase* ranked_database = nullptr);
    ~HttpApiServer();

    HttpApiServer(const HttpApiServer&) = delete;
    HttpApiServer& operator=(const HttpApiServer&) = delete;

    [[nodiscard]] bool run(std::atomic_bool& stop_requested,
                           std::string& error);
    [[nodiscard]] std::uint16_t bound_port() const;

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

}  // namespace tenriff::server
