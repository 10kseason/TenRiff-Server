#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace tenriff::server {

struct ServerOptions {
    std::string bind_address = "0.0.0.0";
    std::uint16_t port = 27300;
    std::string name = "TenRiff Headless Server";
};

class TcpServer {
public:
    explicit TcpServer(ServerOptions options);
    ~TcpServer();

    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    [[nodiscard]] bool run(std::atomic_bool& stop_requested,
                           std::string& error);
    [[nodiscard]] std::uint16_t bound_port() const;
    [[nodiscard]] std::size_t player_count() const;

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

}  // namespace tenriff::server
