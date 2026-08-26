#include "tenriff_server/TcpServer.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <thread>

#include "network/PeerSession.h"

namespace {

using namespace std::chrono_literals;

bool wait_until(const std::function<bool()>& predicate,
                std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return predicate();
}

}  // namespace

int main() {
    tenriff::server::ServerOptions options;
    options.bind_address = "127.0.0.1";
    options.port = 0;
    options.name = "TenRiff v5 compatibility";
    tenriff::server::TcpServer server(options);
    std::atomic_bool stop{false};
    std::string server_error;
    bool server_ok = false;
    std::thread server_thread([&] { server_ok = server.run(stop, server_error); });

    auto finish = [&](int code) {
        stop.store(true, std::memory_order_release);
        server_thread.join();
        if (!server_ok || !server_error.empty()) {
            std::cerr << "Server error: " << server_error << '\n';
            return 1;
        }
        return code;
    };

    if (!wait_until([&] { return server.bound_port() != 0; })) {
        std::cerr << "Server did not begin listening.\n";
        return finish(1);
    }

    const std::string shared_hash(64, 'e');
    tenriff::network::PeerSession alice;
    tenriff::network::PeerSession bob;
    alice.set_local_library({shared_hash});
    bob.set_local_library({shared_hash});
    if (!alice.join("127.0.0.1", server.bound_port(), "Alice") ||
        !bob.join("127.0.0.1", server.bound_port(), "Bob")) {
        std::cerr << "TenRiff PeerSession could not start join workers.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    const bool room_ready = wait_until([&] {
        const auto a = alice.snapshot();
        const auto b = bob.snapshot();
        return a.state == tenriff::network::PeerSessionState::Connected &&
               b.state == tenriff::network::PeerSessionState::Connected &&
               a.participant_count == 2 && b.participant_count == 2 &&
               a.remote_library_ready && b.remote_library_ready &&
               a.remote_library_count == 1 && b.remote_library_count == 1;
    });
    if (!room_ready) {
        std::cerr << "TenRiff clients did not complete the v5 room/library handshake.\n"
                  << "Alice: " << alice.snapshot().status_detail << '\n'
                  << "Bob: " << bob.snapshot().status_detail << '\n';
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    tenriff::network::PeerSession* leader =
        alice.snapshot().local_is_leader ? &alice : &bob;
    tenriff::network::PeerSession* follower = leader == &alice ? &bob : &alice;
    const tenriff::network::ChartFingerprint fingerprint{0x12345678u, 4096};
    if (!leader->set_local_chart(fingerprint, "Compatibility chart") ||
        !wait_until([&] {
            return follower->snapshot().selected_chart.fingerprint.hash ==
                   fingerprint.hash;
        }) ||
        !follower->set_local_chart(fingerprint, "Compatibility chart") ||
        !leader->set_ready(true) || !follower->set_ready(true) ||
        !wait_until([&] { return leader->snapshot().can_start; }) ||
        !leader->send_launch()) {
        std::cerr << "TenRiff clients could not reach the launch barrier.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    std::uint64_t launched_hash = 0;
    if (!wait_until([&] {
            const auto leader_launch = leader->poll_launch();
            const auto follower_launch = follower->poll_launch();
            if (leader_launch) launched_hash = *leader_launch;
            if (follower_launch) launched_hash = *follower_launch;
            return leader->snapshot().round_active &&
                   follower->snapshot().round_active &&
                   launched_hash == fingerprint.hash;
        })) {
        std::cerr << "TenRiff clients did not receive the canonical Launch.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    if (!leader->mark_loaded() || !follower->mark_loaded() ||
        !wait_until([&] {
            return leader->snapshot().remote_loaded &&
                   follower->snapshot().remote_loaded;
        }) ||
        !leader->send_begin(250)) {
        std::cerr << "TenRiff clients could not reach the Begin barrier.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }
    std::uint32_t delay = 0;
    if (!follower->wait_for_begin(3s, delay) || delay != 250) {
        std::cerr << "Follower did not receive the Begin delay.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    tenriff::network::PeerScore score;
    score.score = 9000;
    score.max_combo = 10;
    score.combo = 10;
    score.perfect = 10;
    score.gauge_milli = 80000;
    score.finished = true;
    if (!leader->publish_score(score, true) ||
        !follower->publish_score(score, true) ||
        !wait_until([&] {
            return leader->snapshot().all_remote_finished &&
                   follower->snapshot().all_remote_finished;
        })) {
        std::cerr << "Final score claims were not relayed.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    leader->reset_round();
    follower->reset_round();
    if (!wait_until([&] {
            return !leader->snapshot().round_active &&
                   !follower->snapshot().round_active;
        })) {
        std::cerr << "Round reset did not complete.\n";
        alice.disconnect();
        bob.disconnect();
        return finish(1);
    }

    alice.disconnect("Compatibility test complete");
    bob.disconnect("Compatibility test complete");
    std::cout << "TenRiff PeerSession protocol v5 compatibility passed.\n";
    return finish(0);
}
