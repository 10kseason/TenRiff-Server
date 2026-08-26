#include "tenriff_server/ReplayVerifierProcess.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace tenriff::server {
namespace {

constexpr std::size_t kMaximumVerifierOutput = 64 * 1024;

#ifdef _WIN32
std::wstring widen(const std::string& value) {
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           value.data(), static_cast<int>(value.size()),
                                           nullptr, 0);
    if (count <= 0) return {};
    std::wstring output(static_cast<std::size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), output.data(), count);
    return output;
}

std::wstring quote_windows(const std::wstring& value) {
    std::wstring output = L"\"";
    std::size_t slashes = 0;
    for (const wchar_t byte : value) {
        if (byte == L'\\') {
            ++slashes;
        } else if (byte == L'\"') {
            output.append(slashes * 2 + 1, L'\\');
            output.push_back(L'\"');
            slashes = 0;
        } else {
            output.append(slashes, L'\\');
            slashes = 0;
            output.push_back(byte);
        }
    }
    output.append(slashes * 2, L'\\');
    output.push_back(L'\"');
    return output;
}
#endif

}  // namespace

VerifierProcessResult run_replay_verifier(const std::string& executable,
                                          const std::string& replay_path,
                                          const std::string& chart_path,
                                          const std::string& challenge_id,
                                          const std::string& challenge_nonce,
                                          std::chrono::milliseconds timeout) {
    VerifierProcessResult result;
    if (executable.empty() || replay_path.empty() || chart_path.empty()) {
        result.error = "Verifier executable, replay, and chart paths are required.";
        return result;
    }
#ifdef _WIN32
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0)) {
        result.error = "Could not create verifier output pipe.";
        return result;
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
    const std::wstring executable_w = widen(executable);
    std::wstring command = quote_windows(executable_w) + L" --replay " +
        quote_windows(widen(replay_path)) + L" --chart " + quote_windows(widen(chart_path)) +
        L" --challenge-id " + quote_windows(widen(challenge_id)) +
        L" --challenge-nonce " + quote_windows(widen(challenge_nonce));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        executable_w.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(write_pipe);
    if (!created) {
        CloseHandle(read_pipe);
        result.error = "Could not launch replay verifier.";
        return result;
    }
    result.launched = true;
    const DWORD waited = WaitForSingleObject(process.hProcess,
                                              static_cast<DWORD>(timeout.count()));
    if (waited == WAIT_TIMEOUT) {
        result.timed_out = true;
        TerminateProcess(process.hProcess, 124);
        WaitForSingleObject(process.hProcess, 5000);
    }
    std::array<char, 4096> buffer{};
    DWORD received = 0;
    while (result.output.size() < kMaximumVerifierOutput &&
           ReadFile(read_pipe, buffer.data(), static_cast<DWORD>(buffer.size()),
                    &received, nullptr) && received > 0) {
        result.output.append(buffer.data(), std::min<std::size_t>(
            received, kMaximumVerifierOutput - result.output.size()));
    }
    DWORD exit_code = 1;
    GetExitCodeProcess(process.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);
    CloseHandle(read_pipe);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
#else
    int output_pipe[2]{};
    if (pipe(output_pipe) != 0) {
        result.error = "Could not create verifier output pipe.";
        return result;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        result.error = "Could not fork replay verifier.";
        return result;
    }
    if (child == 0) {
        dup2(output_pipe[1], STDOUT_FILENO);
        dup2(output_pipe[1], STDERR_FILENO);
        close(output_pipe[0]);
        close(output_pipe[1]);
        execl(executable.c_str(), executable.c_str(), "--replay", replay_path.c_str(),
              "--chart", chart_path.c_str(), "--challenge-id", challenge_id.c_str(),
              "--challenge-nonce", challenge_nonce.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    result.launched = true;
    close(output_pipe[1]);
    fcntl(output_pipe[0], F_SETFL, fcntl(output_pipe[0], F_GETFL) | O_NONBLOCK);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int status = 0;
    bool finished = false;
    std::array<char, 4096> buffer{};
    while (!finished && std::chrono::steady_clock::now() < deadline) {
        const ssize_t received = read(output_pipe[0], buffer.data(), buffer.size());
        if (received > 0 && result.output.size() < kMaximumVerifierOutput) {
            result.output.append(buffer.data(), std::min<std::size_t>(
                static_cast<std::size_t>(received),
                kMaximumVerifierOutput - result.output.size()));
        }
        const pid_t waited = waitpid(child, &status, WNOHANG);
        finished = waited == child;
        if (!finished) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!finished) {
        result.timed_out = true;
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    }
    for (;;) {
        const ssize_t received = read(output_pipe[0], buffer.data(), buffer.size());
        if (received <= 0) break;
        if (result.output.size() < kMaximumVerifierOutput) {
            result.output.append(buffer.data(), std::min<std::size_t>(
                static_cast<std::size_t>(received),
                kMaximumVerifierOutput - result.output.size()));
        }
    }
    close(output_pipe[0]);
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
#endif
    if (result.timed_out) result.error = "Replay verifier timed out.";
    return result;
}

}  // namespace tenriff::server
