#include "tenriff_server/BmsCatalog.h"

#include "tenriff_server/OnlineRecordStore.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <fstream>
#include <mutex>
#include <set>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

namespace tenriff::server {
namespace {

constexpr std::size_t kMaximumCatalogCharts = 250'000;

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
        return static_cast<char>(byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte);
    });
    return value;
}

std::string trim_ascii(std::string value) {
    const auto whitespace = [](unsigned char byte) { return std::isspace(byte) != 0; };
    value.erase(value.begin(), std::find_if_not(value.begin(), value.end(), whitespace));
    value.erase(std::find_if_not(value.rbegin(), value.rend(), whitespace).base(), value.end());
    return value;
}

bool is_bms_family(const std::filesystem::path& path) {
    const std::string extension = lower_ascii(path.extension().string());
    return extension == ".bms" || extension == ".bme" ||
           extension == ".bml" || extension == ".pms";
}

std::string hex_encode(const unsigned char* bytes, std::size_t size) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (std::size_t index = 0; index < size; ++index) {
        output[index * 2] = digits[bytes[index] >> 4U];
        output[index * 2 + 1] = digits[bytes[index] & 0x0fU];
    }
    return output;
}

bool sha256_file(const std::filesystem::path& path,
                 std::string& digest,
                 std::string& error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "Could not open BMS file for hashing: " + path.u8string();
        return false;
    }

    std::array<char, 64 * 1024> buffer{};
    std::array<unsigned char, 32> output{};
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD returned = 0;
    std::vector<unsigned char> object;
    bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                           nullptr, 0) == 0 &&
              BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                reinterpret_cast<PUCHAR>(&object_size),
                                sizeof(object_size), &returned, 0) == 0;
    if (ok) {
        object.resize(object_size);
        ok = BCryptCreateHash(algorithm, &hash, object.data(), object_size,
                              nullptr, 0, 0) == 0;
    }
    while (ok && input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()),
                                static_cast<ULONG>(count), 0) == 0;
        }
    }
    ok = ok && input.eof() &&
         BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0) == 0;
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
#else
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    bool ok = context != nullptr && EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    while (ok && input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            ok = EVP_DigestUpdate(context, buffer.data(), static_cast<std::size_t>(count)) == 1;
        }
    }
    unsigned output_size = 0;
    ok = ok && input.eof() &&
         EVP_DigestFinal_ex(context, output.data(), &output_size) == 1 &&
         output_size == output.size();
    EVP_MD_CTX_free(context);
#endif
    if (!ok) {
        error = "Could not calculate SHA-256 for BMS file: " + path.u8string();
        return false;
    }
    digest = hex_encode(output.data(), output.size());
    return true;
}

bool load_exclusions(const std::filesystem::path& path,
                     std::unordered_set<std::string>& exclusions,
                     std::string& error) {
    if (path.empty()) return true;
    std::ifstream input(path);
    if (!input) {
        error = "Could not open excluded chart list: " + path.u8string();
        return false;
    }
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        line = lower_ascii(trim_ascii(std::move(line)));
        if (line.empty()) continue;
        if (!is_sha256_hex(line)) {
            error = "Invalid SHA-256 in excluded chart list at line " +
                    std::to_string(line_number) + ".";
            return false;
        }
        exclusions.insert(std::move(line));
    }
    return true;
}

}  // namespace

bool load_bms_catalog(const std::filesystem::path& chart_root,
                      const std::filesystem::path& excluded_chart_file,
                      BmsCatalogLoadResult& result,
                      std::string& error) {
    result = {};
    error.clear();
    std::error_code filesystem_error;
    const auto root = std::filesystem::weakly_canonical(chart_root, filesystem_error);
    if (filesystem_error || !std::filesystem::is_directory(root, filesystem_error)) {
        error = "BMS chart root is not a readable directory: " + chart_root.u8string();
        return false;
    }

    std::unordered_set<std::string> exclusions;
    if (!load_exclusions(excluded_chart_file, exclusions, error)) return false;

    std::vector<std::filesystem::path> paths;
    std::filesystem::recursive_directory_iterator iterator(
        root, std::filesystem::directory_options::skip_permission_denied, filesystem_error);
    const std::filesystem::recursive_directory_iterator end;
    if (filesystem_error) {
        error = "Could not scan BMS chart root: " + root.u8string();
        return false;
    }
    while (iterator != end) {
        const auto entry = *iterator;
        if (is_bms_family(entry.path())) {
            const auto status = entry.symlink_status(filesystem_error);
            if (filesystem_error) {
                error = "Could not inspect catalog entry: " + entry.path().u8string();
                return false;
            }
            if (std::filesystem::is_symlink(status)) {
                ++result.skipped_symlink_count;
            } else if (std::filesystem::is_regular_file(status)) {
                paths.push_back(entry.path());
                if (paths.size() > kMaximumCatalogCharts) {
                    error = "BMS catalog exceeds the 250000 chart limit.";
                    return false;
                }
            }
        }
        iterator.increment(filesystem_error);
        if (filesystem_error) {
            error = "Could not continue scanning BMS chart root: " + root.u8string();
            return false;
        }
    }

    std::sort(paths.begin(), paths.end());
    std::vector<std::string> hashes(paths.size());
    std::atomic_size_t next_path{0};
    std::atomic_bool hash_failed{false};
    std::mutex error_mutex;
    const std::size_t worker_count = std::min<std::size_t>(4, paths.size());
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::size_t worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&] {
            while (!hash_failed.load(std::memory_order_relaxed)) {
                const std::size_t index = next_path.fetch_add(1, std::memory_order_relaxed);
                if (index >= paths.size()) return;
                std::string hash_error;
                if (!sha256_file(paths[index], hashes[index], hash_error)) {
                    if (!hash_failed.exchange(true, std::memory_order_relaxed)) {
                        std::lock_guard lock(error_mutex);
                        error = std::move(hash_error);
                    }
                    return;
                }
            }
        });
    }
    for (auto& worker : workers) worker.join();
    if (hash_failed.load(std::memory_order_relaxed)) return false;

    std::unordered_set<std::string> included_hashes;
    for (std::size_t index = 0; index < paths.size(); ++index) {
        auto& hash = hashes[index];
        if (exclusions.find(hash) != exclusions.end()) {
            ++result.excluded_count;
            continue;
        }
        if (!included_hashes.insert(hash).second) {
            ++result.duplicate_count;
            continue;
        }
        result.charts.push_back({std::move(hash), paths[index].u8string()});
    }
    return true;
}

}  // namespace tenriff::server
