#include "tenriff_server/RankedDatabase.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <winsqlite/winsqlite3.h>
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#endif

namespace tenriff::server {
namespace {

constexpr int kPasswordIterations = 210'000;
constexpr std::int64_t kSessionLifetimeSeconds = 24 * 60 * 60;
constexpr std::int64_t kChallengeLifetimeSeconds = 10 * 60;

class Statement {
public:
    Statement(sqlite3* db, const char* sql) {
        if (db) sqlite3_prepare_v2(db, sql, -1, &value_, nullptr);
    }
    ~Statement() { if (value_) sqlite3_finalize(value_); }
    sqlite3_stmt* get() const { return value_; }
private:
    sqlite3_stmt* value_ = nullptr;
};

std::string sqlite_error(sqlite3* db, std::string_view prefix) {
    return std::string(prefix) + ": " + (db ? sqlite3_errmsg(db) : "database is not open");
}

bool execute(sqlite3* db, const char* sql, std::string& error) {
    char* message = nullptr;
    const int result = sqlite3_exec(db, sql, nullptr, nullptr, &message);
    if (result == SQLITE_OK) return true;
    error = message ? message : sqlite_error(db, "SQLite command failed");
    sqlite3_free(message);
    return false;
}

std::int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string utc_text(std::int64_t seconds) {
    const std::time_t value = static_cast<std::time_t>(seconds);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &value);
#else
    gmtime_r(&value, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
        return static_cast<char>(byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte);
    });
    return value;
}

bool valid_username(const std::string& value) {
    return value.size() >= 3 && value.size() <= 32 &&
           std::all_of(value.begin(), value.end(), [](unsigned char byte) {
               return (byte >= 'a' && byte <= 'z') ||
                      (byte >= 'A' && byte <= 'Z') ||
                      (byte >= '0' && byte <= '9') ||
                      byte == '_' || byte == '-' || byte == '.';
           });
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

bool random_bytes(unsigned char* output, std::size_t size) {
#ifdef _WIN32
    return BCryptGenRandom(nullptr, output, static_cast<ULONG>(size),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    return RAND_bytes(output, static_cast<int>(size)) == 1;
#endif
}

bool sha256(std::string_view input, std::array<unsigned char, 32>& output) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                           nullptr, 0) == 0 &&
              BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0 &&
              BCryptHashData(hash,
                  reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                  static_cast<ULONG>(input.size()), 0) == 0 &&
              BCryptFinishHash(hash, output.data(),
                               static_cast<ULONG>(output.size()), 0) == 0;
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
#else
    unsigned length = 0;
    return EVP_Digest(input.data(), input.size(), output.data(), &length,
                      EVP_sha256(), nullptr) == 1 && length == output.size();
#endif
}

bool hmac_sha256(std::string_view key,
                 std::string_view input,
                 std::array<unsigned char, 32>& output) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                           nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0 &&
              BCryptCreateHash(algorithm, &hash, nullptr, 0,
                  reinterpret_cast<PUCHAR>(const_cast<char*>(key.data())),
                  static_cast<ULONG>(key.size()), 0) == 0 &&
              BCryptHashData(hash,
                  reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                  static_cast<ULONG>(input.size()), 0) == 0 &&
              BCryptFinishHash(hash, output.data(),
                               static_cast<ULONG>(output.size()), 0) == 0;
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
#else
    unsigned length = 0;
    return HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                reinterpret_cast<const unsigned char*>(input.data()), input.size(),
                output.data(), &length) != nullptr && length == output.size();
#endif
}

bool derive_password(std::string_view password,
                     const unsigned char* salt,
                     std::size_t salt_size,
                     std::array<unsigned char, 32>& output) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    const bool ok = BCryptOpenAlgorithmProvider(
                        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                        BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0 &&
                    BCryptDeriveKeyPBKDF2(
                        algorithm,
                        reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                        static_cast<ULONG>(password.size()),
                        const_cast<PUCHAR>(salt), static_cast<ULONG>(salt_size),
                        kPasswordIterations, output.data(),
                        static_cast<ULONG>(output.size()), 0) == 0;
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
#else
    return PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                            salt, static_cast<int>(salt_size), kPasswordIterations,
                            EVP_sha256(), static_cast<int>(output.size()),
                            output.data()) == 1;
#endif
}

bool constant_equal(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        difference |= static_cast<unsigned char>(lhs[index] ^ rhs[index]);
    }
    return difference == 0;
}

std::string secure_token(std::size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    return random_bytes(buffer.data(), buffer.size())
               ? hex_encode(buffer.data(), buffer.size())
               : std::string{};
}

std::string token_digest(std::string_view token) {
    std::array<unsigned char, 32> digest{};
    return sha256(token, digest) ? hex_encode(digest.data(), digest.size()) : std::string{};
}

bool bind_text(sqlite3_stmt* statement, int index, const std::string& value) {
    return sqlite3_bind_text(statement, index, value.c_str(),
                             static_cast<int>(value.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool create_session(sqlite3* db, std::int64_t user_id,
                    const std::string& username, AccountSession& output,
                    std::string& error) {
    output.bearer_token = secure_token(32);
    const std::string digest = token_digest(output.bearer_token);
    if (output.bearer_token.empty() || digest.empty()) {
        error = "The OS random generator failed.";
        return false;
    }
    const std::int64_t expires = unix_now() + kSessionLifetimeSeconds;
    Statement statement(db,
        "INSERT INTO sessions(token_hash,user_id,expires_unix,created_unix) VALUES(?,?,?,?)");
    if (!statement.get() || !bind_text(statement.get(), 1, digest) ||
        sqlite3_bind_int64(statement.get(), 2, user_id) != SQLITE_OK ||
        sqlite3_bind_int64(statement.get(), 3, expires) != SQLITE_OK ||
        sqlite3_bind_int64(statement.get(), 4, unix_now()) != SQLITE_OK ||
        sqlite3_step(statement.get()) != SQLITE_DONE) {
        error = sqlite_error(db, "Could not create account session");
        return false;
    }
    output.username = username;
    output.expires_at_utc = utc_text(expires);
    return true;
}

std::int64_t authenticated_user(sqlite3* db, const std::string& token,
                                std::string& username) {
    const std::string digest = token_digest(token);
    if (digest.empty()) return 0;
    Statement statement(db,
        "SELECT users.id,users.username FROM sessions JOIN users ON users.id=sessions.user_id "
        "WHERE sessions.token_hash=? AND sessions.expires_unix>=?");
    if (!statement.get() || !bind_text(statement.get(), 1, digest) ||
        sqlite3_bind_int64(statement.get(), 2, unix_now()) != SQLITE_OK ||
        sqlite3_step(statement.get()) != SQLITE_ROW) return 0;
    const auto* text = sqlite3_column_text(statement.get(), 1);
    username = text ? reinterpret_cast<const char*>(text) : "";
    return sqlite3_column_int64(statement.get(), 0);
}

void audit(sqlite3* db, std::string_view event, std::string_view actor,
           std::string_view detail) {
    Statement statement(db,
        "INSERT INTO audit_log(event_type,actor,detail,created_unix) VALUES(?,?,?,?)");
    if (!statement.get()) return;
    sqlite3_bind_text(statement.get(), 1, event.data(), static_cast<int>(event.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 2, actor.data(), static_cast<int>(actor.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(statement.get(), 3, detail.data(), static_cast<int>(detail.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement.get(), 4, unix_now());
    sqlite3_step(statement.get());
}

}  // namespace

RankedDatabase::RankedDatabase() = default;
RankedDatabase::~RankedDatabase() { if (database_) sqlite3_close(database_); }

bool RankedDatabase::open(const std::string& path,
                          const std::string& receipt_signing_secret,
                          std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (receipt_signing_secret.size() < 32) {
        error = "Receipt signing secret must contain at least 32 bytes.";
        return false;
    }
    if (sqlite3_open_v2(path.c_str(), &database_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        error = sqlite_error(database_, "Could not open ranked database");
        return false;
    }
    sqlite3_busy_timeout(database_, 5000);
    const char* schema =
        "PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_unix INTEGER NOT NULL);"
        "INSERT OR IGNORE INTO schema_migrations(version,applied_unix) VALUES(1,strftime('%s','now'));"
        "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
        "password_salt TEXT NOT NULL,password_hash TEXT NOT NULL,created_unix INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),"
        "expires_unix INTEGER NOT NULL,created_unix INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS approved_charts(chart_sha256 TEXT PRIMARY KEY,chart_format TEXT NOT NULL CHECK(chart_format='bms'),"
        "chart_path TEXT NOT NULL,approved_unix INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),"
        "chart_sha256 TEXT NOT NULL REFERENCES approved_charts(chart_sha256),nonce TEXT NOT NULL,expires_unix INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),"
        "chart_sha256 TEXT NOT NULL,replay_sha256 TEXT NOT NULL UNIQUE,score INTEGER NOT NULL,accuracy REAL NOT NULL,max_combo INTEGER NOT NULL,"
        "clear_status TEXT NOT NULL,ruleset_id TEXT NOT NULL,receipt TEXT NOT NULL,verified_unix INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS records_chart_score ON records(chart_sha256,score DESC,accuracy DESC,verified_unix ASC);"
        "CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,event_type TEXT NOT NULL,actor TEXT NOT NULL,detail TEXT NOT NULL,created_unix INTEGER NOT NULL);";
    if (!execute(database_, schema, error)) return false;
    signing_secret_ = receipt_signing_secret;
    return true;
}

bool RankedDatabase::register_account(const std::string& username,
                                      const std::string& password,
                                      AccountSession& session,
                                      std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!database_) { error = "Ranked database is not open."; return false; }
    if (!valid_username(username)) {
        error = "Username must be 3..32 ASCII letters, digits, '.', '_' or '-'.";
        return false;
    }
    if (password.size() < 10 || password.size() > 128) {
        error = "Password must contain 10..128 UTF-8 bytes.";
        return false;
    }
    std::array<unsigned char, 16> salt{};
    std::array<unsigned char, 32> password_hash{};
    if (!random_bytes(salt.data(), salt.size()) ||
        !derive_password(password, salt.data(), salt.size(), password_hash)) {
        error = "Password hashing failed.";
        return false;
    }
    Statement statement(database_,
        "INSERT INTO users(username,password_salt,password_hash,created_unix) VALUES(?,?,?,?)");
    if (!statement.get() || !bind_text(statement.get(), 1, username) ||
        !bind_text(statement.get(), 2, hex_encode(salt.data(), salt.size())) ||
        !bind_text(statement.get(), 3, hex_encode(password_hash.data(), password_hash.size())) ||
        sqlite3_bind_int64(statement.get(), 4, unix_now()) != SQLITE_OK ||
        sqlite3_step(statement.get()) != SQLITE_DONE) {
        error = sqlite3_extended_errcode(database_) == SQLITE_CONSTRAINT_UNIQUE
                    ? "Username is already registered."
                    : sqlite_error(database_, "Could not register account");
        return false;
    }
    const std::int64_t id = sqlite3_last_insert_rowid(database_);
    if (!create_session(database_, id, username, session, error)) return false;
    audit(database_, "account.register", username, "ok");
    return true;
}

bool RankedDatabase::login(const std::string& username,
                           const std::string& password,
                           AccountSession& session,
                           std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    Statement statement(database_,
        "SELECT id,username,password_salt,password_hash FROM users WHERE username=? COLLATE NOCASE");
    if (!statement.get() || !bind_text(statement.get(), 1, username) ||
        sqlite3_step(statement.get()) != SQLITE_ROW) {
        error = "Invalid username or password.";
        return false;
    }
    const std::int64_t id = sqlite3_column_int64(statement.get(), 0);
    const std::string canonical = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 1));
    const std::string salt_hex = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 2));
    const std::string stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 3));
    if (salt_hex.size() != 32) { error = "Account password record is invalid."; return false; }
    std::array<unsigned char, 16> salt{};
    for (std::size_t i = 0; i < salt.size(); ++i) {
        unsigned value = 0;
        std::istringstream input(salt_hex.substr(i * 2, 2));
        input >> std::hex >> value;
        salt[i] = static_cast<unsigned char>(value);
    }
    std::array<unsigned char, 32> calculated{};
    if (!derive_password(password, salt.data(), salt.size(), calculated) ||
        !constant_equal(stored_hash, hex_encode(calculated.data(), calculated.size()))) {
        error = "Invalid username or password.";
        audit(database_, "account.login_failed", username, "bad_credentials");
        return false;
    }
    if (!create_session(database_, id, canonical, session, error)) return false;
    audit(database_, "account.login", canonical, "ok");
    return true;
}

bool RankedDatabase::approve_bms_chart(const std::string& chart_sha256,
                                       const std::string& chart_path,
                                       std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string hash = lower_ascii(chart_sha256);
    std::string extension = lower_ascii(std::filesystem::path(chart_path).extension().string());
    const bool bms_family = extension == ".bms" || extension == ".bme" ||
                            extension == ".bml" || extension == ".pms";
    if (!is_sha256_hex(hash) || chart_path.empty() || !bms_family) {
        error = "Approved chart requires a SHA-256 hash and local BMS path.";
        return false;
    }
    Statement statement(database_,
        "INSERT INTO approved_charts(chart_sha256,chart_format,chart_path,approved_unix) VALUES(?,'bms',?,?) "
        "ON CONFLICT(chart_sha256) DO UPDATE SET chart_path=excluded.chart_path,approved_unix=excluded.approved_unix");
    if (!statement.get() || !bind_text(statement.get(), 1, hash) ||
        !bind_text(statement.get(), 2, chart_path) ||
        sqlite3_bind_int64(statement.get(), 3, unix_now()) != SQLITE_OK ||
        sqlite3_step(statement.get()) != SQLITE_DONE) {
        error = sqlite_error(database_, "Could not approve BMS chart");
        return false;
    }
    audit(database_, "chart.approve", "operator", hash);
    return true;
}

bool RankedDatabase::create_challenge(const std::string& bearer_token,
                                      const std::string& chart_sha256,
                                      ReplayChallenge& challenge,
                                      std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string username;
    const std::int64_t user_id = authenticated_user(database_, bearer_token, username);
    if (!user_id) { error = "Authentication required."; return false; }
    const std::string hash = lower_ascii(chart_sha256);
    Statement chart(database_, "SELECT chart_path FROM approved_charts WHERE chart_sha256=? AND chart_format='bms'");
    if (!chart.get() || !bind_text(chart.get(), 1, hash) || sqlite3_step(chart.get()) != SQLITE_ROW) {
        error = "Chart is not in the approved BMS catalog.";
        return false;
    }
    challenge.chart_sha256 = hash;
    challenge.chart_path = reinterpret_cast<const char*>(sqlite3_column_text(chart.get(), 0));
    challenge.id = secure_token(16);
    challenge.nonce = secure_token(32);
    const std::int64_t expires = unix_now() + kChallengeLifetimeSeconds;
    if (challenge.id.empty() || challenge.nonce.empty()) { error = "The OS random generator failed."; return false; }
    Statement insert(database_,
        "INSERT INTO challenges(id,user_id,chart_sha256,nonce,expires_unix,used) VALUES(?,?,?,?,?,0)");
    if (!insert.get() || !bind_text(insert.get(), 1, challenge.id) ||
        sqlite3_bind_int64(insert.get(), 2, user_id) != SQLITE_OK ||
        !bind_text(insert.get(), 3, hash) || !bind_text(insert.get(), 4, challenge.nonce) ||
        sqlite3_bind_int64(insert.get(), 5, expires) != SQLITE_OK ||
        sqlite3_step(insert.get()) != SQLITE_DONE) {
        error = sqlite_error(database_, "Could not create replay challenge");
        return false;
    }
    challenge.expires_at_utc = utc_text(expires);
    audit(database_, "challenge.create", username, challenge.id + ":" + hash);
    return true;
}

bool RankedDatabase::inspect_challenge(const std::string& bearer_token,
                                       const std::string& challenge_id,
                                       ReplayChallenge& challenge,
                                       std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string username;
    const std::int64_t user_id = authenticated_user(database_, bearer_token, username);
    if (!user_id) { error = "Authentication required."; return false; }
    Statement statement(database_,
        "SELECT challenges.nonce,challenges.chart_sha256,approved_charts.chart_path,challenges.expires_unix "
        "FROM challenges JOIN approved_charts ON approved_charts.chart_sha256=challenges.chart_sha256 "
        "WHERE challenges.id=? AND challenges.user_id=? AND challenges.used=0 AND challenges.expires_unix>=?");
    if (!statement.get() || !bind_text(statement.get(), 1, challenge_id) ||
        sqlite3_bind_int64(statement.get(), 2, user_id) != SQLITE_OK ||
        sqlite3_bind_int64(statement.get(), 3, unix_now()) != SQLITE_OK ||
        sqlite3_step(statement.get()) != SQLITE_ROW) {
        error = "Replay challenge is invalid, expired, used, or owned by another account.";
        return false;
    }
    challenge.id = challenge_id;
    challenge.nonce = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
    challenge.chart_sha256 = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 1));
    challenge.chart_path = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 2));
    challenge.expires_at_utc = utc_text(sqlite3_column_int64(statement.get(), 3));
    return true;
}

bool RankedDatabase::commit_verified_replay(const std::string& bearer_token,
                                            const std::string& challenge_id,
                                            const VerifiedReplayRecord& record,
                                            std::string& receipt,
                                            std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string username;
    const std::int64_t user_id = authenticated_user(database_, bearer_token, username);
    if (!user_id) { error = "Authentication required."; return false; }
    Statement challenge(database_,
        "SELECT chart_sha256 FROM challenges WHERE id=? AND user_id=? AND used=0 AND expires_unix>=?");
    if (!challenge.get() || !bind_text(challenge.get(), 1, challenge_id) ||
        sqlite3_bind_int64(challenge.get(), 2, user_id) != SQLITE_OK ||
        sqlite3_bind_int64(challenge.get(), 3, unix_now()) != SQLITE_OK ||
        sqlite3_step(challenge.get()) != SQLITE_ROW) {
        error = "Replay challenge is invalid, expired, used, or owned by another account.";
        return false;
    }
    const std::string expected_hash = reinterpret_cast<const char*>(sqlite3_column_text(challenge.get(), 0));
    if (lower_ascii(record.chart_sha256) != expected_hash || !is_sha256_hex(record.replay_sha256) ||
        record.ruleset_id.empty() || record.accuracy < 0.0 || record.accuracy > 100.0 ||
        record.score > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
        error = "Verifier result does not match the replay challenge.";
        return false;
    }
    const std::int64_t verified = unix_now();
    const std::string receipt_payload = username + "|" + expected_hash + "|" +
        lower_ascii(record.replay_sha256) + "|" + std::to_string(record.score) + "|" +
        std::to_string(verified);
    std::array<unsigned char, 32> signature{};
    if (!hmac_sha256(signing_secret_, receipt_payload, signature)) {
        error = "Could not sign verification receipt.";
        return false;
    }
    receipt = "v1." + std::to_string(verified) + "." + hex_encode(signature.data(), signature.size());
    if (!execute(database_, "BEGIN IMMEDIATE", error)) return false;
    Statement insert(database_,
        "INSERT INTO records(user_id,chart_sha256,replay_sha256,score,accuracy,max_combo,clear_status,ruleset_id,receipt,verified_unix) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)");
    bool ok = insert.get() && sqlite3_bind_int64(insert.get(), 1, user_id) == SQLITE_OK &&
        bind_text(insert.get(), 2, expected_hash) && bind_text(insert.get(), 3, lower_ascii(record.replay_sha256)) &&
        sqlite3_bind_int64(insert.get(), 4, static_cast<sqlite3_int64>(record.score)) == SQLITE_OK &&
        sqlite3_bind_double(insert.get(), 5, record.accuracy) == SQLITE_OK &&
        sqlite3_bind_int64(insert.get(), 6, record.max_combo) == SQLITE_OK &&
        bind_text(insert.get(), 7, record.clear_status) && bind_text(insert.get(), 8, record.ruleset_id) &&
        bind_text(insert.get(), 9, receipt) && sqlite3_bind_int64(insert.get(), 10, verified) == SQLITE_OK &&
        sqlite3_step(insert.get()) == SQLITE_DONE;
    Statement consume(database_, "UPDATE challenges SET used=1 WHERE id=? AND used=0");
    ok = ok && consume.get() && bind_text(consume.get(), 1, challenge_id) &&
         sqlite3_step(consume.get()) == SQLITE_DONE && sqlite3_changes(database_) == 1;
    if (!ok) {
        execute(database_, "ROLLBACK", error);
        if (error.empty()) error = sqlite_error(database_, "Could not commit verified replay");
        return false;
    }
    if (!execute(database_, "COMMIT", error)) return false;
    audit(database_, "replay.verified", username, receipt_payload);
    return true;
}

std::vector<OnlineRecord> RankedDatabase::leaderboard(const std::string& chart_sha256,
                                                       std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<OnlineRecord> output;
    Statement statement(database_,
        "SELECT users.username,records.score,records.accuracy,records.max_combo,records.clear_status,records.ruleset_id,records.verified_unix "
        "FROM records JOIN users ON users.id=records.user_id WHERE records.chart_sha256=? "
        "ORDER BY records.score DESC,records.accuracy DESC,records.verified_unix ASC LIMIT ?");
    if (!statement.get() || !bind_text(statement.get(), 1, lower_ascii(chart_sha256)) ||
        sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(std::min<std::size_t>(limit, 100))) != SQLITE_OK) {
        return output;
    }
    while (sqlite3_step(statement.get()) == SQLITE_ROW) {
        OnlineRecord record;
        record.chart_sha256 = lower_ascii(chart_sha256);
        record.chart_format = "bms";
        record.player_name = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 0));
        record.score = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
        record.accuracy = sqlite3_column_double(statement.get(), 2);
        record.max_combo = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 3));
        record.clear_status = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 4));
        record.ruleset_id = reinterpret_cast<const char*>(sqlite3_column_text(statement.get(), 5));
        record.verification_status = "online_verified";
        record.verified_at_utc = utc_text(sqlite3_column_int64(statement.get(), 6));
        output.push_back(std::move(record));
    }
    return output;
}

bool RankedDatabase::ready() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return database_ != nullptr && !signing_secret_.empty();
}

}  // namespace tenriff::server
