#pragma once

// ---------------------------------------------------------------------------
// license_core.hpp
//
// PORTABLE portion of the HWID license client. This header and license_core.cpp
// are 100% standard C++20 with ZERO Windows headers so that the decision logic
// can be compiled and unit-tested on any host (see license_test.cpp).
//
// Everything that actually talks to the network, reads the registry, hashes
// with BCrypt or touches the filesystem lives in license_win.cpp and is compiled
// out entirely when _WIN32 is not defined.
//
// SECURITY POSTURE (read this before adding anything to this file):
//   * There is NO signing key, NO JWT secret, NO admin token and NO pepper in
//     this repository, on purpose. See README.md ("Known limitations").
//   * Nothing in this file ever returns "success" because the server was
//     unreachable. See decide_offline().
// ---------------------------------------------------------------------------

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace license {

    // -------------------------------------------------------------------------
    // error codes
    // -------------------------------------------------------------------------

    // Mirrors the server's `error.code` strings. Values are stable ints so they
    // can be logged / compared across builds; the order is NOT the wire format.
    enum class error_code_t : int {
        none = 0,             // success
        invalid_key,          // KEY_MALFORMED / VALIDATION_ERROR
        license_not_found,    // LICENSE_NOT_FOUND
        license_revoked,      // LICENSE_REVOKED
        license_suspended,    // LICENSE_SUSPENDED
        license_expired,      // LICENSE_EXPIRED
        hwid_mismatch,        // HWID_MISMATCH
        rate_limited,         // RATE_LIMITED
        session_expired,      // SESSION_EXPIRED
        session_invalid,      // SESSION_INVALID / TOKEN_INVALID
        session_missing,      // SESSION_MISSING / AUTH_REQUIRED
        service_maintenance,  // SERVICE_MAINTENANCE
        database_unavailable, // DATABASE_UNAVAILABLE
        network_error,        // transport failure: DNS/connect/TLS/timeout
        server_error,         // 500 / 502 / 504
        malformed_response,   // not JSON, or JSON we cannot make sense of
        not_activated,        // local only: no session token has been issued yet
        unknown               // unmapped server code / anything else
    };

    // Stable identifier, e.g. "hwid_mismatch". Never null.
    const char* to_string(error_code_t code) noexcept;
    std::wstring to_wstring(error_code_t code);

    // Maps the server's `error.code` string onto the enum. Unknown literals and
    // empty strings both yield error_code_t::unknown.
    error_code_t error_from_server_code(std::string_view code) noexcept;

    // Transient == the server never got to make an authorization decision, or it
    // made one that is expected to clear on its own (429 / maintenance). Only
    // transient errors may ever be covered by offline_policy_t::cached_grace.
    bool is_transient_error(error_code_t code) noexcept;

    // Hard == the server (or local validation) definitively refused. These must
    // never be retried and are never covered by any offline grace.
    bool is_hard_failure(error_code_t code) noexcept;

    // -------------------------------------------------------------------------
    // minimal JSON
    // -------------------------------------------------------------------------

    struct json_value_t;

    using json_array_t = std::vector<json_value_t>;
    using json_object_t = std::vector<std::pair<std::string, json_value_t>>;

    // Hard parser limits. Anything exceeding them is rejected, not truncated.
    // These bound both memory and recursion so a hostile body cannot make us
    // allocate wildly or blow the stack.
    namespace json_limits {
        inline constexpr std::size_t max_depth = 32;            // nesting depth
        inline constexpr std::size_t max_input = 256u * 1024u;  // 256 KiB
        inline constexpr std::size_t max_string = 64u * 1024u;  // 64 KiB
        inline constexpr std::size_t max_elements = 4096u;      // per array/object
    }

    struct json_value_t {
        using storage_t = std::variant<std::monostate, bool, double, std::string, json_array_t, json_object_t>;

        storage_t storage{};
        // Exact source text of a number literal. `exp` is read through this so a
        // 64-bit unix timestamp survives without going through a double.
        std::string number_raw{};

        json_value_t() = default;
        json_value_t(std::nullptr_t) {}
        json_value_t(bool v) : storage(v) {}
        json_value_t(double v) : storage(v) {}
        json_value_t(std::string v) : storage(std::move(v)) {}
        json_value_t(const char* v) : storage(std::string(v ? v : "")) {}
        json_value_t(json_array_t v) : storage(std::move(v)) {}
        json_value_t(json_object_t v) : storage(std::move(v)) {}

        bool is_null() const noexcept;
        bool is_bool() const noexcept;
        bool is_number() const noexcept;
        bool is_string() const noexcept;
        bool is_array() const noexcept;
        bool is_object() const noexcept;

        bool as_bool(bool fallback = false) const noexcept;
        double as_double(double fallback = 0.0) const noexcept;
        std::int64_t as_int64(std::int64_t fallback = 0) const noexcept;
        // Returns a pointer to a shared empty string when this is not a string.
        const std::string& as_string() const noexcept;
        const json_array_t* as_array() const noexcept;
        const json_object_t* as_object() const noexcept;

        // Object member lookup. nullptr when absent or when *this is not an object.
        const json_value_t* find(std::string_view key) const noexcept;
        bool has(std::string_view key) const noexcept { return find(key) != nullptr; }
        std::string string_at(std::string_view key) const;
        std::optional<std::int64_t> int_at(std::string_view key) const;
    };

    // Strict RFC 8259 parser. Returns nullopt on ANY malformed input, on input
    // longer than json_limits::max_input, or on nesting deeper than
    // json_limits::max_depth. Never throws, never loops forever, never reads out
    // of bounds. Trailing non-whitespace after the value is an error.
    std::optional<json_value_t> parse_json(std::string_view text);

    // Convenience for building the small request bodies. Not a general
    // serializer (no pretty printing, no indentation).
    std::string json_escape(std::string_view text);
    std::string build_activate_body(const std::string& key, const std::string& hwid);
    std::string build_validate_body(const std::string& hwid);

    // -------------------------------------------------------------------------
    // license key normalization
    // -------------------------------------------------------------------------

    // Exactly 16 symbols from the alphabet below, emitted as XXXX-XXXX-XXXX-XXXX.
    // Mirrors server/app/keys.py. Steps: trim surrounding whitespace, uppercase,
    // drop every space and hyphen, require exactly 16 characters drawn from
    // ABCDEFGHJKLMNPQRSTUVWXYZ23456789 (note: no I, O, 0 or 1), re-insert the
    // dashes. Anything shorter or longer is REJECTED - partial keys are never
    // padded or guessed.
    std::optional<std::string> normalize_license_key(const std::string& raw);

    // The bare (undashed) 16-symbol form, which is what gets sent on the wire.
    std::optional<std::string> to_bare_key(const std::string& normalized_dashed);

    // The server alphabet, exposed for tests and for the error message.
    std::string_view license_key_alphabet() noexcept;

    // -------------------------------------------------------------------------
    // server response envelope
    // -------------------------------------------------------------------------

    // Classifies an HTTP status plus a (possibly absent) parsed body onto
    // error_code_t, implementing the server contract:
    //   200 + success:true              -> none
    //   400                            -> invalid_key       (KEY_MALFORMED/VALIDATION_ERROR)
    //   401                            -> session_expired / session_invalid / session_missing
    //   403                            -> session_missing   (AUTH_REQUIRED)
    //   404                            -> license_not_found
    //   409                            -> hwid_mismatch
    //   429                            -> rate_limited
    //   500 / 502 / 504                -> server_error
    //   503                            -> service_maintenance
    //   anything else, or 200 with success != true -> malformed_response
    // When the body carries a recognised `error.code`, that wins over the bare
    // status mapping.
    error_code_t classify_response(int http_status, const json_value_t& body);

    // Same, but for the "we could not even parse the body" case.
    error_code_t classify_unparsable_response(int http_status) noexcept;

    bool envelope_success(const json_value_t& body) noexcept;

    // `error.message` from the server. Already user-safe English, meant to be
    // shown verbatim in a MessageBox. Empty when absent.
    std::string extract_error_message(const json_value_t& body);
    std::string extract_error_code_string(const json_value_t& body);

    // Session token, which the server puts either at `session_token` or at
    // `data.session_token`. Empty when absent.
    std::string extract_session_token(const json_value_t& body);

    // Server-declared expiry: `expires_at` (RFC 3339) or `data.expires_at`, with
    // a numeric `exp`/`data.exp` as a unix-seconds fallback.
    std::optional<std::chrono::system_clock::time_point> extract_expiry(const json_value_t& body);

    // -------------------------------------------------------------------------
    // JWT (local gating only - NOT verification)
    // -------------------------------------------------------------------------

    struct jwt_claims_t {
        std::string alg;
        std::string jti;
        std::string sub;
        std::optional<std::int64_t> exp; // unix seconds
        std::optional<std::int64_t> iat; // unix seconds
        bool has_expiry() const noexcept { return exp.has_value(); }
        bool is_expired(std::chrono::system_clock::time_point now) const noexcept;
    };

    // IMPORTANT: this decodes the token so the client can honour its `exp` while
    // the server is unreachable. It performs NO signature verification and NO
    // issuer/audience validation - the client holds no key and must never be
    // given one. A token that parses here is therefore NOT proof of anything: the
    // only authoritative check is a successful validate() against the server.
    // Unsigned ("alg":"none") or headerless tokens are rejected outright.
    std::optional<jwt_claims_t> parse_jwt_claims(const std::string& token);

    // base64url without padding. Rejects any character outside the alphabet.
    std::optional<std::string> base64url_decode(std::string_view text);
    std::string base64url_encode(std::string_view raw);

    // -------------------------------------------------------------------------
    // time helpers
    // -------------------------------------------------------------------------

    std::chrono::system_clock::time_point utc_now() noexcept;
    std::int64_t to_unix_seconds(std::chrono::system_clock::time_point tp) noexcept;
    std::chrono::system_clock::time_point from_unix_seconds(std::int64_t seconds) noexcept;

    // "2026-10-01T12:34:56Z". Always UTC, second resolution.
    std::string format_rfc3339(std::chrono::system_clock::time_point tp);

    // Accepts "YYYY-MM-DDTHH:MM:SS", optional fractional seconds, and an
    // optional 'Z' or +/-HH:MM offset. Rejects out-of-range fields rather than
    // clamping them. Locale independent.
    std::optional<std::chrono::system_clock::time_point> parse_rfc3339(std::string_view text);

    // -------------------------------------------------------------------------
    // text conversion (MessageBoxW wants wide, JSON wants UTF-8)
    // -------------------------------------------------------------------------

    std::string to_utf8(const std::wstring& text);
    std::wstring from_utf8(const std::string& text);

    // -------------------------------------------------------------------------
    // offline policy / decision logic
    // -------------------------------------------------------------------------

    // There is NO "return true on failure" path in this module, ever. The only
    // leniency is time-bounded and lives in decide_offline() below.
    enum class offline_policy_t {
        fail_closed = 0, // default. Any network/parse failure is an error.
        cached_grace     // may keep operating ONLY until a previously issued
                         // session token's `exp` passes. Never beyond, and never
                         // after the server answered 4xx.
    };

    struct offline_state_t {
        bool has_session{false};
        bool has_session_expiry{false};
        std::chrono::system_clock::time_point session_exp{};
        std::chrono::system_clock::time_point last_success{};
        int consecutive_transient_failures{0};
    };

    enum class offline_decision_t {
        deny = 0,     // shut down / re-activate
        allow_grace   // keep running, still time-bounded
    };

    // The single choke point that decides whether a failed revalidation may be
    // ridden out. `last_error` is the error that just happened:
    //   * a HARD failure (revoked, suspended, expired, hwid_mismatch,
    //     invalid_key, not_found, malformed_response, ...) -> always deny,
    //     regardless of policy and regardless of grace.
    //   * a TRANSIENT failure with policy fail_closed -> deny once `grace`
    //     seconds have elapsed since last_success; with the default grace of
    //     zero that means deny on the first failure.
    //   * a TRANSIENT failure with policy cached_grace -> allow only while
    //     now < session_exp. Once `exp` passes this returns deny, permanently.
    offline_decision_t decide_offline(offline_policy_t policy,
                                      error_code_t last_error,
                                      const offline_state_t& state,
                                      std::chrono::system_clock::time_point now,
                                      std::chrono::seconds grace) noexcept;

} // namespace license
