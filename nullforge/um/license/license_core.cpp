// ---------------------------------------------------------------------------
// license_core.cpp
//
// Portable, Windows-free implementation of the license decision logic.
// Compiled and unit-tested by license_test.cpp on the build host.
//
// NEVER put anything secret in this file. It ships inside the client.
// ---------------------------------------------------------------------------

#include "license_core.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace license {

    namespace {

        constexpr std::string_view KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        constexpr std::size_t KEY_BARE_LENGTH = 16;

        bool is_ascii_space(char c) noexcept {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
        }

        char ascii_upper(char c) noexcept {
            return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
        }

        char ascii_lower(char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }

        std::string ascii_lower_copy(std::string_view text) {
            std::string out(text);
            for (char& c : out) {
                c = ascii_lower(c);
            }
            return out;
        }

        bool is_hex_digit(char c) noexcept {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        unsigned hex_value(char c) noexcept {
            if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
            return static_cast<unsigned>(c - 'A' + 10);
        }

        bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

        bool all_digits(std::string_view text) noexcept {
            if (text.empty()) return false;
            return std::all_of(text.begin(), text.end(), is_digit);
        }

        void append_utf8(std::string& out, std::uint32_t code_point) {
            if (code_point > 0x10FFFFu || (code_point >= 0xD800u && code_point <= 0xDFFFu)) {
                code_point = 0xFFFDu; // never emit an invalid scalar value
            }
            if (code_point < 0x80u) {
                out.push_back(static_cast<char>(code_point));
            } else if (code_point < 0x800u) {
                out.push_back(static_cast<char>(0xC0u | (code_point >> 6)));
                out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
            } else if (code_point < 0x10000u) {
                out.push_back(static_cast<char>(0xE0u | (code_point >> 12)));
                out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
            } else {
                out.push_back(static_cast<char>(0xF0u | (code_point >> 18)));
                out.push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
                out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
            }
        }

        std::uint32_t decode_utf8(const std::string& text, std::size_t& index) noexcept {
            const auto byte_at = [&](std::size_t i) -> unsigned {
                return static_cast<unsigned>(static_cast<unsigned char>(text[i]));
            };

            const unsigned b0 = byte_at(index);
            std::size_t extra = 0;
            std::uint32_t code_point = 0;
            std::uint32_t lowest = 0;

            if (b0 < 0x80u) {
                ++index;
                return b0;
            }
            if (b0 >= 0xC2u && b0 <= 0xDFu) {
                extra = 1;
                code_point = b0 & 0x1Fu;
                lowest = 0x80u;
            } else if (b0 >= 0xE0u && b0 <= 0xEFu) {
                extra = 2;
                code_point = b0 & 0x0Fu;
                lowest = 0x800u;
            } else if (b0 >= 0xF0u && b0 <= 0xF4u) {
                extra = 3;
                code_point = b0 & 0x07u;
                lowest = 0x10000u;
            } else {
                ++index; // 0x80..0xC1 and 0xF5..0xFF are never valid leads
                return 0xFFFDu;
            }

            if (index + extra >= text.size()) {
                index = text.size(); // truncated sequence at end of input
                return 0xFFFDu;
            }

            for (std::size_t i = 1; i <= extra; ++i) {
                const unsigned b = byte_at(index + i);
                if ((b & 0xC0u) != 0x80u) {
                    index += i; // resynchronise on the offending byte
                    return 0xFFFDu;
                }
                code_point = (code_point << 6) | (b & 0x3Fu);
            }

            index += extra + 1;

            if (code_point < lowest || code_point > 0x10FFFFu ||
                (code_point >= 0xD800u && code_point <= 0xDFFFu)) {
                return 0xFFFDu;
            }
            return code_point;
        }

        // Days since 1970-01-01 for a proleptic Gregorian y/m/d (Howard Hinnant's
        // algorithm). No timegm, no gmtime_s, no locale, no TZ database.
        std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) noexcept {
            year -= (month <= 2) ? 1 : 0;
            const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
            const auto year_of_era = static_cast<unsigned>(year - era * 400);
            const unsigned shifted_month = (month > 2) ? (month - 3u) : (month + 9u);
            const unsigned day_of_year = (153u * shifted_month + 2u) / 5u + day - 1u;
            const unsigned day_of_era =
                year_of_era * 365u + year_of_era / 4u - year_of_era / 100u + day_of_year;
            return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
        }

        void civil_from_days(std::int64_t days, std::int64_t& year, unsigned& month,
                             unsigned& day) noexcept {
            days += 719468;
            const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
            const auto day_of_era = static_cast<unsigned>(days - era * 146097);
            const unsigned year_of_era =
                (day_of_era - day_of_era / 1460u + day_of_era / 36524u - day_of_era / 146096u) / 365u;
            const std::int64_t y = static_cast<std::int64_t>(year_of_era) + era * 400;
            const unsigned day_of_year =
                day_of_era - (365u * year_of_era + year_of_era / 4u - year_of_era / 100u);
            const unsigned shifted_month = (5u * day_of_year + 2u) / 153u;
            day = day_of_year - (153u * shifted_month + 2u) / 5u + 1u;
            month = (shifted_month < 10u) ? (shifted_month + 3u) : (shifted_month - 9u);
            year = y + ((month <= 2) ? 1 : 0);
        }

        bool is_leap_year(std::int64_t year) noexcept {
            return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        }

        unsigned days_in_month(std::int64_t year, unsigned month) noexcept {
            static const unsigned table[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
            if (month < 1 || month > 12) return 0;
            if (month == 2 && is_leap_year(year)) return 29;
            return table[month - 1];
        }

        std::optional<unsigned> parse_fixed_digits(std::string_view text, std::size_t offset,
                                                   std::size_t count) {
            if (offset + count > text.size()) return std::nullopt;
            const std::string_view slice = text.substr(offset, count);
            if (!all_digits(slice)) return std::nullopt;
            unsigned value = 0;
            for (char c : slice) {
                value = value * 10u + static_cast<unsigned>(c - '0');
            }
            return value;
        }

        // Status-only fallback mapping. Deliberately identical to the table in
        // classify_response() so an unparsable body degrades the same way.
        error_code_t status_fallback(int http_status) noexcept {
            switch (http_status) {
            case 400: return error_code_t::invalid_key;
            case 401: return error_code_t::session_missing;
            case 403: return error_code_t::session_missing;
            case 404: return error_code_t::license_not_found;
            case 409: return error_code_t::hwid_mismatch;
            case 429: return error_code_t::rate_limited;
            case 503: return error_code_t::service_maintenance;
            case 500:
            case 502:
            case 504: return error_code_t::server_error;
            default: return error_code_t::malformed_response;
            }
        }

    } // namespace

    // -------------------------------------------------------------------------
    // error codes
    // -------------------------------------------------------------------------

    const char* to_string(error_code_t code) noexcept {
        switch (code) {
        case error_code_t::none: return "none";
        case error_code_t::invalid_key: return "invalid_key";
        case error_code_t::license_not_found: return "license_not_found";
        case error_code_t::license_revoked: return "license_revoked";
        case error_code_t::license_suspended: return "license_suspended";
        case error_code_t::license_expired: return "license_expired";
        case error_code_t::hwid_mismatch: return "hwid_mismatch";
        case error_code_t::rate_limited: return "rate_limited";
        case error_code_t::session_expired: return "session_expired";
        case error_code_t::session_invalid: return "session_invalid";
        case error_code_t::session_missing: return "session_missing";
        case error_code_t::service_maintenance: return "service_maintenance";
        case error_code_t::database_unavailable: return "database_unavailable";
        case error_code_t::network_error: return "network_error";
        case error_code_t::server_error: return "server_error";
        case error_code_t::malformed_response: return "malformed_response";
        case error_code_t::not_activated: return "not_activated";
        case error_code_t::unknown: return "unknown";
        }
        return "unknown";
    }

    std::wstring to_wstring(error_code_t code) {
        return from_utf8(to_string(code));
    }

    error_code_t error_from_server_code(std::string_view code) noexcept {
        const std::string normalized = ascii_lower_copy(code);
        if (normalized.empty()) return error_code_t::unknown;

        if (normalized == "key_malformed" || normalized == "validation_error" ||
            normalized == "invalid_key" || normalized == "key_invalid") {
            return error_code_t::invalid_key;
        }
        if (normalized == "license_not_found") return error_code_t::license_not_found;
        if (normalized == "license_revoked") return error_code_t::license_revoked;
        if (normalized == "license_suspended") return error_code_t::license_suspended;
        if (normalized == "license_expired") return error_code_t::license_expired;
        if (normalized == "hwid_mismatch") return error_code_t::hwid_mismatch;
        if (normalized == "rate_limited" || normalized == "too_many_requests") {
            return error_code_t::rate_limited;
        }
        if (normalized == "session_expired") return error_code_t::session_expired;
        if (normalized == "session_invalid" || normalized == "token_invalid") {
            return error_code_t::session_invalid;
        }
        if (normalized == "session_missing" || normalized == "auth_required" ||
            normalized == "unauthorized") {
            return error_code_t::session_missing;
        }
        if (normalized == "service_maintenance") return error_code_t::service_maintenance;
        if (normalized == "database_unavailable") return error_code_t::database_unavailable;
        if (normalized == "network_error") return error_code_t::network_error;
        if (normalized == "server_error" || normalized == "internal_error") {
            return error_code_t::server_error;
        }
        if (normalized == "malformed_response") return error_code_t::malformed_response;
        if (normalized == "not_activated") return error_code_t::not_activated;
        return error_code_t::unknown;
    }

    bool is_transient_error(error_code_t code) noexcept {
        switch (code) {
        case error_code_t::network_error:
        case error_code_t::rate_limited:
        case error_code_t::server_error:
        case error_code_t::service_maintenance:
        case error_code_t::database_unavailable:
            return true;
        default:
            return false;
        }
    }

    bool is_hard_failure(error_code_t code) noexcept {
        return code != error_code_t::none && !is_transient_error(code);
    }

    // -------------------------------------------------------------------------
    // json_value_t accessors
    // -------------------------------------------------------------------------

    bool json_value_t::is_null() const noexcept {
        return std::holds_alternative<std::monostate>(storage);
    }

    bool json_value_t::is_bool() const noexcept { return std::holds_alternative<bool>(storage); }

    bool json_value_t::is_number() const noexcept {
        return std::holds_alternative<double>(storage);
    }

    bool json_value_t::is_string() const noexcept {
        return std::holds_alternative<std::string>(storage);
    }

    bool json_value_t::is_array() const noexcept {
        return std::holds_alternative<json_array_t>(storage);
    }

    bool json_value_t::is_object() const noexcept {
        return std::holds_alternative<json_object_t>(storage);
    }

    bool json_value_t::as_bool(bool fallback) const noexcept {
        if (const auto* value = std::get_if<bool>(&storage)) return *value;
        return fallback;
    }

    double json_value_t::as_double(double fallback) const noexcept {
        if (const auto* value = std::get_if<double>(&storage)) return *value;
        return fallback;
    }

    std::int64_t json_value_t::as_int64(std::int64_t fallback) const noexcept {
        if (!is_number()) return fallback;
        // Prefer the exact literal so a 64-bit unix timestamp is not mangled by
        // a round trip through double.
        if (!number_raw.empty()) {
            std::int64_t parsed = 0;
            const char* first = number_raw.data();
            const char* last = first + number_raw.size();
            const auto result = std::from_chars(first, last, parsed);
            if (result.ec == std::errc() && result.ptr == last) return parsed;
        }
        const double value = std::get<double>(storage);
        if (!std::isfinite(value)) return fallback;
        if (value >= 9223372036854775808.0 || value < -9223372036854775808.0) return fallback;
        return static_cast<std::int64_t>(value);
    }

    const std::string& json_value_t::as_string() const noexcept {
        static const std::string empty;
        if (const auto* value = std::get_if<std::string>(&storage)) return *value;
        return empty;
    }

    const json_array_t* json_value_t::as_array() const noexcept {
        return std::get_if<json_array_t>(&storage);
    }

    const json_object_t* json_value_t::as_object() const noexcept {
        return std::get_if<json_object_t>(&storage);
    }

    const json_value_t* json_value_t::find(std::string_view key) const noexcept {
        const auto* members = as_object();
        if (members == nullptr) return nullptr;
        // First match wins; duplicate keys are not an error.
        for (const auto& member : *members) {
            if (member.first == key) return &member.second;
        }
        return nullptr;
    }

    std::string json_value_t::string_at(std::string_view key) const {
        const json_value_t* member = find(key);
        return member != nullptr ? member->as_string() : std::string();
    }

    std::optional<std::int64_t> json_value_t::int_at(std::string_view key) const {
        const json_value_t* member = find(key);
        if (member == nullptr || !member->is_number()) return std::nullopt;
        return member->as_int64();
    }

    // -------------------------------------------------------------------------
    // JSON parser
    // -------------------------------------------------------------------------

    namespace {

        class json_parser final {
        public:
            explicit json_parser(std::string_view text) noexcept : m_text(text) {}

            std::optional<json_value_t> run() {
                if (m_text.size() > json_limits::max_input) return std::nullopt;
                skip_whitespace();
                std::optional<json_value_t> value = parse_value(0);
                if (!value) return std::nullopt;
                skip_whitespace();
                // Trailing content is a hard error: no streaming/no concatenation.
                if (m_pos != m_text.size()) return std::nullopt;
                return value;
            }

        private:
            bool at_end() const noexcept { return m_pos >= m_text.size(); }

            char peek() const noexcept { return m_text[m_pos]; }

            void skip_whitespace() noexcept {
                while (!at_end()) {
                    const char c = m_text[m_pos];
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                        ++m_pos;
                    } else {
                        break;
                    }
                }
            }

            bool consume_literal(std::string_view literal) noexcept {
                if (m_text.size() - m_pos < literal.size()) return false;
                if (m_text.compare(m_pos, literal.size(), literal) != 0) return false;
                m_pos += literal.size();
                return true;
            }

            std::optional<std::string> parse_string() {
                if (at_end() || peek() != '"') return std::nullopt;
                ++m_pos; // opening quote

                std::string out;
                for (;;) {
                    if (at_end()) return std::nullopt; // unterminated
                    if (out.size() > json_limits::max_string) return std::nullopt;

                    const unsigned char c = static_cast<unsigned char>(m_text[m_pos]);

                    if (c == '"') {
                        ++m_pos;
                        return out;
                    }
                    if (c < 0x20u) return std::nullopt; // unescaped control character
                    if (c != '\\') {
                        out.push_back(static_cast<char>(c));
                        ++m_pos;
                        continue;
                    }

                    ++m_pos; // backslash
                    if (at_end()) return std::nullopt;
                    const char escape = m_text[m_pos++];
                    switch (escape) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        std::uint32_t code_point = 0;
                        if (!read_hex4(code_point)) return std::nullopt;
                        if (code_point >= 0xD800u && code_point <= 0xDBFFu) {
                            // high surrogate: needs a following low surrogate
                            if (m_text.size() - m_pos < 6 || m_text[m_pos] != '\\' ||
                                m_text[m_pos + 1] != 'u') {
                                append_utf8(out, 0xFFFDu);
                                break;
                            }
                            const std::size_t saved = m_pos;
                            m_pos += 2;
                            std::uint32_t low = 0;
                            if (!read_hex4(low)) return std::nullopt;
                            if (low >= 0xDC00u && low <= 0xDFFFu) {
                                code_point =
                                    0x10000u + ((code_point - 0xD800u) << 10) + (low - 0xDC00u);
                            } else {
                                m_pos = saved; // rewind, the low half is not one
                                code_point = 0xFFFDu;
                            }
                        } else if (code_point >= 0xDC00u && code_point <= 0xDFFFu) {
                            code_point = 0xFFFDu; // lone low surrogate
                        }
                        append_utf8(out, code_point);
                        break;
                    }
                    default:
                        return std::nullopt; // unknown escape
                    }
                }
            }

            bool read_hex4(std::uint32_t& out) noexcept {
                if (m_text.size() - m_pos < 4) return false;
                std::uint32_t value = 0;
                for (int i = 0; i < 4; ++i) {
                    const char c = m_text[m_pos + static_cast<std::size_t>(i)];
                    if (!is_hex_digit(c)) return false;
                    value = (value << 4) | hex_value(c);
                }
                m_pos += 4;
                out = value;
                return true;
            }

            std::optional<json_value_t> parse_number() {
                const std::size_t start = m_pos;
                if (!at_end() && peek() == '-') ++m_pos;

                if (at_end()) return std::nullopt;
                if (peek() == '0') {
                    ++m_pos; // a leading zero may not be followed by more digits
                } else if (peek() >= '1' && peek() <= '9') {
                    while (!at_end() && is_digit(peek())) ++m_pos;
                } else {
                    return std::nullopt;
                }

                if (!at_end() && peek() == '.') {
                    ++m_pos;
                    if (at_end() || !is_digit(peek())) return std::nullopt;
                    while (!at_end() && is_digit(peek())) ++m_pos;
                }

                if (!at_end() && (peek() == 'e' || peek() == 'E')) {
                    ++m_pos;
                    if (!at_end() && (peek() == '+' || peek() == '-')) ++m_pos;
                    if (at_end() || !is_digit(peek())) return std::nullopt;
                    while (!at_end() && is_digit(peek())) ++m_pos;
                }

                const std::string_view raw = m_text.substr(start, m_pos - start);
                json_value_t value;
                value.storage = decimal_literal_to_double(raw);
                value.number_raw.assign(raw);
                return value;
            }

            // Locale independent. strtod() would honour LC_NUMERIC's decimal
            // separator, which can silently corrupt every number in a body.
            static double decimal_literal_to_double(std::string_view raw) noexcept {
                std::size_t i = 0;
                bool negative = false;
                if (i < raw.size() && (raw[i] == '-' || raw[i] == '+')) {
                    negative = raw[i] == '-';
                    ++i;
                }

                double mantissa = 0.0;
                int significant = 0;
                std::int64_t exponent = 0;
                constexpr int max_significant = 17;

                while (i < raw.size() && is_digit(raw[i])) {
                    if (significant < max_significant) {
                        mantissa = mantissa * 10.0 + static_cast<double>(raw[i] - '0');
                        ++significant;
                    }
                    ++i;
                }
                if (i < raw.size() && raw[i] == '.') {
                    ++i;
                    while (i < raw.size() && is_digit(raw[i])) {
                        if (significant < max_significant) {
                            mantissa = mantissa * 10.0 + static_cast<double>(raw[i] - '0');
                            ++significant;
                            --exponent;
                        }
                        ++i;
                    }
                }
                if (i < raw.size() && (raw[i] == 'e' || raw[i] == 'E')) {
                    ++i;
                    bool exp_negative = false;
                    if (i < raw.size() && (raw[i] == '+' || raw[i] == '-')) {
                        exp_negative = raw[i] == '-';
                        ++i;
                    }
                    std::int64_t exp_value = 0;
                    while (i < raw.size() && is_digit(raw[i])) {
                        if (exp_value < 100000) exp_value = exp_value * 10 + (raw[i] - '0');
                        ++i;
                    }
                    exponent += exp_negative ? -exp_value : exp_value;
                }

                const double result = mantissa * std::pow(10.0, static_cast<double>(exponent));
                return negative ? -result : result;
            }

            std::optional<json_value_t> parse_array(std::size_t depth) {
                ++m_pos; // '['
                json_array_t items;
                skip_whitespace();
                if (!at_end() && peek() == ']') {
                    ++m_pos;
                    return json_value_t(std::move(items));
                }

                for (;;) {
                    if (items.size() >= json_limits::max_elements) return std::nullopt;
                    skip_whitespace();
                    std::optional<json_value_t> item = parse_value(depth + 1);
                    if (!item) return std::nullopt;
                    items.push_back(std::move(*item));
                    skip_whitespace();
                    if (at_end()) return std::nullopt;
                    if (peek() == ',') {
                        ++m_pos;
                        continue;
                    }
                    if (peek() == ']') {
                        ++m_pos;
                        return json_value_t(std::move(items));
                    }
                    return std::nullopt;
                }
            }

            std::optional<json_value_t> parse_object(std::size_t depth) {
                ++m_pos; // '{'
                json_object_t members;
                skip_whitespace();
                if (!at_end() && peek() == '}') {
                    ++m_pos;
                    return json_value_t(std::move(members));
                }

                for (;;) {
                    if (members.size() >= json_limits::max_elements) return std::nullopt;
                    skip_whitespace();
                    std::optional<std::string> key = parse_string();
                    if (!key) return std::nullopt;
                    skip_whitespace();
                    if (at_end() || peek() != ':') return std::nullopt;
                    ++m_pos;
                    skip_whitespace();
                    std::optional<json_value_t> value = parse_value(depth + 1);
                    if (!value) return std::nullopt;
                    members.emplace_back(std::move(*key), std::move(*value));
                    skip_whitespace();
                    if (at_end()) return std::nullopt;
                    if (peek() == ',') {
                        ++m_pos;
                        continue;
                    }
                    if (peek() == '}') {
                        ++m_pos;
                        return json_value_t(std::move(members));
                    }
                    return std::nullopt;
                }
            }

            std::optional<json_value_t> parse_value(std::size_t depth) {
                if (depth > json_limits::max_depth) return std::nullopt;
                if (at_end()) return std::nullopt;

                switch (peek()) {
                case '{':
                    return parse_object(depth);
                case '[':
                    return parse_array(depth);
                case '"': {
                    std::optional<std::string> text = parse_string();
                    if (!text) return std::nullopt;
                    return json_value_t(std::move(*text));
                }
                case 't':
                    if (!consume_literal("true")) return std::nullopt;
                    return json_value_t(true);
                case 'f':
                    if (!consume_literal("false")) return std::nullopt;
                    return json_value_t(false);
                case 'n':
                    if (!consume_literal("null")) return std::nullopt;
                    return json_value_t(nullptr);
                default:
                    if (peek() == '-' || is_digit(peek())) return parse_number();
                    return std::nullopt;
                }
            }

            std::string_view m_text;
            std::size_t m_pos{0};
        };

    } // namespace

    std::optional<json_value_t> parse_json(std::string_view text) {
        json_parser parser(text);
        return parser.run();
    }

    std::string json_escape(std::string_view text) {
        std::string out;
        out.reserve(text.size() + 8);
        for (char raw : text) {
            const auto c = static_cast<unsigned char>(raw);
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20u) {
                    static const char* kHex = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(kHex[(c >> 4) & 0x0Fu]);
                    out.push_back(kHex[c & 0x0Fu]);
                } else {
                    out.push_back(raw);
                }
                break;
            }
        }
        return out;
    }

    std::string build_activate_body(const std::string& key, const std::string& hwid) {
        std::string body;
        body.reserve(key.size() + hwid.size() + 32);
        body += "{\"key\":\"";
        body += json_escape(key);
        body += "\",\"hwid\":\"";
        body += json_escape(hwid);
        body += "\"}";
        return body;
    }

    std::string build_validate_body(const std::string& hwid) {
        std::string body;
        body.reserve(hwid.size() + 16);
        body += "{\"hwid\":\"";
        body += json_escape(hwid);
        body += "\"}";
        return body;
    }

    // -------------------------------------------------------------------------
    // license key normalization  (mirrors server/app/keys.py)
    // -------------------------------------------------------------------------

    std::string_view license_key_alphabet() noexcept { return KEY_ALPHABET; }

    std::optional<std::string> normalize_license_key(const std::string& raw) {
        // 1. trim surrounding whitespace
        std::size_t begin = 0;
        std::size_t end = raw.size();
        while (begin < end && is_ascii_space(raw[begin])) ++begin;
        while (end > begin && is_ascii_space(raw[end - 1])) --end;
        if (begin == end) return std::nullopt;

        // 2. uppercase and drop exactly what keys.py drops:
        //    _STRIPPED_CHARACTERS = " \t\r\n\v\f\u00a0" + "-"
        //    NBSP is two bytes in UTF-8 (0xC2 0xA0) and is matched as a pair,
        //    so a key pasted out of a browser or a pdf normalizes here exactly
        //    as it does on the server.
        std::string bare;
        bare.reserve(end - begin);
        for (std::size_t i = begin; i < end; ++i) {
            const unsigned char c = static_cast<unsigned char>(raw[i]);
            if (c == static_cast<unsigned char>('-') ||
                is_ascii_space(static_cast<char>(c))) {
                continue;
            }
            if (c == 0xC2u && i + 1 < end &&
                static_cast<unsigned char>(raw[i + 1]) == 0xA0u) {
                ++i; // non-breaking space
                continue;
            }
            bare.push_back(ascii_upper(static_cast<char>(c)));
        }

        // 3. exactly 16 symbols from the server alphabet. Partial keys are
        //    rejected outright - never padded, never truncated, never guessed.
        if (bare.size() != KEY_BARE_LENGTH) return std::nullopt;
        for (char c : bare) {
            if (KEY_ALPHABET.find(c) == std::string_view::npos) return std::nullopt;
        }

        // 4. re-emit as XXXX-XXXX-XXXX-XXXX
        std::string formatted;
        formatted.reserve(KEY_BARE_LENGTH + 3);
        for (std::size_t i = 0; i < bare.size(); ++i) {
            if (i != 0 && i % 4 == 0) formatted.push_back('-');
            formatted.push_back(bare[i]);
        }
        return formatted;
    }

    std::optional<std::string> to_bare_key(const std::string& normalized_dashed) {
        if (normalized_dashed.size() != KEY_BARE_LENGTH + 3) return std::nullopt;
        std::string bare;
        bare.reserve(KEY_BARE_LENGTH);
        for (std::size_t i = 0; i < normalized_dashed.size(); ++i) {
            const char c = normalized_dashed[i];
            if (c == '-') {
                if (i != 4 && i != 9 && i != 14) return std::nullopt;
                continue;
            }
            bare.push_back(c);
        }
        return bare.size() == KEY_BARE_LENGTH ? std::optional<std::string>(bare) : std::nullopt;
    }

    // -------------------------------------------------------------------------
    // response envelope
    // -------------------------------------------------------------------------

    bool envelope_success(const json_value_t& body) noexcept {
        if (!body.is_object()) return false;
        const json_value_t* success = body.find("success");
        // Strictly JSON `true`. `"true"`, `1` and a missing field all fail.
        return success != nullptr && success->is_bool() && success->as_bool(false);
    }

    std::string extract_error_code_string(const json_value_t& body) {
        if (!body.is_object()) return std::string();
        const json_value_t* error = body.find("error");
        if (error != nullptr && error->is_object()) {
            const std::string code = error->string_at("code");
            if (!code.empty()) return code;
        }
        if (error != nullptr && error->is_string() && !error->as_string().empty()) {
            return error->as_string();
        }
        return body.string_at("error_code");
    }

    std::string extract_error_message(const json_value_t& body) {
        if (!body.is_object()) return std::string();
        const json_value_t* error = body.find("error");
        if (error != nullptr && error->is_object()) {
            const std::string message = error->string_at("message");
            if (!message.empty()) return message;
        }
        if (error != nullptr && error->is_string()) return error->as_string();
        return body.string_at("message");
    }

    error_code_t classify_response(int http_status, const json_value_t& body) {
        const std::string code_string = extract_error_code_string(body);
        const error_code_t from_code = error_from_server_code(code_string);
        const bool code_recognised = !code_string.empty() && from_code != error_code_t::unknown;

        if (http_status == 200) {
            // The ONLY success signal in the whole client: HTTP 200 carrying
            // `"success": true`. Nothing else, ever, produces error_code_t::none.
            if (envelope_success(body)) return error_code_t::none;
            if (code_recognised) return from_code;
            return error_code_t::malformed_response;
        }

        if (code_recognised) return from_code;
        return status_fallback(http_status);
    }

    error_code_t classify_unparsable_response(int http_status) noexcept {
        return status_fallback(http_status);
    }

    std::string extract_session_token(const json_value_t& body) {
        if (!body.is_object()) return std::string();
        std::string token = body.string_at("session_token");
        if (!token.empty()) return token;
        token = body.string_at("token");
        if (!token.empty()) return token;

        const json_value_t* data = body.find("data");
        if (data == nullptr || !data->is_object()) return std::string();
        token = data->string_at("session_token");
        if (!token.empty()) return token;
        return data->string_at("token");
    }

    std::optional<std::chrono::system_clock::time_point> extract_expiry(const json_value_t& body) {
        if (!body.is_object()) return std::nullopt;

        const auto from_rfc3339 = [](const std::string& text)
            -> std::optional<std::chrono::system_clock::time_point> {
            if (text.empty()) return std::nullopt;
            return parse_rfc3339(text);
        };

        if (auto parsed = from_rfc3339(body.string_at("expires_at"))) return parsed;
        if (auto parsed = from_rfc3339(body.string_at("expires"))) return parsed;
        if (auto seconds = body.int_at("exp")) return from_unix_seconds(*seconds);
        if (auto seconds = body.int_at("expires_at_unix")) return from_unix_seconds(*seconds);

        const json_value_t* data = body.find("data");
        if (data == nullptr || !data->is_object()) return std::nullopt;
        if (auto parsed = from_rfc3339(data->string_at("expires_at"))) return parsed;
        if (auto seconds = data->int_at("exp")) return from_unix_seconds(*seconds);
        return std::nullopt;
    }

    // -------------------------------------------------------------------------
    // base64url + JWT
    // -------------------------------------------------------------------------

    std::optional<std::string> base64url_decode(std::string_view text) {
        if (text.size() % 4 == 1) return std::nullopt; // no byte can come from one symbol

        std::size_t pad_start = text.size();
        std::string out;
        out.reserve(text.size() / 4 * 3 + 3);

        std::uint32_t buffer = 0;
        int bits = 0;

        for (std::size_t i = 0; i < text.size(); ++i) {
            const char c = text[i];
            if (c == '=') {
                pad_start = i;
                break;
            }

            int value = -1;
            if (c >= 'A' && c <= 'Z') value = c - 'A';
            else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
            else if (c >= '0' && c <= '9') value = c - '0' + 52;
            else if (c == '-' || c == '+') value = 62;
            else if (c == '_' || c == '/') value = 63;
            else return std::nullopt; // whitespace and everything else: rejected

            buffer = (buffer << 6) | static_cast<std::uint32_t>(value);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<char>((buffer >> bits) & 0xFFu));
            }
        }

        // Padding, when present, must be the tail and nothing else.
        for (std::size_t i = pad_start; i < text.size(); ++i) {
            if (text[i] != '=') return std::nullopt;
        }
        if (pad_start % 4 != 0 && pad_start != text.size()) {
            // "QQ=" style is nonsense; only 0, 2 or 3 symbols before padding
            if (pad_start % 4 != 2 && pad_start % 4 != 3) return std::nullopt;
        }

        if (bits >= 6) return std::nullopt;
        if (bits > 0 && (buffer & ((1u << bits) - 1u)) != 0) return std::nullopt; // non-canonical
        return out;
    }

    std::string base64url_encode(std::string_view raw) {
        static const char* kAlphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        std::string out;
        out.reserve((raw.size() + 2) / 3 * 4);

        std::size_t i = 0;
        while (i + 3 <= raw.size()) {
            const std::uint32_t triple = (static_cast<unsigned char>(raw[i]) << 16) |
                                         (static_cast<unsigned char>(raw[i + 1]) << 8) |
                                         static_cast<unsigned char>(raw[i + 2]);
            out.push_back(kAlphabet[(triple >> 18) & 0x3Fu]);
            out.push_back(kAlphabet[(triple >> 12) & 0x3Fu]);
            out.push_back(kAlphabet[(triple >> 6) & 0x3Fu]);
            out.push_back(kAlphabet[triple & 0x3Fu]);
            i += 3;
        }

        const std::size_t remaining = raw.size() - i;
        if (remaining == 1) {
            const std::uint32_t triple = static_cast<unsigned char>(raw[i]) << 16;
            out.push_back(kAlphabet[(triple >> 18) & 0x3Fu]);
            out.push_back(kAlphabet[(triple >> 12) & 0x3Fu]);
        } else if (remaining == 2) {
            const std::uint32_t triple = (static_cast<unsigned char>(raw[i]) << 16) |
                                         (static_cast<unsigned char>(raw[i + 1]) << 8);
            out.push_back(kAlphabet[(triple >> 18) & 0x3Fu]);
            out.push_back(kAlphabet[(triple >> 12) & 0x3Fu]);
            out.push_back(kAlphabet[(triple >> 6) & 0x3Fu]);
        }
        return out; // unpadded, per base64url
    }

    bool jwt_claims_t::is_expired(std::chrono::system_clock::time_point now) const noexcept {
        if (!exp.has_value()) return false;
        return now >= from_unix_seconds(*exp);
    }

    std::optional<jwt_claims_t> parse_jwt_claims(const std::string& token) {
        std::string_view text(token);
        while (!text.empty() && is_ascii_space(text.front())) text.remove_prefix(1);
        while (!text.empty() && is_ascii_space(text.back())) text.remove_suffix(1);
        if (text.empty()) return std::nullopt;

        // header.payload.signature, all three non-empty.
        const std::size_t first_dot = text.find('.');
        if (first_dot == std::string_view::npos) return std::nullopt;
        const std::size_t second_dot = text.find('.', first_dot + 1);
        if (second_dot == std::string_view::npos) return std::nullopt;
        if (text.find('.', second_dot + 1) != std::string_view::npos) return std::nullopt;
        if (first_dot == 0) return std::nullopt;
        if (second_dot == first_dot + 1) return std::nullopt;
        if (second_dot + 1 >= text.size()) return std::nullopt;

        const std::optional<std::string> header_bytes = base64url_decode(text.substr(0, first_dot));
        if (!header_bytes) return std::nullopt;
        const std::optional<json_value_t> header = parse_json(*header_bytes);
        if (!header || !header->is_object()) return std::nullopt;

        const std::string alg = ascii_lower_copy(header->string_at("alg"));
        if (alg.empty()) return std::nullopt;
        // An unsigned token is never acceptable, not even for local gating.
        if (alg == "none") return std::nullopt;

        const std::optional<std::string> payload_bytes =
            base64url_decode(text.substr(first_dot + 1, second_dot - first_dot - 1));
        if (!payload_bytes) return std::nullopt;
        const std::optional<json_value_t> payload = parse_json(*payload_bytes);
        if (!payload || !payload->is_object()) return std::nullopt;

        jwt_claims_t claims;
        claims.alg = alg;
        claims.jti = payload->string_at("jti");
        claims.sub = payload->string_at("sub");
        claims.exp = payload->int_at("exp");
        claims.iat = payload->int_at("iat");
        return claims;
    }

    // -------------------------------------------------------------------------
    // time
    // -------------------------------------------------------------------------

    std::chrono::system_clock::time_point utc_now() noexcept {
        return std::chrono::system_clock::now();
    }

    std::int64_t to_unix_seconds(std::chrono::system_clock::time_point tp) noexcept {
        return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
    }

    std::chrono::system_clock::time_point from_unix_seconds(std::int64_t seconds) noexcept {
        return std::chrono::system_clock::time_point(std::chrono::seconds(seconds));
    }

    std::string format_rfc3339(std::chrono::system_clock::time_point tp) {
        std::int64_t seconds = to_unix_seconds(tp);
        std::int64_t days = seconds / 86400;
        std::int64_t remainder = seconds % 86400;
        if (remainder < 0) {
            remainder += 86400;
            --days;
        }

        std::int64_t year = 0;
        unsigned month = 0;
        unsigned day = 0;
        civil_from_days(days, year, month, day);

        const unsigned hour = static_cast<unsigned>(remainder / 3600);
        const unsigned minute = static_cast<unsigned>((remainder % 3600) / 60);
        const unsigned second = static_cast<unsigned>(remainder % 60);

        std::string out;
        out.reserve(20);
        const auto append_padded = [&out](unsigned value, unsigned width) {
            std::string digits = std::to_string(value);
            while (digits.size() < width) digits.insert(digits.begin(), '0');
            out += digits;
        };
        append_padded(static_cast<unsigned>(year), 4);
        out.push_back('-');
        append_padded(month, 2);
        out.push_back('-');
        append_padded(day, 2);
        out.push_back('T');
        append_padded(hour, 2);
        out.push_back(':');
        append_padded(minute, 2);
        out.push_back(':');
        append_padded(second, 2);
        out.push_back('Z');
        return out;
    }

    std::optional<std::chrono::system_clock::time_point> parse_rfc3339(std::string_view text) {
        // "YYYY-MM-DDTHH:MM:SS" plus optional fraction plus optional offset.
        if (text.size() < 19) return std::nullopt;

        const auto year = parse_fixed_digits(text, 0, 4);
        const auto month = parse_fixed_digits(text, 5, 2);
        const auto day = parse_fixed_digits(text, 8, 2);
        const auto hour = parse_fixed_digits(text, 11, 2);
        const auto minute = parse_fixed_digits(text, 14, 2);
        const auto second = parse_fixed_digits(text, 17, 2);
        if (!year || !month || !day || !hour || !minute || !second) return std::nullopt;

        if (text[4] != '-' || text[7] != '-') return std::nullopt;
        const char separator = text[10];
        if (separator != 'T' && separator != 't' && separator != ' ') return std::nullopt;
        if (text[13] != ':' || text[16] != ':') return std::nullopt;

        const auto year_value = static_cast<std::int64_t>(*year);
        if (*month < 1 || *month > 12) return std::nullopt;
        if (*day < 1 || *day > days_in_month(year_value, *month)) return std::nullopt;
        if (*hour > 23 || *minute > 59 || *second > 59) return std::nullopt; // no leap seconds

        std::size_t cursor = 19;
        if (cursor < text.size() && text[cursor] == '.') {
            ++cursor;
            std::size_t digits = 0;
            while (cursor < text.size() && is_digit(text[cursor])) {
                ++cursor;
                ++digits;
            }
            if (digits == 0 || digits > 9) return std::nullopt; // "." or 1e9+ digits
        }

        std::int64_t offset_seconds = 0;
        if (cursor < text.size()) {
            const char zone = text[cursor];
            if (zone == 'Z' || zone == 'z') {
                ++cursor;
            } else if (zone == '+' || zone == '-') {
                const auto off_hour = parse_fixed_digits(text, cursor + 1, 2);
                if (!off_hour) return std::nullopt;
                if (text[cursor + 3] != ':') return std::nullopt;
                const auto off_minute = parse_fixed_digits(text, cursor + 4, 2);
                if (!off_minute) return std::nullopt;
                if (*off_hour > 23 || *off_minute > 59) return std::nullopt;
                offset_seconds = static_cast<std::int64_t>(*off_hour) * 3600 +
                                 static_cast<std::int64_t>(*off_minute) * 60;
                if (zone == '+') offset_seconds = -offset_seconds;
                cursor += 5;
            } else {
                return std::nullopt;
            }
        }

        if (cursor != text.size()) return std::nullopt; // trailing junk

        const std::int64_t days = days_from_civil(year_value, *month, *day);
        const std::int64_t seconds = days * 86400 + static_cast<std::int64_t>(*hour) * 3600 +
                                     static_cast<std::int64_t>(*minute) * 60 +
                                     static_cast<std::int64_t>(*second) + offset_seconds;
        return from_unix_seconds(seconds);
    }

    // -------------------------------------------------------------------------
    // text conversion
    // -------------------------------------------------------------------------

    std::string to_utf8(const std::wstring& text) {
        std::string out;
        out.reserve(text.size());
        for (std::size_t i = 0; i < text.size(); ++i) {
            std::uint32_t code_point = static_cast<std::uint32_t>(text[i]);
            if (code_point >= 0xD800u && code_point <= 0xDBFFu && i + 1 < text.size()) {
                const std::uint32_t low = static_cast<std::uint32_t>(text[i + 1]);
                if (low >= 0xDC00u && low <= 0xDFFFu) {
                    code_point = 0x10000u + ((code_point - 0xD800u) << 10) + (low - 0xDC00u);
                    ++i;
                } else {
                    code_point = 0xFFFDu;
                }
            } else if (code_point >= 0xD800u && code_point <= 0xDFFFu) {
                code_point = 0xFFFDu;
            }
            append_utf8(out, code_point);
        }
        return out;
    }

    std::wstring from_utf8(const std::string& text) {
        std::wstring out;
        out.reserve(text.size());
        std::size_t index = 0;
        while (index < text.size()) {
            const std::uint32_t code_point = decode_utf8(text, index);
            if (code_point < 0x10000u) {
                out.push_back(static_cast<wchar_t>(code_point));
            } else {
                const std::uint32_t adjusted = code_point - 0x10000u;
                out.push_back(static_cast<wchar_t>(0xD800u + (adjusted >> 10)));
                out.push_back(static_cast<wchar_t>(0xDC00u + (adjusted & 0x3FFu)));
            }
        }
        return out;
    }

    // -------------------------------------------------------------------------
    // offline policy
    // -------------------------------------------------------------------------

    offline_decision_t decide_offline(offline_policy_t policy,
                                      error_code_t last_error,
                                      const offline_state_t& state,
                                      std::chrono::system_clock::time_point now,
                                      std::chrono::seconds grace) noexcept {
        if (last_error == error_code_t::none) return offline_decision_t::allow_grace;

        // A definitive refusal is never papered over, under any policy.
        if (is_hard_failure(last_error)) return offline_decision_t::deny;

        // Past this point the failure is transient. Neither policy may ever run
        // past a server-issued session expiry.
        const bool session_still_valid = state.has_session && state.has_session_expiry &&
                                         now < state.session_exp;

        if (policy == offline_policy_t::cached_grace) {
            return session_still_valid ? offline_decision_t::allow_grace
                                       : offline_decision_t::deny;
        }

        // fail_closed: the default grace is zero, which denies on the first
        // failure. A grace window, if one was configured, is still capped by the
        // session expiry and requires a previously successful validation.
        if (grace.count() <= 0) return offline_decision_t::deny;
        if (!session_still_valid) return offline_decision_t::deny;
        if (state.last_success == std::chrono::system_clock::time_point{}) {
            return offline_decision_t::deny;
        }
        if (now - state.last_success >= grace) return offline_decision_t::deny;
        return offline_decision_t::allow_grace;
    }

} // namespace license
