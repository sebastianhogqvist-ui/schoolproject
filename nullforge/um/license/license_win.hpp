#pragma once

// ---------------------------------------------------------------------------
// license_win.hpp
//
// Windows-only surface for the portable license client. This header is only
// pulled in by license.hpp when _WIN32 is defined, so it may freely name Win32
// types. The .cpp keeps every Windows-specific implementation behind
// #ifdef _WIN32 with a stub #else branch so the file still compiles on Linux
// (used only to verify the type surface).
//
// SECURITY: this file and license_win.cpp contain NO signing key, NO JWT
// secret, NO admin token and NO pepper. The only secret-like value here is the
// license key the user types, and that never touches this file.
// ---------------------------------------------------------------------------

#include <chrono>
#include <optional>
#include <string>

#include "license_core.hpp"

namespace license {

    // Result of a single network round-trip. `session_token` is filled in by
    // activate()/validate()/logout(); `claims`/`expires_at` are derived from
    // that token and the server-declared expiry so the client can honour them
    // while offline.
    struct network_result_t {
        error_code_t code{error_code_t::unknown};
        std::string session_token;
        std::optional<jwt_claims_t> claims;
        std::optional<std::chrono::system_clock::time_point> expires_at;
    };

    // WinHTTP-based provider. Construct once with the base URL (scheme +
    // host + port, no trailing slash), then call activate/validate/logout.
    class NetworkProvider {
    public:
        explicit NetworkProvider(std::string base_url);
        ~NetworkProvider();

        NetworkProvider(const NetworkProvider&) = delete;
        NetworkProvider& operator=(const NetworkProvider&) = delete;
        NetworkProvider(NetworkProvider&&) = delete;
        NetworkProvider& operator=(NetworkProvider&&) = delete;

        network_result_t activate(const std::string& key, const std::string& hwid);
        network_result_t validate(const std::string& hwid);
        network_result_t logout();
        network_result_t license_status();

    private:
        network_result_t post_json(const std::string& path, const std::string& body);
        network_result_t get_json(const std::string& path);
        network_result_t handle_response(int http_status, const std::string& response_body);
        std::string base_url_;
    };

    // Deterministic, non-secret machine fingerprint. Combines the Windows
    // product id (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid), the C:
    // drive volume serial, the primary MAC address and the computer name,
    // then hashes the lot with BCrypt (SHA-256) and returns a lowercase hex
    // string. Nothing here is a secret and the result is stable per machine.
    std::string compute_hwid();

    // Persisted session token + its server-declared expiry, stored as a small
    // JSON file under the user's Local AppData folder (CSIDL_LOCAL_APPDATA)
    // alongside the project name. Only the token and its expiry are written;
    // never the license key or any secret.
    std::string load_session_token();
    void save_session_token(const std::string& token);

} // namespace license
