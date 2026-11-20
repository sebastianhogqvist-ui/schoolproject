#pragma once
#include "license_core.hpp"
#ifdef _WIN32
#include "license_win.hpp"
#endif
namespace license {
inline constexpr bool kLicenseWindowsEnabled = true;
}
