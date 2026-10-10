// hrd_internal.h — shared internal types for the C++ host engine.
//
// This is a faithful C++ port of the Zig engine pipeline (src/*.zig):
// types.zig, sniffer.zig, volumes.zig, password.zig, engine.zig. The 7-Zip
// backend is implemented against the 7-Zip SDK (ip7z/7zip CPP sources)
// compiled by the embedding project — through the vcpkg "7zip" port or the
// bundled cmake/AetherSevenZipSdk.cmake module. libarchive is deliberately
// not a backend.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hrd {

enum class Format : uint8_t {
    none = 0,
    zip = 1,
    rar4 = 2,
    rar5 = 3,
    sevenz = 4,
    gz = 5,
    bz2 = 6,
    xz = 7,
    tar = 8,
    cab = 9,
};

inline const char *FormatName(Format fmt) {
    switch (fmt) {
        case Format::zip: return "zip";
        case Format::rar4: return "rar4";
        case Format::rar5: return "rar5";
        case Format::sevenz: return "sevenz";
        case Format::gz: return "gz";
        case Format::bz2: return "bz2";
        case Format::xz: return "xz";
        case Format::tar: return "tar";
        case Format::cab: return "cab";
        default: return "none";
    }
}

enum class Event : uint8_t {
    grouped = 1,
    sniffed = 2,
    probe = 3,
    extracting = 4,
    extracted = 5,
    delivered = 6,
    kept = 7,
    circuit = 8,
};

struct EventInfo {
    Event event;
    const char *path;
    uint32_t depth;
    Format fmt;
    uint64_t aux;
};

struct Report {
    uint64_t processed = 0;
    uint64_t archives = 0;
    uint64_t kept = 0;
    uint64_t delivered_files = 0;
    uint64_t delivered_bytes = 0;
    uint64_t errors = 0;
    uint64_t passwords_used = 0;
};

}  // namespace hrd
