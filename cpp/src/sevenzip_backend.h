// sevenzip_backend.h — the cross-platform 7-Zip SDK backend.
//
// This replaces the Zig ffi_bridge.zig/sevenzip_com.zig pair (which loaded
// 7z.dll / lib7z.so at runtime) with a direct static link against the 7-Zip
// SDK compiled by the embedding project (vcpkg "7zip" port or the bundled
// AetherSevenZipSdk.cmake module). libarchive is intentionally not used.

#pragma once

#include "hrd_internal.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hrd {

struct ProbeEntry {
    uint32_t index = 0;
    std::string path;
    bool is_dir = false;
    uint64_t size = 0;
    bool encrypted = false;
};

struct ProbeResult {
    std::vector<ProbeEntry> entries;
    bool any_encrypted = false;
};

struct ExtractOutcome {
    uint64_t files = 0;
    uint64_t bytes = 0;
    bool wrong_password = false;
    bool data_error = false;
    bool bomb_tripped = false;
};

struct ArchiveHandle;
struct BackendGuid;

// Find a handler CLSID by extension. When sig_want is non-empty, the
// handler's Name property must match it (used to disambiguate the Rar (v4)
// vs Rar5 handlers, which share the "rar" extension).
bool FindHandlerSig(const std::string &ext_want, const std::string &sig_want,
                    BackendGuid &out_clsid);

// Open an archive. `volumes` lists the sibling volumes of a multi-volume
// set; they are served to the handler through the open callback. `password`
// may be empty. `password_requested` (optional) receives whether the handler
// asked for a password while opening (encrypted-header archives such as
// 7z -mhe do that before the open can succeed). Returns nullptr when the
// archive cannot be opened (wrong format, wrong password on encrypted
// headers, or I/O failure).
ArchiveHandle *OpenArchive(const std::string &path, const BackendGuid &clsid,
                           const std::vector<std::string> &volumes,
                           const std::string &password,
                           bool *password_requested = nullptr);
void CloseArchive(ArchiveHandle *handle);

ProbeResult ListEntries(ArchiveHandle *handle);

// Extract every entry into out_dir. `bomb_limit` (0 = disabled) caps the
// total bytes written across the whole extraction. Entry paths are
// sanitized (zip-slip guard) before files are created.
ExtractOutcome ExtractAll(ArchiveHandle *handle, const std::string &out_dir,
                           uint64_t bomb_limit, const std::string &password);

}  // namespace hrd
