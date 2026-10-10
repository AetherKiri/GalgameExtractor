// sniffer.h — port of src/sniffer.zig.
//
// Magic-byte sniffing with three detection layers:
//   1. magic bytes at offset 0 (plain archives)
//   2. EOCD tail scan (zip appended to a carrier — "steg" archives such as
//      mp4/png/gif files that carry a zip payload)
//   3. sliding-window scan over the first 64 MiB (disguised carriers)

#pragma once

#include "hrd_internal.h"

#include <string>
#include <vector>

namespace hrd {

struct SniffResult {
    Format fmt = Format::none;
    uint64_t offset = 0;
    bool disguised = false;
};

// Collect all plausible archive candidates, ordered by confidence:
// magic@0 first, then EOCD-detected zip, then sliding-window hits (the
// earliest hit per format).
std::vector<SniffResult> SniffFileAll(const std::string &path);

// First (highest-confidence) candidate, or none.
bool SniffFile(const std::string &path, SniffResult &out);

// Materialize bytes [offset, EOF) of src into dst_dir/tag. Returns false on
// I/O failure. `out` receives the created file path.
bool SliceToFile(const std::string &src, uint64_t offset,
                 const std::string &dst_dir, const std::string &tag,
                 std::string &out);

}  // namespace hrd
