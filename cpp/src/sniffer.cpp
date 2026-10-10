// sniffer.cpp — port of src/sniffer.zig.

#include "sniffer.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>

namespace hrd {
namespace {

namespace fs = std::filesystem;

struct Signature {
    const char *sig;
    size_t len;
    Format fmt;
};

// Sorted longest-first for correct matching (see sniffer.zig).
constexpr Signature kSignatures[] = {
    {"Rar!\x1A\x07\x01\x00", 8, Format::rar5},
    {"Rar!\x1A\x07\x00", 7, Format::rar4},
    {"7z\xBC\xAF\x27\x1C", 6, Format::sevenz},
    {"\xFD\x37zXZ\x00", 6, Format::xz},
    {"PK\x03\x04", 4, Format::zip},
    {"MSCF", 4, Format::cab},
    {"BZh", 3, Format::bz2},
    {"\x1F\x8B", 2, Format::gz},
};

constexpr uint8_t kZipLocalSig[4] = {'P', 'K', 3, 4};
constexpr uint8_t kZipEocdSig[4] = {'P', 'K', 5, 6};

const char *kKnownNonArchive[] = {
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
    ".md", ".rst", ".html", ".css", ".js", ".ts", ".py", ".rs", ".go", ".c",
    ".cpp", ".h", ".hpp", ".java", ".rb", ".sh", ".bat", ".ps1", ".sql",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".opus",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".lib",
    ".iso", ".img", ".vmdk", ".vdi", ".qcow2",
    ".sqlite", ".db",
};

bool EqualsNoCase(const char *a, const char *b) {
#ifdef _WIN32
    return _stricmp(a, b) == 0;
#else
    return strcasecmp(a, b) == 0;
#endif
}

bool IsKnownNonArchive(const std::string &ext) {
    if (ext.empty()) return false;
    for (const char *candidate : kKnownNonArchive) {
        if (EqualsNoCase(ext.c_str(), candidate)) return true;
    }
    return false;
}

bool MatchMagic(const uint8_t *buf, size_t len, size_t pos, Format &fmt) {
    for (const Signature &sig : kSignatures) {
        if (pos + sig.len <= len &&
            std::memcmp(buf + pos, sig.sig, sig.len) == 0) {
            fmt = sig.fmt;
            return true;
        }
    }
    return false;
}

bool MatchTar(const uint8_t *buf, size_t len, size_t pos) {
    if (pos + 262 > len) return false;
    return std::memcmp(buf + pos + 257, "ustar", 5) == 0;
}

uint32_t ReadU32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool ReadAt(std::FILE *file, uint64_t pos, void *dst, size_t size) {
    if (size == 0) return true;
#ifdef _WIN32
    if (_fseeki64(file, static_cast<int64_t>(pos), SEEK_SET) != 0) return false;
#else
    if (fseeko(file, static_cast<off_t>(pos), SEEK_SET) != 0) return false;
#endif
    return std::fread(dst, 1, size, file) == size;
}

}  // namespace

std::vector<SniffResult> SniffFileAll(const std::string &path) {
    std::vector<SniffResult> list;
    std::FILE *file =
        std::fopen(path.c_str(), "rb");  // NOLINT(cert-33.112) — needed by
                                         // POSIX fopen; the path is host data.
    if (file == nullptr) return list;

    std::error_code ec;
    const uint64_t size = fs::file_size(fs::u8path(path), ec);
    if (ec || size == 0) {
        std::fclose(file);
        return list;
    }

    // Fast path: check extension to skip non-archive files entirely.
    const fs::path raw_path = fs::u8path(path);
    std::string ext = raw_path.extension().u8string();
    if (!ext.empty() && IsKnownNonArchive(ext)) {
        std::fclose(file);
        return list;
    }

    // Read head (8 KiB) — check magic at offset 0.
    std::array<uint8_t, 8192> head{};
    const size_t head_n = ReadAt(file, 0, head.data(), head.size())
                              ? head.size()
                              : 0;
    if (head_n >= 2) {
        Format fmt = Format::none;
        if (MatchMagic(head.data(), head_n, 0, fmt)) {
            list.push_back(SniffResult{fmt, 0, false});
            std::fclose(file);
            return list;  // strongest signal, no need for more
        }
        if (MatchTar(head.data(), head_n, 0)) {
            list.push_back(SniffResult{Format::tar, 0, false});
            std::fclose(file);
            return list;
        }
    }

    // EOCD tail scan (ZIP self-locating for steg / prepended data). The
    // comment field may legitimately be huge (steg wrappers declare the
    // carrier media as the zip comment), so a strict comment-length check
    // would reject valid steg archives; validate by signature instead.
    if (size >= 22) {
        const uint64_t tail_sz = std::min<uint64_t>(size, (1 << 16) + 22);
        std::vector<uint8_t> tail(static_cast<size_t>(tail_sz));
        if (ReadAt(file, size - tail_sz, tail.data(), tail.size())) {
            const uint64_t tail_base = size - tail_sz;
            for (size_t ui = tail.size() >= 22 ? tail.size() - 22 : 0;;
                 --ui) {
                if (std::memcmp(tail.data() + ui, kZipEocdSig, 4) == 0) {
                    const uint32_t cd_size = ReadU32(tail.data() + ui + 12);
                    const uint32_t cd_off = ReadU32(tail.data() + ui + 16);
                    const uint64_t eocd_abs = tail_base + ui;
                    // Candidate 1: classic layout — archive starts at
                    // (eocd - cd_size - cd_off).
                    if (static_cast<uint64_t>(cd_off) + cd_size <= eocd_abs) {
                        const uint64_t arc_start =
                            eocd_abs - cd_size - cd_off;
                        if (arc_start < size) {
                            uint8_t sig[4];
                            if (ReadAt(file, arc_start, sig, sizeof(sig)) &&
                                std::memcmp(sig, kZipLocalSig, 4) == 0) {
                                list.push_back(SniffResult{
                                    Format::zip, arc_start,
                                    arc_start != 0});
                                break;
                            }
                        }
                    }
                    // Candidate 2: steg wrapper — treat the whole file as
                    // the zip and let the zip handler locate the central
                    // directory itself.
                    uint8_t sig2[4];
                    if (ReadAt(file, cd_off, sig2, sizeof(sig2)) &&
                        std::memcmp(sig2, kZipLocalSig, 4) == 0) {
                        list.push_back(
                            SniffResult{Format::zip, cd_off, cd_off != 0});
                        break;
                    }
                    // Candidate 3: prefix-carrier zip (offset unknown) —
                    // hand the whole file to the zip handler, which walks
                    // the EOCD itself.
                    list.push_back(SniffResult{Format::zip, 0, false});
                    break;
                }
                if (ui == 0) break;
            }
        }
    }

    // Sliding window scan (for disguised files). 4 MiB chunks with 8-byte
    // overlap for signature boundary crossing; collect the earliest hit per
    // format. Weak 2-3 byte signatures (gz/bz2) that collide with media data
    // are only accepted near the file head.
    {
        constexpr size_t kChunk = 4u << 20;
        const uint64_t scan_limit = std::min<uint64_t>(size, 64u << 20);
        std::vector<uint8_t> buf(kChunk + 8);
        uint64_t pos = 0;
        size_t carry = 0;
        std::array<bool, 10> seen_fmt{};
        while (pos < scan_limit) {
            const size_t want = static_cast<size_t>(
                std::min<uint64_t>(kChunk, scan_limit - pos));
            if (!ReadAt(file, pos, buf.data() + carry, want)) break;
            const size_t n = want;
            const size_t valid = carry + n;
            if (valid < 2) break;
            for (size_t i = 0; i + 2 <= valid; ++i) {
                const uint64_t abs = pos + i - carry;
                Format fmt = Format::none;
                if (MatchMagic(buf.data(), valid, i, fmt)) {
                    const auto slot = static_cast<size_t>(fmt);
                    if (slot < seen_fmt.size() && !seen_fmt[slot]) {
                        const bool weak =
                            fmt == Format::gz || fmt == Format::bz2;
                        if (!weak || abs < (1u << 20)) {
                            seen_fmt[slot] = true;
                            list.push_back(
                                SniffResult{fmt, abs, abs != 0});
                        }
                    }
                    if (list.size() >= 8) goto scan_done;
                    continue;
                }
                if (MatchTar(buf.data(), valid, i)) {
                    const auto slot = static_cast<size_t>(Format::tar);
                    if (slot < seen_fmt.size() && !seen_fmt[slot]) {
                        seen_fmt[slot] = true;
                        list.push_back(SniffResult{Format::tar, abs, abs != 0});
                    }
                    if (list.size() >= 8) goto scan_done;
                }
            }
            carry = std::min<size_t>(8, valid);
            std::memmove(buf.data(), buf.data() + valid - carry, carry);
            pos += n;
        }
    }
scan_done:
    std::fclose(file);
    return list;
}

bool SniffFile(const std::string &path, SniffResult &out) {
    const std::vector<SniffResult> candidates = SniffFileAll(path);
    if (candidates.empty()) return false;
    out = candidates.front();
    return true;
}

bool SliceToFile(const std::string &src, uint64_t offset,
                 const std::string &dst_dir, const std::string &tag,
                 std::string &out) {
    std::FILE *in = std::fopen(src.c_str(), "rb");
    if (in == nullptr) return false;
    std::error_code ec;
    fs::create_directories(fs::u8path(dst_dir), ec);
    out = (fs::u8path(dst_dir) / fs::u8path(tag)).u8string();
    std::FILE *dst = std::fopen(out.c_str(), "wb");
    if (dst == nullptr) {
        std::fclose(in);
        return false;
    }
    constexpr size_t kBuffer = 1u << 23;  // 8 MiB streaming buffer
    std::vector<uint8_t> buffer(kBuffer);
    bool ok = true;
#ifdef _WIN32
    if (_fseeki64(in, static_cast<int64_t>(offset), SEEK_SET) != 0) ok = false;
#else
    if (fseeko(in, static_cast<off_t>(offset), SEEK_SET) != 0) ok = false;
#endif
    while (ok) {
        const size_t n = std::fread(buffer.data(), 1, buffer.size(), in);
        if (n == 0) break;
        if (std::fwrite(buffer.data(), 1, n, dst) != n) ok = false;
    }
    ok = ok && std::ferror(in) == 0;
    std::fclose(in);
    if (std::fclose(dst) != 0) ok = false;
    if (!ok) {
        std::error_code remove_ec;
        fs::remove(fs::u8path(out), remove_ec);
    }
    return ok;
}

}  // namespace hrd
