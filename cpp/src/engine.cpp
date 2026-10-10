// engine.cpp — port of src/engine.zig.

#include "engine.h"

#include "sniffer.h"
#include "volumes.h"

// The public C ABI status codes (include/hrd.h) are reused as internal
// engine error codes.
#include "hrd.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <set>
#include <system_error>

namespace hrd {
namespace {

namespace fs = std::filesystem;

std::string Basename(const std::string &path) {
    const size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string Dirname(const std::string &path) {
    const size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

fs::path Join(const std::string &a, const std::string &b) {
    return fs::u8path(a) / fs::u8path(b);
}

std::string JoinUtf8(const std::string &a, const std::string &b) {
    return Join(a, b).u8string();
}

// True when the file name ends with ".NNN" (3 decimal digits) — numeric
// split marker.
bool EndsWithNumericSplit(const std::string &name) {
    if (name.size() < 4 || name[name.size() - 4] != '.') return false;
    for (size_t i = name.size() - 3; i < name.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(name[i]))) return false;
    }
    return true;
}

// Extension mapping for the 7-Zip handler lookup. Rar (v4) and Rar5 share
// the "rar" extension — the handler Name disambiguates.
const char *HandlerExt(Format fmt) {
    switch (fmt) {
        case Format::zip: return "zip";
        case Format::rar4:
        case Format::rar5: return "rar";
        case Format::sevenz: return "7z";
        case Format::gz: return "gz";
        case Format::bz2: return "bz2";
        case Format::xz: return "xz";
        case Format::tar: return "tar";
        case Format::cab: return "cab";
        default: return nullptr;
    }
}

const char *HandlerName(Format fmt) {
    switch (fmt) {
        case Format::rar4: return "Rar";
        case Format::rar5: return "Rar5";
        default: return nullptr;
    }
}

bool CopyFileBytes(const std::string &src, const std::string &dst,
                   uint64_t *out_size) {
    std::FILE *in = std::fopen(src.c_str(), "rb");
    if (in == nullptr) return false;
    std::FILE *out = std::fopen(dst.c_str(), "wb");
    if (out == nullptr) {
        std::fclose(in);
        return false;
    }
    std::vector<char> buffer(1u << 23);  // 8 MiB
    uint64_t total = 0;
    bool ok = true;
    while (ok) {
        const size_t n = std::fread(buffer.data(), 1, buffer.size(), in);
        if (n == 0) break;
        if (std::fwrite(buffer.data(), 1, n, out) != n) ok = false;
        total += n;
    }
    ok = ok && std::ferror(in) == 0;
    std::fclose(in);
    if (std::fclose(out) != 0) ok = false;
    if (out_size != nullptr) *out_size = total;
    return ok;
}

bool RemoveTree(const std::string &path) {
    std::error_code ec;
    fs::remove_all(fs::u8path(path), ec);
    return !ec;
}

}  // namespace

Engine::Engine(const EngineOptions &options) : options_(options) {
    book_.LoadDefaultDb(options_.password_db);
}

Engine::~Engine() = default;

void Engine::SetCallbacks(NeedPasswordFn need_password, EventFn event) {
    need_password_ = std::move(need_password);
    event_ = std::move(event);
}

void Engine::Emit(Event event, const char *path, uint32_t depth, Format fmt,
                  uint64_t aux) {
    if (!event_) return;
    EventInfo info;
    info.event = event;
    info.path = path;
    info.depth = depth;
    info.fmt = fmt;
    info.aux = aux;
    event_(info);
}

int Engine::Process(const std::vector<std::string> &inputs,
                    const std::string &out_dir) {
    // Expand directories to their contents (walk non-recursively:
    // first-level files).
    std::vector<std::string> all_files;
    for (const std::string &input : inputs) {
        std::error_code ec;
        if (fs::is_directory(fs::u8path(input), ec)) {
            for (const fs::directory_entry &entry :
                 fs::recursive_directory_iterator(fs::u8path(input), ec)) {
                if (ec) break;
                if (entry.is_regular_file(ec)) {
                    all_files.push_back(entry.path().u8string());
                }
            }
        } else {
            all_files.push_back(input);
        }
    }

    // Module 1: volume aggregation.
    GroupResult groups = GroupVolumes(all_files);
    std::set<std::string> processed_paths;

    std::error_code ec;
    fs::create_directories(fs::u8path(out_dir), ec);

    int first_error = 0;

    // Process groups first.
    for (const Group &group : groups.groups) {
        Emit(Event::grouped, group.display.c_str(), 0, Format::none,
             group.deps.size());
        // Only process if not already handled as part of another group.
        if (processed_paths.count(group.entry) != 0) continue;
        const int status = ProcessEntry(group.entry, out_dir, 0,
                                        processed_paths, group.deps);
        if (status != 0 && first_error == 0) first_error = status;
        for (const std::string &dep : group.deps) {
            processed_paths.insert(dep);
        }
    }

    // Process singles.
    for (const std::string &single : groups.singles) {
        if (processed_paths.count(single) != 0) continue;
        const int status = ProcessEntry(single, out_dir, 0, processed_paths,
                                        std::vector<std::string>());
        if (status != 0 && first_error == 0) first_error = status;
    }

    return first_error;
}

int Engine::ProcessEntry(const std::string &path, const std::string &out_dir,
                         uint32_t depth,
                         std::set<std::string> &processed,
                         const std::vector<std::string> &vol_deps) {
    if (depth >= options_.max_depth) {
        Emit(Event::circuit, path.c_str(), depth, Format::none,
             options_.max_depth);
        return 0;
    }
    if (processed.count(path) != 0) {
        return 0;
    }
    processed.insert(path);

    // Password hints travel with the download surprisingly often. Load them
    // before probing this entry so README/NFO/TXT files beside a volume are
    // part of the same unified password-book pipeline.
    book_.GatherContext(path);

    // Module 2: sniff the real carrier — collect all plausible candidates.
    const std::vector<SniffResult> candidates = SniffFileAll(path);
    if (candidates.empty()) {
        // Not an archive at all — deliver as-is.
        report_.kept += 1;
        Emit(Event::kept, path.c_str(), depth, Format::none, 0);
        if (!DeliverFile(path, out_dir)) {
            report_.errors += 1;
            return HRD_ERR_IO;
        }
        return 0;
    }

    std::string current_password;
    ProbeResult probe_result;
    bool probe_valid = false;
    Format chosen_fmt = Format::none;
    std::string chosen_actual = path;
    BackendGuid chosen_clsid;
    bool has_clsid = false;
    std::string volcat_path;
    ArchiveHandle *opened = nullptr;
    // Set when a candidate asked for a password while opening (encrypted
    // headers) and no candidate password worked — reported as ENCRYPTED so
    // the host can prompt instead of silently keeping the archive as-is.
    bool password_blocked = false;

    // Try every sniff candidate until one opens as a valid archive. Deliver
    // nothing until an archive is positively identified.
    for (const SniffResult &candidate : candidates) {
        Emit(Event::sniffed, path.c_str(), depth, candidate.fmt,
             candidate.offset);

        // Materialize a disguised carrier if needed.
        std::string actual_path = path;
        bool owns_actual = false;
        if (candidate.disguised) {
            std::string stripped;
            if (!SliceToFile(path, candidate.offset, out_dir, "_stripped_",
                             stripped)) {
                continue;
            }
            actual_path = stripped;
            owns_actual = true;
        }

        // Multi-volume: numeric split archives (.7z.001/.001) cannot be
        // opened by the 7z handler directly — concatenate volumes into one
        // temp file.
        if (!vol_deps.empty() && EndsWithNumericSplit(Basename(path))) {
            if (volcat_path.empty()) {
                std::string concatenated;
                if (ConcatVolumes(path, vol_deps, out_dir, concatenated)) {
                    volcat_path = concatenated;
                }
            }
            if (!volcat_path.empty()) {
                if (owns_actual) {
                    std::error_code ec;
                    fs::remove(fs::u8path(actual_path), ec);
                    owns_actual = false;
                }
                actual_path = volcat_path;
            }
        }

        // Map format to 7z handler.
        const char *ext_str = HandlerExt(candidate.fmt);
        const char *sig_str = HandlerName(candidate.fmt);
        BackendGuid clsid;
        if (ext_str == nullptr ||
            !FindHandlerSig(ext_str, sig_str != nullptr ? sig_str : "",
                            clsid)) {
            if (owns_actual) {
                std::error_code ec;
                fs::remove(fs::u8path(actual_path), ec);
            }
            continue;
        }

        Emit(Event::probe, path.c_str(), depth, candidate.fmt,
             candidate.offset);

        // Probe without a password first; if the archive has encrypted
        // headers (e.g. 7z -mhe=on) the open itself fails, so retry with
        // password-book candidates.
        bool pw_requested = false;
        ArchiveHandle *probe_handle =
            OpenArchive(actual_path, clsid, vol_deps, "", &pw_requested);
        if (probe_handle == nullptr) {
            for (const std::string &candidate_password : book_.candidates()) {
                probe_handle = OpenArchive(actual_path, clsid, vol_deps,
                                           candidate_password);
                if (probe_handle != nullptr) {
                    current_password = candidate_password;
                    report_.passwords_used += 1;
                    break;
                }
            }
        }

        if (probe_handle == nullptr) {
            // If the archive is not covered by the local book, give the host
            // one interactive opportunity.
            if (options_.interactive && need_password_) {
                std::string entered;
                if (need_password_(path, entered)) {
                    probe_handle = OpenArchive(actual_path, clsid, vol_deps,
                                               entered);
                    if (probe_handle != nullptr) {
                        book_.Learn(entered);
                        current_password = book_.candidates().back();
                        report_.passwords_used += 1;
                    }
                }
            }
            if (probe_handle == nullptr) {
                if (pw_requested) password_blocked = true;
                // This candidate is not a valid archive — try the next sniff
                // hit.
                if (owns_actual) {
                    std::error_code ec;
                    fs::remove(fs::u8path(actual_path), ec);
                }
                continue;
            }
        }

        probe_result = ListEntries(probe_handle);
        probe_valid = true;
        chosen_fmt = candidate.fmt;
        chosen_actual = actual_path;
        chosen_clsid = clsid;
        has_clsid = true;
        owns_actual = false;  // transferred to chosen_actual lifecycle
        opened = probe_handle;
        break;
    }

    if (!probe_valid) {
        // Every candidate exhausted — keep the original file as-is.
        report_.kept += 1;
        Emit(Event::kept, path.c_str(), depth, Format::none, 0);
        if (!DeliverFile(path, out_dir)) {
            report_.errors += 1;
            return HRD_ERR_ARCHIVE;
        }
        report_.errors += 1;
        if (password_blocked) {
            // Encrypted headers with no working password: tell the host so
            // it can prompt and retry instead of treating the carrier as a
            // plain file.
            return HRD_ERR_ENCRYPTED;
        }
        return 0;
    }

    // Re-open with the working password if the first probe opened without
    // one but entries are encrypted (Zip-style: readable headers,
    // encrypted content).
    const bool needs_pass = probe_result.any_encrypted || !current_password.empty();

    // Module 4: extract.
    Emit(Event::extracting, path.c_str(), depth, chosen_fmt, 0);

    const std::string depth_dir =
        JoinUtf8(out_dir, "_" + std::to_string(depth) + "_" + Basename(path));
    std::error_code ec;
    fs::create_directories(fs::u8path(depth_dir), ec);

    // Extract. The byte budget is an independent circuit breaker: 0 disables
    // it (the ratio limit is enforced by the same budget at a higher level).
    const uint64_t bomb_limit = options_.max_total_bytes;

    int status = 0;
    bool verified_extract = false;
    if (needs_pass && current_password.empty()) {
        if (probe_result.any_encrypted) {
            // Zip-style: headers readable but entries encrypted — the only
            // sound check is a real extraction attempt (wrong password →
            // CRC error). A successful attempt leaves the content
            // extracted; skip re-extract.
            for (const std::string &candidate : book_.candidates()) {
                CloseArchive(opened);
                opened = OpenArchive(chosen_actual, chosen_clsid, vol_deps,
                                     candidate);
                if (opened == nullptr) continue;
                const ExtractOutcome outcome =
                    ExtractAll(opened, depth_dir, bomb_limit, candidate);
                if (!outcome.wrong_password && !outcome.data_error &&
                    !outcome.bomb_tripped) {
                    current_password = candidate;
                    verified_extract = true;
                    report_.passwords_used += 1;
                    report_.archives += 1;
                    Emit(Event::extracted, path.c_str(), depth, chosen_fmt, 0);
                    break;
                }
                // Wipe partial output of the wrong-password attempt.
                RemoveTree(depth_dir);
                fs::create_directories(fs::u8path(depth_dir), ec);
            }
        } else {
            // rar5-style: encrypted headers — the probe itself validates the
            // password (block CRC), so retry the probe with book candidates.
            for (const std::string &candidate : book_.candidates()) {
                ArchiveHandle *retry = OpenArchive(chosen_actual, chosen_clsid,
                                                   vol_deps, candidate);
                if (retry != nullptr) {
                    CloseArchive(opened);
                    opened = retry;
                    current_password = candidate;
                    report_.passwords_used += 1;
                    probe_result = ListEntries(opened);
                    break;
                }
            }
        }
        if (current_password.empty()) {
            CloseArchive(opened);
            report_.errors += 1;
            RemoveTree(depth_dir);
            return HRD_ERR_ENCRYPTED;
        }
        if (verified_extract) {
            status = 0;
        }
    }

    if (!verified_extract) {
        if (opened == nullptr && has_clsid) {
            opened = OpenArchive(chosen_actual, chosen_clsid, vol_deps,
                                 current_password);
        }
        if (opened == nullptr) {
            report_.errors += 1;
            RemoveTree(depth_dir);
            return HRD_ERR_ARCHIVE;
        }
        const ExtractOutcome outcome =
            ExtractAll(opened, depth_dir, bomb_limit, current_password);
        if (outcome.bomb_tripped) {
            report_.errors += 1;
            CloseArchive(opened);
            RemoveTree(depth_dir);
            return HRD_ERR_BOMB;
        }
        if (outcome.wrong_password) {
            report_.errors += 1;
            CloseArchive(opened);
            RemoveTree(depth_dir);
            return HRD_ERR_PASSWORD;
        }
        if (outcome.data_error) {
            report_.errors += 1;
        }
        CloseArchive(opened);
        opened = nullptr;
        report_.archives += 1;
        Emit(Event::extracted, path.c_str(), depth, chosen_fmt, 0);
    } else {
        CloseArchive(opened);
        opened = nullptr;
    }

    // Module 4b: recursive scan of extracted contents.
    {
        std::error_code walk_ec;
        for (const fs::directory_entry &entry :
             fs::recursive_directory_iterator(fs::u8path(depth_dir), walk_ec)) {
            if (walk_ec) break;
            if (!entry.is_regular_file(walk_ec)) continue;
            const int child_status = ProcessEntry(entry.path().u8string(),
                                                  out_dir, depth + 1,
                                                  processed,
                                                  std::vector<std::string>());
            if (child_status != 0 && status == 0) status = child_status;
        }
    }

    // Module 5: cleanup temp stripped files & deliver final non-archive
    // files.
    if (!DeliverTree(depth_dir, out_dir)) {
        if (status == 0) status = HRD_ERR_IO;
    }
    RemoveTree(depth_dir);

    // The stripped/volcat temp carrier is not needed after extraction.
    if (chosen_actual != path) {
        std::error_code remove_ec;
        fs::remove(fs::u8path(chosen_actual), remove_ec);
    }
    if (!volcat_path.empty() && volcat_path != chosen_actual) {
        std::error_code remove_ec;
        fs::remove(fs::u8path(volcat_path), remove_ec);
    }
    return status;
}

bool Engine::ConcatVolumes(const std::string &first,
                           const std::vector<std::string> &rest,
                           const std::string &out_dir, std::string &out_path) {
    const std::string name = Basename(first);
    // Strip the trailing ".NNN".
    const std::string stem = name.size() > 4 ? name.substr(0, name.size() - 4)
                                             : name;
    out_path = JoinUtf8(out_dir, "_volcat_" + stem);
    std::FILE *out = std::fopen(out_path.c_str(), "wb");
    if (out == nullptr) return false;
    std::vector<char> buffer(1u << 20);
    bool ok = true;
    std::vector<std::string> all;
    all.push_back(first);
    all.insert(all.end(), rest.begin(), rest.end());
    for (const std::string &volume : all) {
        std::FILE *in = std::fopen(volume.c_str(), "rb");
        if (in == nullptr) {
            ok = false;
            break;
        }
        while (ok) {
            const size_t n = std::fread(buffer.data(), 1, buffer.size(), in);
            if (n == 0) break;
            if (std::fwrite(buffer.data(), 1, n, out) != n) ok = false;
        }
        ok = ok && std::ferror(in) == 0;
        std::fclose(in);
        if (!ok) break;
    }
    if (std::fclose(out) != 0) ok = false;
    if (!ok) {
        std::error_code ec;
        fs::remove(fs::u8path(out_path), ec);
        out_path.clear();
    }
    return ok;
}

bool Engine::DeliverFile(const std::string &src, const std::string &out_dir) {
    const std::string dest = JoinUtf8(out_dir, Basename(src));
    std::error_code ec;
    fs::create_directories(fs::u8path(out_dir), ec);
    uint64_t size = 0;
    if (!CopyFileBytes(src, dest, &size)) return false;
    report_.delivered_files += 1;
    report_.delivered_bytes += size;
    Emit(Event::delivered, dest.c_str(), 0, Format::none, size);
    return true;
}

bool Engine::DeliverTree(const std::string &src_dir,
                         const std::string &out_dir) {
    std::error_code walk_ec;
    fs::recursive_directory_iterator it(fs::u8path(src_dir), walk_ec);
    if (walk_ec) return false;
    bool all_ok = true;
    for (const fs::directory_entry &entry : it) {
        if (walk_ec) break;
        if (!entry.is_regular_file(walk_ec)) continue;
        const std::string child = entry.path().u8string();
        // Check if it's an archive — those were handled by recursion.
        SniffResult sniffed;
        if (SniffFile(child, sniffed) && sniffed.fmt != Format::none) {
            continue;
        }
        const std::string relative =
            fs::relative(entry.path(), fs::u8path(src_dir)).u8string();
        const std::string dest = JoinUtf8(out_dir, relative);
        std::error_code ec;
        fs::create_directories(fs::u8path(Dirname(dest)), ec);
        uint64_t size = 0;
        if (CopyFileBytes(child, dest, &size)) {
            report_.delivered_files += 1;
            report_.delivered_bytes += size;
            Emit(Event::delivered, dest.c_str(), 0, Format::none, size);
        } else {
            all_ok = false;
        }
    }
    return all_ok;
}

}  // namespace hrd
