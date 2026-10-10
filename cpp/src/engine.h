// engine.h — port of src/engine.zig (Engine struct).

#pragma once

#include "hrd_internal.h"
#include "password.h"
#include "sevenzip_backend.h"

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace hrd {

struct EngineOptions {
    uint32_t max_depth = 8;
    uint32_t max_ratio = 100;  // 0 disables
    uint64_t max_total_bytes = 32ull << 30;  // 0 disables
    bool flatten = false;
    bool overwrite = false;
    bool interactive = true;
    std::string password_db;
    std::string temp_dir;
};

using NeedPasswordFn = std::function<bool(
    const std::string &archive_path, std::string &out_password)>;
using EventFn = std::function<void(const EventInfo &info)>;

class Engine {
public:
    explicit Engine(const EngineOptions &options);
    ~Engine();

    void SetCallbacks(NeedPasswordFn need_password, EventFn event);

    PasswordBook &book() { return book_; }
    Report &report() { return report_; }

    // Process files/directories (directories are walked). Returns the first
    // error, or 0 on success. `out_dir` is created if needed.
    int Process(const std::vector<std::string> &inputs,
                const std::string &out_dir);

    // Process one file (recursion entry). Returns the first error status
    // for this entry, or 0.
    int ProcessEntry(const std::string &path, const std::string &out_dir,
                     uint32_t depth, std::set<std::string> &processed,
                     const std::vector<std::string> &vol_deps);

    // Concatenate all volumes of a split archive into a single temp file.
    // Returns false on I/O failure.
    bool ConcatVolumes(const std::string &first,
                       const std::vector<std::string> &rest,
                       const std::string &out_dir, std::string &out_path);

    // Deliver a plain file as-is into out_dir.
    bool DeliverFile(const std::string &src, const std::string &out_dir);

    // Deliver every non-archive file below src_dir into out_dir.
    bool DeliverTree(const std::string &src_dir, const std::string &out_dir);

private:
    void Emit(Event event, const char *path, uint32_t depth, Format fmt,
              uint64_t aux);

    EngineOptions options_;
    PasswordBook book_;
    Report report_;
    NeedPasswordFn need_password_;
    EventFn event_;
};

}  // namespace hrd
