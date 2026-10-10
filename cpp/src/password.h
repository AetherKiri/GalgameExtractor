// password.h — port of src/password.zig.

#pragma once

#include "hrd_internal.h"

#include <string>
#include <vector>

namespace hrd {

class PasswordBook {
public:
    // Load the user-supplied DB (or the default file when empty) plus the
    // built-in common-password list. Extra DBs never replace the defaults.
    void LoadDefaultDb(const std::string &extra_db);

    // Harvest password candidates from hint files (README/NFO/TXT/etc.)
    // placed next to the archive.
    void GatherContext(const std::string &archive_path);

    // Learn a new password: highest priority + persistent in the DB file.
    void Learn(const std::string &password);

    const std::vector<std::string> &candidates() const { return candidates_; }
    uint64_t used_count() const { return used_count_; }

private:
    void Push(const std::string &password);
    void DedupeInPlace();
    void TokensFromText(const std::string &text);

    std::vector<std::string> candidates_;
    std::vector<std::string> seen_;
    std::string db_path_;
    uint64_t used_count_ = 0;
};

}  // namespace hrd
