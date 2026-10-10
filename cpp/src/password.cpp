// password.cpp — port of src/password.zig.

#include "password.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>

namespace hrd {
namespace {

namespace fs = std::filesystem;

bool EqualsNoCase(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool EndsWithNoCase(const std::string &s, const std::string &suffix) {
    if (s.size() < suffix.size()) return false;
    return EqualsNoCase(s.substr(s.size() - suffix.size()), suffix);
}

bool IndexOfNoCase(const std::string &haystack, const std::string &needle,
                   size_t &out) {
    if (needle.empty()) {
        out = 0;
        return true;
    }
    if (haystack.size() < needle.size()) return false;
    const size_t last = haystack.size() - needle.size();
    for (size_t i = 0; i <= last; ++i) {
        if (EqualsNoCase(haystack.substr(i, needle.size()), needle)) {
            out = i;
            return true;
        }
    }
    return false;
}

std::string Dirname(const std::string &path) {
    const size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

bool IsTrimPunct(char c) {
    switch (c) {
        case '.': case ',': case ';': case ':': case '!': case '?':
        case '"': case '\'': case '`': case ')': case '(': case '[':
        case ']': case '{': case '}': case '<': case '>': case '*':
        case '#':
            return true;
        default:
            return false;
    }
}

std::string ReadTextFile(const std::string &path, size_t max_bytes) {
    std::FILE *file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) return "";
    std::string data;
    data.resize(max_bytes);
    const size_t n = std::fread(data.data(), 1, max_bytes, file);
    std::fclose(file);
    data.resize(n);
    return data;
}

}  // namespace

void PasswordBook::Push(const std::string &password) {
    if (password.empty() || password.size() > 256) return;
    if (std::find(seen_.begin(), seen_.end(), password) != seen_.end()) return;
    seen_.push_back(password);
    candidates_.push_back(password);
}

void PasswordBook::LoadDefaultDb(const std::string &extra_db) {
    const char *default_name = "hrd_passwords.txt";
    const std::string primary = extra_db.empty() ? default_name : extra_db;
    std::string data = ReadTextFile(primary, 1u << 20);
    if (!data.empty()) {
        size_t start = 0;
        while (start <= data.size()) {
            const size_t end = data.find('\n', start);
            const std::string line = data.substr(
                start, end == std::string::npos ? std::string::npos : end - start);
            Push(line);
            if (end == std::string::npos) break;
            start = end + 1;
        }
    }
    db_path_ = primary;
    if (!extra_db.empty()) {
        data = ReadTextFile(default_name, 1u << 20);
        if (!data.empty()) {
            size_t start = 0;
            while (start <= data.size()) {
                const size_t end = data.find('\n', start);
                const std::string line = data.substr(
                    start,
                    end == std::string::npos ? std::string::npos : end - start);
                Push(line);
                if (end == std::string::npos) break;
                start = end + 1;
            }
        }
    }
    // Community/common passwords first (most likely hits, cheapest rejects).
    // Mirrors the Zig password.zig list.
    static const char *const common[] = {
        "acgs", "绮梦", "qym", "123456", "password", "12345678", "123456789",
        "12345", "qwerty", "abc123", "111111", "000000", "iloveyou"};
    for (const char *candidate : common) Push(candidate);
}

void PasswordBook::TokensFromText(const std::string &text) {
    // Separators include fullwidth CJK punctuation (matched at byte level —
    // the individual UTF-8 bytes of （）：！ etc. act as delimiters, which
    // cleanly splits ASCII tokens embedded in CJK text).
    static const std::string delims =
        " \t\r\n,;\"'`<>[](){}|"
        "\xEF\xBC\x88\xEF\xBC\x89\xEF\xBC\x9A\xEF\xBC\x8C\xEF\xBC\x81\xEF\xBC\x9F"  // （）：！？
        "\xE3\x80\x90\xE3\x80\x91\xE3\x80\x82\xE3\x80\x81\xE3\x80\x8A\xE3\x80\x8B"  // 【】。、《》
        "\xEF\xBC\x8B\xEF\xBC\x9D\xE3\x80\x9C\xEF\xBD\x9E";                          // ＋＝~～
    size_t start = 0;
    while (start < text.size()) {
        const size_t end = text.find_first_of(delims, start);
        std::string tok = text.substr(
            start, end == std::string::npos ? std::string::npos : end - start);
        while (!tok.empty() && IsTrimPunct(tok.back())) tok.pop_back();
        while (!tok.empty() && IsTrimPunct(tok.front())) tok.erase(tok.begin());
        if (!tok.empty() && tok.size() <= 128) {
            size_t at = 0;
            if (IndexOfNoCase(tok, "password", at) && tok.size() > 10) {
                const size_t colon = tok.find(':');
                if (colon != std::string::npos) {
                    const std::string rest = tok.substr(colon + 1);
                    if (!rest.empty() && rest.size() <= 128) {
                        candidates_.push_back(rest);
                    }
                }
            } else {
                candidates_.push_back(tok);
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
}

void PasswordBook::GatherContext(const std::string &archive_path) {
    std::error_code ec;
    const std::string dir_path = Dirname(archive_path);
    if (!fs::is_directory(fs::u8path(dir_path), ec)) return;
    for (const fs::directory_entry &ent :
         fs::directory_iterator(fs::u8path(dir_path), ec)) {
        if (ec) break;
        if (!ent.is_regular_file(ec)) continue;
        const std::string n = ent.path().filename().u8string();
        size_t at = 0;
        const bool looks_hint = IndexOfNoCase(n, "pass", at) ||
                                IndexOfNoCase(n, "readme", at) ||
                                n.find("密码") != std::string::npos ||
                                n.find("口令") != std::string::npos ||
                                n.find("说明") != std::string::npos ||
                                IndexOfNoCase(n, "key", at) ||
                                EndsWithNoCase(n, ".nfo") ||
                                EndsWithNoCase(n, ".txt");
        if (!looks_hint) continue;
        const std::string data = ReadTextFile(ent.path().u8string(), 1u << 20);
        if (data.empty()) continue;
        TokensFromText(data);
    }
    DedupeInPlace();
}

void PasswordBook::DedupeInPlace() {
    // seen_ holds every candidate pushed via Push(); the local set removes
    // context-harvested duplicates without deleting legit candidates.
    std::set<std::string> local_seen;
    std::vector<std::string> kept;
    kept.reserve(candidates_.size());
    for (std::string &candidate : candidates_) {
        if (candidate.empty() || candidate.size() > 256) continue;
        if (local_seen.insert(candidate).second) kept.push_back(candidate);
    }
    candidates_.swap(kept);
}

void PasswordBook::Learn(const std::string &password) {
    if (std::find(seen_.begin(), seen_.end(), password) != seen_.end()) return;
    Push(password);
    if (db_path_.empty()) return;
    std::FILE *file = std::fopen(db_path_.c_str(), "a");
    if (file == nullptr) return;
    std::fprintf(file, "%s\n", password.c_str());
    std::fclose(file);
    used_count_ += 1;
}

}  // namespace hrd
