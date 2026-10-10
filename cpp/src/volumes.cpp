// volumes.cpp — port of src/volumes.zig.

#include "volumes.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <utility>

namespace hrd {
namespace {

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

std::string Extension(const std::string &name) {
    const size_t dot = name.find_last_of('.');
    if (dot == std::string::npos || dot + 1 == name.size()) return "";
    return name.substr(dot);
}

std::string Stem(const std::string &name) {
    const size_t dot = name.find_last_of('.');
    return dot == std::string::npos ? name : name.substr(0, dot);
}

std::string ToLower(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string MakeBase(const std::string &dir, const std::string &prefix,
                     const char *tag) {
    // base key: "<dir>/<prefix>|<tag>", lowercased for case-insensitive
    // grouping across platforms.
    return ToLower(dir + "/" + prefix + "|" + tag);
}

uint32_t ParseDigits(const std::string &s) {
    uint32_t value = 0;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return 0;
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    return value;
}

}  // namespace

VolumeInfo AnalyzeVolume(const std::string &path) {
    const std::string name = Basename(path);
    const std::string dir = Dirname(path);
    const std::string ext = Extension(name);
    const std::string stem = Stem(name);

    VolumeInfo info;

    if (EndsWithNoCase(ext, ".rar")) {
        const size_t pi = stem.find(".part");
        if (pi != std::string::npos) {
            const std::string digits = stem.substr(pi + 5);
            if (!digits.empty() &&
                std::isdigit(static_cast<unsigned char>(digits[0]))) {
                info.kind = VolumeKind::rar_part;
                info.index = ParseDigits(digits);
                info.is_first = info.index == 1;
                info.base = MakeBase(dir, stem.substr(0, pi), "part.rar");
                return info;
            }
        }
        info.kind = VolumeKind::rar_old;
        info.index = 0;
        info.is_first = true;
        info.base = MakeBase(dir, stem, "rxx");
        return info;
    }
    if (ext.size() == 4 && (ext[1] == 'r' || ext[1] == 'R') &&
        std::isdigit(static_cast<unsigned char>(ext[2])) &&
        std::isdigit(static_cast<unsigned char>(ext[3]))) {
        info.kind = VolumeKind::rar_old;
        info.index = ParseDigits(ext.substr(2));
        info.is_first = false;
        info.base = MakeBase(dir, stem, "rxx");
        return info;
    }
    // 7z split: name.7z.001 — check before generic numeric.
    if (EndsWithNoCase(stem, ".7z") && ext.size() == 4 &&
        std::isdigit(static_cast<unsigned char>(ext[1]))) {
        info.kind = VolumeKind::sevenz_part;
        info.index = ParseDigits(ext.substr(1));
        info.is_first = info.index == 1;
        info.base = MakeBase(dir, stem.substr(0, stem.size() - 3), "7znnn");
        return info;
    }
    if (ext.size() == 4 && std::isdigit(static_cast<unsigned char>(ext[1])) &&
        std::isdigit(static_cast<unsigned char>(ext[2])) &&
        std::isdigit(static_cast<unsigned char>(ext[3]))) {
        // Generic numeric split (e.g. .001, .002)
        info.kind = VolumeKind::numeric;
        info.index = ParseDigits(ext.substr(1));
        info.is_first = info.index == 1;
        info.base = MakeBase(dir, stem, "nnn");
        return info;
    }
    if (ext.size() == 4 && (ext[1] == 'z' || ext[1] == 'Z') &&
        std::isdigit(static_cast<unsigned char>(ext[2])) &&
        std::isdigit(static_cast<unsigned char>(ext[3]))) {
        info.kind = VolumeKind::zip_split;
        info.index = ParseDigits(ext.substr(2));
        info.is_first = false;
        info.base = MakeBase(dir, stem, "zxx");
        return info;
    }
    if (EndsWithNoCase(ext, ".zip")) {
        info.kind = VolumeKind::zip_split;
        info.index = 999;
        info.is_first = true;
        info.base = MakeBase(dir, stem, "zxx");
        return info;
    }
    return info;
}

GroupResult GroupVolumes(const std::vector<std::string> &paths) {
    struct Item {
        std::string path;
        VolumeInfo info;
    };
    std::map<std::string, std::vector<Item>> map;
    GroupResult result;

    for (const std::string &p : paths) {
        VolumeInfo info = AnalyzeVolume(p);
        if (info.kind == VolumeKind::none) {
            result.singles.push_back(p);
            continue;
        }
        auto it = map.find(info.base);
        if (it == map.end()) {
            map.emplace(info.base, std::vector<Item>{Item{p, std::move(info)}});
        } else {
            it->second.push_back(Item{p, std::move(info)});
        }
    }

    for (auto &entry : map) {
        std::vector<Item> &items = entry.second;
        std::stable_sort(items.begin(), items.end(),
                         [](const Item &a, const Item &b) {
                             return a.info.index < b.info.index;
                         });
        size_t entry_idx = 0;
        for (size_t i = 0; i < items.size(); ++i) {
            if (items[i].info.is_first) {
                entry_idx = i;
                break;
            }
        }
        Group group;
        group.entry = items[entry_idx].path;
        for (size_t i = 0; i < items.size(); ++i) {
            if (i != entry_idx) group.deps.push_back(items[i].path);
        }
        group.display = items[entry_idx].path;
        group.multi = items.size() > 1;
        result.groups.push_back(std::move(group));
    }
    return result;
}

}  // namespace hrd
