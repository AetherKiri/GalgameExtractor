// volumes.h — port of src/volumes.zig.
//
// Multi-volume aggregation: partN.rar, old-style .rNN, .NNN numeric splits,
// 7z.001 splits, and .zNN + .zip split sets are grouped so the engine opens
// the first volume and feeds the siblings through the open callback.

#pragma once

#include "hrd_internal.h"

#include <string>
#include <vector>

namespace hrd {

enum class VolumeKind {
    none,
    rar_part,
    rar_old,
    numeric,
    zip_split,
    sevenz_part,
};

struct VolumeInfo {
    VolumeKind kind = VolumeKind::none;
    std::string base;
    uint32_t index = 0;
    bool is_first = false;
};

VolumeInfo AnalyzeVolume(const std::string &path);

struct Group {
    std::string entry;  // first (or only) volume to open
    std::vector<std::string> deps;  // remaining volumes of the group
    std::string display;
    bool multi = false;
};

struct GroupResult {
    std::vector<Group> groups;
    std::vector<std::string> singles;
};

GroupResult GroupVolumes(const std::vector<std::string> &paths);

}  // namespace hrd
