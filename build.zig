const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const exe = b.addExecutable(.{ .name = "hrd", .root_module = exe_mod });
    b.installArtifact(exe);

    const abi_mod = b.createModule(.{
        .root_source_file = b.path("src/abi.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const abi_lib = b.addLibrary(.{
        .name = "hrd",
        .linkage = .dynamic,
        .root_module = abi_mod,
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
    });
    b.installArtifact(abi_lib);

    const hdr = b.addInstallFileWithDir(b.path("include/hrd.h"), .header, "hrd.h");
    b.getInstallStep().dependOn(&hdr.step);

    // Copy 7z.dll next to binaries.  The backend is intentionally kept as a
    // runtime dependency so the same HRD ABI can be loaded by the Godot host.
    if (target.result.os.tag == .windows) {
        const dll_copy = b.addInstallFileWithDir(b.path("third_party/7zip/7z.dll"), .bin, "7z.dll");
        b.getInstallStep().dependOn(&dll_copy.step);
    }

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run unit tests").dependOn(&run_tests.step);

    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| run_exe.addArgs(args);
    b.step("run", "Run the hrd CLI").dependOn(&run_exe.step);
}
