const std = @import("std");
const types = @import("types.zig");
const util = @import("util.zig");
const engine_mod = @import("engine.zig");

const usage =
    \\Usage: hrd [options] <input...> -o <output_dir>
    \\
    \\  Heuristic Recursive Decompressor
    \\
    \\Options:
    \\  -o, --output <dir>   Output directory (required)
    \\  -d, --depth <N>      Max recursion depth (default: 8)
    \\  -r, --ratio <N>      Max expansion ratio (0=disable, default: 100)
    \\  -b, --bytes <N>      Max total bytes (0=disable, default: 34359738368)
    \\  --no-interactive      Disable interactive password prompts
    \\  --password-db <file>  Extra password DB file (one per line)
    \\  --temp-dir <dir>      Temporary directory
    \\  --flatten             Flatten output (no directory tree)
    \\  --overwrite           Overwrite existing files
    \\  -h, --help            Show this help
    \\
    \\Examples:
    \\  hrd archive.zip -o ./out
    \\  hrd ./downloads/ -o ./extracted
    \\  hrd part1.rar part2.rar part3.rar -o ./out
    \\  hrd photo.png -o ./out
    \\
    \\The program never trusts file extensions. It sniffs magic bytes to detect
    \\real archive formats, finds embedded archives in mp4/png/steg files,
    \\handles encrypted archives with password book + interactive fallback,
    \\and recursively extracts nested archives up to the depth limit.
    \\
;

pub fn main(init: std.process.Init.Minimal) !void {
    const a = std.heap.c_allocator;

    // Use Zig's portable argument API.  The old implementation reached into
    // the Windows PEB directly, which made the extractor impossible to build
    // for Android/iOS and also made the CLI unnecessarily hard to test.
    var it = try std.process.Args.Iterator.initAllocator(init.args, a);
    defer it.deinit();
    _ = it.next();

    var inputs = std.ArrayList([]const u8).empty;
    defer inputs.deinit(a);
    var output_dir: ?[]const u8 = null;
    var max_depth: u32 = 8;
    var max_ratio: u32 = 100;
    var max_bytes: u64 = 32 << 30;
    var interactive = true;
    var password_db: ?[]const u8 = null;
    var temp_dir: ?[]const u8 = null;
    var flatten = false;
    var overwrite = false;

    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage});
            return;
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            if (it.next()) |value| output_dir = value;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--depth")) {
            if (it.next()) |value| max_depth = std.fmt.parseInt(u32, value, 10) catch 8;
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--ratio")) {
            if (it.next()) |value| max_ratio = std.fmt.parseInt(u32, value, 10) catch 100;
        } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--bytes")) {
            if (it.next()) |value| max_bytes = std.fmt.parseInt(u64, value, 10) catch (32 << 30);
        } else if (std.mem.eql(u8, arg, "--no-interactive")) {
            interactive = false;
        } else if (std.mem.eql(u8, arg, "--password-db")) {
            if (it.next()) |value| password_db = value;
        } else if (std.mem.eql(u8, arg, "--temp-dir")) {
            if (it.next()) |value| temp_dir = value;
        } else if (std.mem.eql(u8, arg, "--flatten")) {
            flatten = true;
        } else if (std.mem.eql(u8, arg, "--overwrite")) {
            overwrite = true;
        } else {
            try inputs.append(a, arg);
        }
    }

    if (inputs.items.len == 0 or output_dir == null) {
        std.debug.print("Error: at least one input and -o <output_dir> are required.\n\n{s}", .{usage});
        std.process.exit(1);
    }

    var eng = engine_mod.Engine.init(a, .{
        .max_depth = max_depth,
        .max_ratio = max_ratio,
        .max_total_bytes = max_bytes,
        .flatten = flatten,
        .overwrite = overwrite,
        .interactive = interactive,
        .password_db = password_db,
        .temp_dir = temp_dir,
    }) catch |e| {
        std.debug.print("Failed to initialize: {}\n", .{e});
        std.process.exit(1);
    };
    defer eng.deinit();

    eng.setCallbacks(.{
        .event = eventPrinter,
        .user = null,
    });

    const report = eng.process(inputs.items, output_dir.?) catch |e| {
        std.debug.print("Processing failed: {}\n", .{e});
        std.process.exit(1);
    };

    var buf: [64]u8 = undefined;
    std.debug.print("\n=== HRD Report ===\n", .{});
    std.debug.print("  Archives processed : {d}\n", .{report.archives});
    std.debug.print("  Files delivered    : {d}\n", .{report.delivered_files});
    std.debug.print("  Bytes delivered    : {s}\n", .{util.fmtBytes(&buf, report.delivered_bytes)});
    std.debug.print("  Kept as-is         : {d}\n", .{report.kept});
    std.debug.print("  Passwords used     : {d}\n", .{report.passwords_used});
    std.debug.print("  Errors             : {d}\n", .{report.errors});
}

fn eventPrinter(info: types.EventInfo, _: ?*anyopaque) void {
    const label: []const u8 = switch (info.event) {
        .grouped => "GROUP",
        .sniffed => "SNIFF",
        .probe => "PROBE",
        .extracting => "EXTRACT",
        .extracted => "DONE",
        .delivered => "DELIVER",
        .kept => "KEEP",
        .circuit => "CIRCUIT",
    };
    const fmt_str: []const u8 = if (info.fmt != .none) @tagName(info.fmt) else "-";
    std.debug.print("  [{s}] {s}  fmt={s}  aux={d}\n", .{ label, info.path, fmt_str, info.aux });
}
