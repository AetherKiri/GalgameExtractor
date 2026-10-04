const std = @import("std");
const types = @import("types.zig");
const engine_mod = @import("engine.zig");
const util = @import("util.zig");

const HRD_STATUS_OK = 0;
const HRD_STATUS_ERR_INVALID_ARG = 1;
const HRD_STATUS_ERR_IO = 2;
const HRD_STATUS_ERR_UNSUPPORTED = 3;
const HRD_STATUS_ERR_ENCRYPTED = 4;
const HRD_STATUS_ERR_PASSWORD = 5;
const HRD_STATUS_ERR_BOMB = 6;
const HRD_STATUS_ERR_DEPTH = 7;
const HRD_STATUS_ERR_ARCHIVE = 8;
const HRD_STATUS_ERR_NOMEM = 9;
const HRD_STATUS_ERR_CANCELLED = 10;
const HRD_STATUS_ERR_INTERNAL = 255;

var gpa_storage: ?std.heap.DebugAllocator(.{}) = null;

fn gpa() std.mem.Allocator {
    if (gpa_storage == null) gpa_storage = .{};
    return gpa_storage.?.allocator();
}

const CNeedPass = *const fn (
    archive_path: [*:0]const u8,
    out_password: [*]u8,
    out_cap: usize,
    user: ?*anyopaque,
) callconv(.c) c_int;
const CEvent = *const fn (
    event: c_int,
    path: [*:0]const u8,
    depth: u32,
    fmt: c_int,
    aux: u64,
    user: ?*anyopaque,
) callconv(.c) void;

const COptions = extern struct {
    struct_size: u32,
    max_depth: u32,
    max_ratio: u32,
    max_total_bytes: u64,
    flatten: u32,
    overwrite: u32,
    interactive: u32,
    password_db: ?[*:0]const u8,
    temp_dir: ?[*:0]const u8,
};

const Ctx = struct {
    engine: engine_mod.Engine,
    need_pass: ?CNeedPass = null,
    event: ?CEvent = null,
    user: ?*anyopaque = null,
};

var ctx_map = std.AutoHashMap(usize, *Ctx).init(undefined);
var ctx_map_init = false;

fn ensureCtxMap() void {
    if (!ctx_map_init) {
        ctx_map = std.AutoHashMap(usize, *Ctx).init(gpa());
        ctx_map_init = true;
    }
}

fn toStatus(e: anyerror) c_int {
    const val: c_int = switch (e) {
        error.OutOfMemory => HRD_STATUS_ERR_NOMEM,
        error.BackendMissing => HRD_STATUS_ERR_UNSUPPORTED,
        error.OpenFailed, error.NotArchive => HRD_STATUS_ERR_ARCHIVE,
        error.EncryptedHeaders, error.WrongPassword => HRD_STATUS_ERR_ENCRYPTED,
        error.DataError, error.CrcError, error.UndecryptableFile => HRD_STATUS_ERR_ARCHIVE,
        error.Cancelled => HRD_STATUS_ERR_CANCELLED,
        error.Bomb => HRD_STATUS_ERR_BOMB,
        else => HRD_STATUS_ERR_INTERNAL,
    };
    return val;
}

export fn hrd_abi_version() callconv(.c) u32 {
    return 1 << 16 | 0; // v1.0
}

export fn hrd_status_string(st: c_int) callconv(.c) [*:0]const u8 {
    return switch (st) {
        HRD_STATUS_OK => "ok",
        HRD_STATUS_ERR_INVALID_ARG => "invalid argument",
        HRD_STATUS_ERR_IO => "I/O error",
        HRD_STATUS_ERR_UNSUPPORTED => "unsupported format",
        HRD_STATUS_ERR_ENCRYPTED => "encrypted (password needed)",
        HRD_STATUS_ERR_PASSWORD => "wrong password",
        HRD_STATUS_ERR_BOMB => "bomb limit exceeded",
        HRD_STATUS_ERR_DEPTH => "max recursion depth",
        HRD_STATUS_ERR_ARCHIVE => "archive error",
        HRD_STATUS_ERR_NOMEM => "out of memory",
        HRD_STATUS_ERR_CANCELLED => "cancelled",
        else => "unknown error",
    };
}

export fn hrd_ctx_create(opts_ptr: ?*const anyopaque) callconv(.c) ?*anyopaque {
    const alloc = gpa();
    var opts: types.Options = .{};
    if (opts_ptr) |raw| {
        const c: *const COptions = @ptrCast(@alignCast(raw));
        opts.max_depth = if (c.max_depth == 0) opts.max_depth else c.max_depth;
        opts.max_ratio = c.max_ratio;
        opts.max_total_bytes = c.max_total_bytes;
        opts.flatten = c.flatten != 0;
        opts.overwrite = c.overwrite != 0;
        opts.interactive = c.interactive != 0;
        if (c.password_db) |p| opts.password_db = std.mem.span(p);
        if (c.temp_dir) |p| opts.temp_dir = std.mem.span(p);
    }
    const ctx = alloc.create(Ctx) catch return null;
    ctx.engine = engine_mod.Engine.init(alloc, opts) catch {
        alloc.destroy(ctx);
        return null;
    };
    ensureCtxMap();
    ctx_map.put(@intFromPtr(ctx), ctx) catch {
        ctx.engine.deinit();
        alloc.destroy(ctx);
        return null;
    };
    return @ptrCast(ctx);
}

export fn hrd_ctx_destroy(ctx: ?*anyopaque) callconv(.c) void {
    if (ctx) |c| {
        const context: *Ctx = @ptrCast(@alignCast(c));
        if (ctx_map_init) _ = ctx_map.remove(@intFromPtr(context));
        context.engine.deinit();
        gpa().destroy(context);
    }
}

fn passwordAdapter(path: []const u8, buf: []u8, user: ?*anyopaque) ?[]const u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(user.?));
    const path_z = std.heap.c_allocator.dupeZ(u8, path) catch return null;
    defer std.heap.c_allocator.free(path_z);
    const cb = ctx.need_pass orelse return null;
    const n = cb(path_z.ptr, buf.ptr, buf.len, ctx.user);
    if (n == 0) return null;
    const len = std.mem.indexOfScalar(u8, buf, 0) orelse @min(@as(usize, @intCast(n)), buf.len);
    return buf[0..len];
}

fn eventAdapter(info: types.EventInfo, user: ?*anyopaque) void {
    const ctx: *Ctx = @ptrCast(@alignCast(user.?));
    const cb = ctx.event orelse return;
    const path_z = std.heap.c_allocator.dupeZ(u8, info.path) catch return;
    defer std.heap.c_allocator.free(path_z);
    cb(@intFromEnum(info.event), path_z.ptr, info.depth, @intFromEnum(info.fmt), info.aux, ctx.user);
}

fn applyCallbacks(ctx: *Ctx) void {
    ctx.engine.setCallbacks(.{
        .need_password = if (ctx.need_pass != null) passwordAdapter else null,
        .event = if (ctx.event != null) eventAdapter else null,
        .user = @ptrCast(ctx),
    });
}

export fn hrd_ctx_set_need_password_cb(ctx_ptr: ?*anyopaque, cb: ?CNeedPass, user: ?*anyopaque) callconv(.c) void {
    const ctx = if (ctx_ptr) |p| @as(*Ctx, @ptrCast(@alignCast(p))) else return;
    ctx.need_pass = cb;
    ctx.user = user;
    applyCallbacks(ctx);
}

export fn hrd_ctx_set_event_cb(ctx_ptr: ?*anyopaque, cb: ?CEvent, user: ?*anyopaque) callconv(.c) void {
    const ctx = if (ctx_ptr) |p| @as(*Ctx, @ptrCast(@alignCast(p))) else return;
    ctx.event = cb;
    ctx.user = user;
    applyCallbacks(ctx);
}

export fn hrd_ctx_add_password(ctx_ptr: ?*anyopaque, password: ?[*:0]const u8) callconv(.c) c_int {
    const ctx = if (ctx_ptr) |p| @as(*Ctx, @ptrCast(@alignCast(p))) else return HRD_STATUS_ERR_INVALID_ARG;
    const pw = password orelse return HRD_STATUS_ERR_INVALID_ARG;
    ctx.engine.book.learn(std.mem.span(pw)) catch |e| return toStatus(e);
    return HRD_STATUS_OK;
}

export fn hrd_process(
    ctx: ?*anyopaque,
    inputs: ?[*]const [*:0]const u8,
    input_count: usize,
    out_dir: ?[*:0]const u8,
    out_report: ?*?[*:0]const u8,
) callconv(.c) c_int {
    if (ctx == null or inputs == null or out_dir == null) return HRD_STATUS_ERR_INVALID_ARG;
    const context: *Ctx = @ptrCast(@alignCast(ctx.?));
    const alloc = gpa();

    const inputs_raw = inputs.?[0..input_count];
    var input_list = std.ArrayList([]const u8).empty;
    defer input_list.deinit(alloc);
    for (inputs_raw) |inp| {
        input_list.append(alloc, std.mem.span(inp)) catch return HRD_STATUS_ERR_NOMEM;
    }
    const od = std.mem.span(out_dir.?);

    const report = context.engine.process(input_list.items, od) catch |e| return toStatus(e);

    if (out_report) |or_| {
        const r = std.fmt.allocPrint(
            alloc,
            "{{\"archives\":{d},\"delivered_files\":{d},\"delivered_bytes\":{d},\"errors\":{d},\"passwords_used\":{d}}}",
            .{ report.archives, report.delivered_files, report.delivered_bytes, report.errors, report.passwords_used },
        ) catch return HRD_STATUS_ERR_NOMEM;
        or_.* = @ptrCast(r.ptr);
    }
    return HRD_STATUS_OK;
}

export fn hrd_free(p: ?*anyopaque) callconv(.c) void {
    if (p) |ptr| {
        gpa().free(std.mem.span(@as([*:0]const u8, @ptrCast(ptr))));
    }
}
