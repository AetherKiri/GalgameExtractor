const std = @import("std");
const types = @import("types.zig");
const util = @import("util.zig");
const ioctx = @import("ioctx.zig");
const sniffer = @import("sniffer.zig");
const volumes = @import("volumes.zig");
const password = @import("password.zig");
const ffi = @import("ffi_bridge.zig");

pub const Engine = struct {
    alloc: std.mem.Allocator,
    opts: types.Options,
    book: password.PasswordBook,
    lib: ffi.Lib,
    report: types.Report,
    evcb: ?types.Callbacks,

    pub fn init(alloc: std.mem.Allocator, opts: types.Options) !Engine {
        ioctx.init(alloc);
        const lib = ffi.Lib.load() catch return error.BackendMissing;
        var book = password.PasswordBook.init(alloc);
        try book.loadDefaultDb(opts.password_db);
        return .{
            .alloc = alloc,
            .opts = opts,
            .book = book,
            .lib = lib,
            .report = .{},
            .evcb = null,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.book.deinit();
        ioctx.deinit();
    }

    pub fn setCallbacks(self: *Engine, cb: types.Callbacks) void {
        self.evcb = cb;
    }

    fn emit(self: *Engine, ev: types.EventInfo) void {
        if (self.evcb) |cb| {
            if (cb.event) |f| f(ev, cb.user);
        }
    }

    pub fn process(self: *Engine, inputs: []const []const u8, out_dir: []const u8) !types.Report {
        // Expand directories to their contents (walk non-recursively: first-level files).
        var all_files = std.ArrayList([]const u8).empty;
        defer {
            for (all_files.items) |f| self.alloc.free(f);
            all_files.deinit(self.alloc);
        }
        for (inputs) |inp| {
            // try to open as dir
            const _io = ioctx.io();
            if (ioctx.cwd().openDir(_io, inp, .{ .iterate = true })) |*d| {
                var dd = d;
                defer dd.close(_io);
                var w = try dd.walk(self.alloc);
                defer w.deinit();
                while (w.next(_io) catch null) |entry| {
                    if (entry.kind == .file) {
                        const p = try util.join(self.alloc, &.{ inp, entry.path });
                        try all_files.append(self.alloc, p);
                    }
                }
            } else |_| {
                try all_files.append(self.alloc, try self.alloc.dupe(u8, inp));
            }
        }

        // Module 1: Volume aggregation
        const gr = try volumes.group(self.alloc, all_files.items);
        defer {
            for (gr.groups) |g| self.alloc.free(g.deps);
            self.alloc.free(gr.groups);
            self.alloc.free(gr.singles);
        }
        var processed_paths = std.StringHashMap(void).init(self.alloc);
        defer processed_paths.deinit();

        // Create output directory
        try ioctx.cwd().createDirPath(ioctx.io(), out_dir);

        // Process groups first
        for (gr.groups) |g| {
            const display = g.display;
            self.emit(.{ .event = .grouped, .path = display, .depth = 0, .fmt = .none, .aux = @intCast(g.deps.len) });
            // Only process if not already handled as part of another group
            if (processed_paths.contains(g.entry)) continue;
            try self.processEntry(g.entry, out_dir, 0, &processed_paths, g.deps);
            for (g.deps) |d| try processed_paths.put(d, {});
        }

        // Process singles
        for (gr.singles) |s| {
            if (processed_paths.contains(s)) continue;
            try self.processEntry(s, out_dir, 0, &processed_paths, &.{});
        }

        return self.report;
    }

    fn processEntry(self: *Engine, path: []const u8, out_dir: []const u8, depth: u32, processed: *std.StringHashMap(void), vol_deps: []const []const u8) !void {
        if (depth >= self.opts.max_depth) {
            self.emit(.{ .event = .circuit, .path = path, .depth = depth, .fmt = .none, .aux = self.opts.max_depth });
            return;
        }
        if (processed.contains(path)) return;
        try processed.put(path, {});

        // Password hints travel with the download surprisingly often.  Load
        // them before probing this entry so README/NFO/TXT files beside a
        // volume are part of the same unified password-book pipeline.
        self.book.gatherContext(path) catch {};

        // Module 2: Sniff real carrier — collect all plausible candidates
        const cands = sniffer.sniffFileAll(self.alloc, path) catch return;
        defer self.alloc.free(cands);
        if (cands.len == 0) {
            // Not an archive at all — deliver as-is
            self.report.kept += 1;
            self.emit(.{ .event = .kept, .path = path, .depth = depth, .fmt = .none, .aux = 0 });
            self.deliverFile(path, out_dir) catch {};
            return;
        }

        // Points into self.book.candidates (book-owned; freed by book.deinit).
        var current_password: ?[]const u8 = null;
        var probe_result: ?ffi.ProbeResult = null;
        var chosen_fmt: types.Format = .none;
        var chosen_clsid: ?com.GUID = null;
        var chosen_actual: []const u8 = path;
        var chosen_free = false;
        defer if (chosen_free) {
            ioctx.cwd().deleteFile(ioctx.io(), chosen_actual) catch {};
            self.alloc.free(chosen_actual);
        };
        defer if (probe_result) |pr| {
            for (pr.entries) |e| self.alloc.free(e.path);
            self.alloc.free(pr.entries);
        };

        var volcat_path: ?[]u8 = null;
        defer if (volcat_path) |p| self.alloc.free(p);

        // Try every sniff candidate until one opens as a valid archive.
        // Deliver nothing until an archive is positively identified.
        for (cands) |cand| {
            self.emit(.{ .event = .sniffed, .path = path, .depth = depth, .fmt = cand.fmt, .aux = cand.offset });

            // Materialize disguised carrier if needed
            var actual_path: []const u8 = path;
            var free_actual = false;
            if (cand.disguised) {
                actual_path = sniffer.sliceToFile(self.alloc, path, cand.offset, out_dir, "_stripped_") catch continue;
                free_actual = true;
            }

            // Multi-volume: numeric split archives (.7z.001/.001) cannot be opened
            // by the 7z handler directly — concatenate volumes into one temp file.
            if (vol_deps.len > 0 and util.endsWithNumericSplit(util.basename(path))) {
                if (volcat_path == null) volcat_path = self.concatVolumes(path, vol_deps, out_dir) catch null;
                if (volcat_path) |cp| {
                    if (free_actual) ioctx.cwd().deleteFile(ioctx.io(), actual_path) catch {};
                    actual_path = cp;
                    free_actual = false;
                }
            }

            // Map format to 7z handler. Rar (v4) and Rar5 share the "rar"
            // extension — disambiguate via the handler's signature bytes.
            const ext_str: ?[]const u8 = switch (cand.fmt) {
                .zip => "zip",
                .rar4, .rar5 => "rar",
                .sevenz => "7z",
                .gz => "gz",
                .bz2 => "bz2",
                .xz => "xz",
                .tar => "tar",
                .cab => "cab",
                .none => null,
            };
            const sig_want: ?[]const u8 = switch (cand.fmt) {
                .rar4 => "Rar",
                .rar5 => "Rar5",
                else => null,
            };
            const clsid = if (ext_str) |es| self.lib.findHandlerSig(self.alloc, es, sig_want) catch null else null;
            if (clsid == null) {
                if (free_actual) ioctx.cwd().deleteFile(ioctx.io(), actual_path) catch {};
                continue;
            }

            self.emit(.{ .event = .probe, .path = path, .depth = depth, .fmt = cand.fmt, .aux = cand.offset });

            // Probe without a password first; if the archive has encrypted
            // headers (e.g. 7z -mhe=on) the open itself fails, so retry with
            // password-book candidates.
            const pr = blk: {
                if (self.lib.probe(self.alloc, actual_path, clsid.?, vol_deps, null)) |p| {
                    break :blk p;
                } else |_| {}
                for (self.book.candidates.items) |cand_pw| {
                    if (self.lib.probe(self.alloc, actual_path, clsid.?, vol_deps, cand_pw)) |p| {
                        current_password = cand_pw;
                        self.report.passwords_used += 1;
                        break :blk p;
                    } else |_| {}
                }
                break :blk null;
            };

            if (pr == null) {
                // If the archive is not covered by the local book, give the
                // host one interactive opportunity.  The callback is optional
                // and remains disabled for non-interactive callers.
                var interactive_probe: ?ffi.ProbeResult = null;
                if (self.opts.interactive) {
                    if (self.evcb) |cb| {
                        if (cb.need_password) |need| {
                            var pass_buf: [512]u8 = undefined;
                            if (need(path, &pass_buf, cb.user)) |pass| {
                                if (self.lib.probe(self.alloc, actual_path, clsid.?, vol_deps, pass)) |found_probe| {
                                    self.book.learn(pass) catch {};
                                    current_password = self.book.candidates.items[self.book.candidates.items.len - 1];
                                    self.report.passwords_used += 1;
                                    interactive_probe = found_probe;
                                } else |_| {}
                            }
                        }
                    }
                }
                if (interactive_probe) |found| {
                    probe_result = found;
                    chosen_fmt = cand.fmt;
                    chosen_clsid = clsid;
                    chosen_actual = actual_path;
                    chosen_free = free_actual;
                    break;
                }
                // This candidate is not a valid archive — try the next sniff hit.
                if (free_actual) ioctx.cwd().deleteFile(ioctx.io(), actual_path) catch {};
                continue;
            }

            probe_result = pr;
            chosen_fmt = cand.fmt;
            chosen_clsid = clsid;
            chosen_actual = actual_path;
            chosen_free = free_actual;
            break;
        }

        const pr = probe_result orelse {
            // Every candidate exhausted — keep the original file as-is.
            self.report.kept += 1;
            self.emit(.{ .event = .kept, .path = path, .depth = depth, .fmt = .none, .aux = 0 });
            self.deliverFile(path, out_dir) catch {};
            self.report.errors += 1;
            return;
        };
        const sniff_fmt = chosen_fmt;
        const actual_path = chosen_actual;

        // Module 4: Extract
        self.emit(.{ .event = .extracting, .path = path, .depth = depth, .fmt = sniff_fmt, .aux = 0 });

        const depth_dir = try util.allocPrint(self.alloc, "{s}/_{d}_{s}", .{ out_dir, depth, util.basename(path) });
        defer self.alloc.free(depth_dir);
        try ioctx.cwd().createDirPath(ioctx.io(), depth_dir);

        // Extract
        const bomb_limit: u64 = if (self.opts.max_ratio > 0) self.opts.max_total_bytes else 0;

        const needs_pass = pr.any_encrypted or current_password != null;
        var verified_extract = false;
        if (needs_pass and current_password == null) {
            // Zip-style: headers readable but entries encrypted — the only sound
            // check is a real extraction attempt (wrong password → CRC error).
            // A successful attempt leaves the content extracted; skip re-extract.
            if (pr.any_encrypted) {
                for (self.book.candidates.items) |candidate| {
                    const arc = self.lib.openArchive(self.alloc, actual_path, chosen_clsid.?, vol_deps, candidate) catch continue;
                    var ok = true;
                    _ = arc.extractAll(.{
                        .out_dir = depth_dir,
                        .bomb_limit = bomb_limit,
                        .password = candidate,
                    }) catch {
                        ok = false;
                    };
                    arc.close();
                    self.alloc.destroy(arc);
                    if (ok) {
                        current_password = candidate;
                        verified_extract = true;
                        self.report.passwords_used += 1;
                        self.report.archives += 1;
                        self.emit(.{ .event = .extracted, .path = path, .depth = depth, .fmt = sniff_fmt, .aux = 0 });
                        break;
                    }
                    // Wipe partial output of the wrong-password attempt.
                    ioctx.cwd().deleteTree(ioctx.io(), depth_dir) catch {};
                    ioctx.cwd().createDirPath(ioctx.io(), depth_dir) catch {};
                }
            } else {
                // rar5-style: encrypted headers — the probe itself validates the
                // password (block CRC), so retry probe with book candidates.
                for (self.book.candidates.items) |candidate| {
                    if (self.lib.probe(self.alloc, actual_path, chosen_clsid.?, vol_deps, candidate)) |pr2| {
                        current_password = candidate;
                        self.report.passwords_used += 1;
                        for (pr.entries) |e| self.alloc.free(e.path);
                        self.alloc.free(pr.entries);
                        probe_result = pr2;
                        break;
                    } else |_| {}
                }
            }
            if (current_password == null) {
                self.report.errors += 1;
                return;
            }
        }

        if (!verified_extract) {
            // Open archive
            const arc = self.lib.openArchive(self.alloc, actual_path, chosen_clsid.?, vol_deps, current_password) catch {
                self.report.errors += 1;
                return;
            };

            // Extract
            _ = arc.extractAll(.{
                .out_dir = depth_dir,
                .bomb_limit = bomb_limit,
                .password = current_password,
            }) catch {
                self.report.errors += 1;
            };

            arc.close();
            self.alloc.destroy(arc);
            self.report.archives += 1;
            self.emit(.{ .event = .extracted, .path = path, .depth = depth, .fmt = sniff_fmt, .aux = 0 });
        }

        // Module 4b: Recursive scan of extracted contents
        var wdir = ioctx.cwd().openDir(ioctx.io(), depth_dir, .{ .iterate = true }) catch {
                        return;
        };
        defer wdir.close(ioctx.io());
        var walker = try wdir.walk(self.alloc);
        defer walker.deinit();
        while (walker.next(ioctx.io()) catch blk: {
            break :blk null;
        }) |entry| {
            if (entry.kind == .file) {
                const child = try util.join(self.alloc, &.{ depth_dir, entry.path });
                defer self.alloc.free(child);
                self.processEntry(child, out_dir, depth + 1, processed, &.{}) catch {};
            }
        }

        // Module 5: Cleanup temp stripped files & deliver
        // Deliver final non-archived files
        self.deliverTree(depth_dir, out_dir) catch {};

        // Cleanup temp
        ioctx.cwd().deleteTree(ioctx.io(), depth_dir) catch {};
    }

    fn tryPassword(self: *Engine, path: []const u8, clsid: com.GUID, pass: []const u8) bool {
        _ = self;
        _ = path;
        _ = clsid;
        _ = pass;
        // TODO: implement real password test via 7z Open with password callback
        return false;
    }

    /// Concatenate all volumes of a split archive into a single temp file.
    fn concatVolumes(self: *Engine, first: []const u8, rest: []const []const u8, out_dir: []const u8) ![]u8 {
        const io = ioctx.io();
        const name = util.basename(first);
        // strip trailing .NNN
        const stem = if (name.len > 4) name[0 .. name.len - 4] else name;
        const dest = try util.join(self.alloc, &.{ out_dir, try util.allocPrint(self.alloc, "_volcat_{s}", .{stem}) });
        errdefer self.alloc.free(dest);
        var out = try ioctx.cwd().createFile(io, dest, .{ .truncate = true });
        defer out.close(io);
        var out_pos: u64 = 0;
        var buf: [1 << 20]u8 = undefined;
        for ([2][]const []const u8{ &[_][]const u8{first}, rest }) |list| {
            for (list) |vol| {
                var f = try ioctx.cwd().openFile(io, vol, .{});
                defer f.close(io);
                var in_pos: u64 = 0;
                while (true) {
                    const n = try f.readPositional(io, &.{&buf}, in_pos);
                    if (n == 0) break;
                    try out.writePositionalAll(io, buf[0..n], out_pos);
                    in_pos += n;
                    out_pos += n;
                }
            }
        }
        return dest;
    }

    fn deliverFile(self: *Engine, src: []const u8, out_dir: []const u8) !void {
        const io = ioctx.io();
        const name = util.basename(src);
        const dest = try util.join(self.alloc, &.{ out_dir, name });
        defer self.alloc.free(dest);
        var src_file = try ioctx.cwd().openFile(io, src, .{});
        defer src_file.close(io);
        try ioctx.cwd().createDirPath(io, out_dir);
        var dst_file = try ioctx.cwd().createFile(io, dest, .{ .truncate = true });
        defer dst_file.close(io);
        const stat = try src_file.stat(io);
        if (stat.size == 0) return;
        var pos: u64 = 0;
        const buf = try self.alloc.alloc(u8, 1 << 23);
        defer self.alloc.free(buf);
        while (pos < stat.size) {
            const n = try src_file.readPositional(io, &.{buf}, pos);
            if (n == 0) break;
            try dst_file.writePositionalAll(io, buf[0..n], pos);
            pos += n;
        }
        self.report.delivered_files += 1;
        self.report.delivered_bytes += stat.size;
        self.emit(.{ .event = .delivered, .path = dest, .depth = 0, .fmt = .none, .aux = stat.size });
    }

    fn deliverTree(self: *Engine, src_dir: []const u8, out_dir: []const u8) !void {
        const io = ioctx.io();
        var d = ioctx.cwd().openDir(io, src_dir, .{ .iterate = true }) catch return;
        defer d.close(io);
        var w = try d.walk(self.alloc);
        defer w.deinit();
        while (w.next(io) catch null) |entry| {
            if (entry.kind == .file) {
                const child = try util.join(self.alloc, &.{ src_dir, entry.path });
                defer self.alloc.free(child);
                // Check if it's an archive
                if (sniffer.sniffFile(self.alloc, child) catch null) |sr| {
                    if (sr.fmt != .none) continue; // will be handled by recursion
                }
                const dest = try util.join(self.alloc, &.{ out_dir, entry.path });
                defer self.alloc.free(dest);
                if (util.dirname(dest)) |d2| ioctx.cwd().createDirPath(io, d2) catch {};
                var src_file = try ioctx.cwd().openFile(io, child, .{});
                defer src_file.close(io);
                var dst_file = ioctx.cwd().createFile(io, dest, .{ .truncate = true }) catch continue;
                defer dst_file.close(io);
                const stat = try src_file.stat(io);
                var pos: u64 = 0;
                const buf = try self.alloc.alloc(u8, 1 << 23);
                defer self.alloc.free(buf);
                while (pos < stat.size) {
                    const n = src_file.readPositional(io, &.{buf}, pos) catch break;
                    if (n == 0) break;
                    dst_file.writePositionalAll(io, buf[0..n], pos) catch break;
                    pos += n;
                }
                self.report.delivered_files += 1;
                self.report.delivered_bytes += stat.size;
                self.emit(.{ .event = .delivered, .path = dest, .depth = 0, .fmt = .none, .aux = stat.size });
            }
        }
    }
};

const com = @import("sevenzip_com.zig");
