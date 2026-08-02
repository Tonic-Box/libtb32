//! A two-pass TB32 assembler that emits a TBX object.

const std = @import("std");
const isa = @import("isa.zig");

pub const Error = error{
    BadRegister,
    BadMemoryOperand,
    BadString,
    UnknownInstruction,
    UnknownDirective,
    UnresolvedSymbol,
    CannotEvaluate,
    BadArgs,
} || std.mem.Allocator.Error;

const SEC_ORDER = [_][]const u8{ ".text", ".rodata", ".data", ".bss" };
const SEC_TYPE = [_]u16{ 1, 1, 1, 2 };

fn secIndex(name: []const u8) ?usize {
    for (SEC_ORDER, 0..) |s, i| {
        if (std.mem.eql(u8, s, name)) return i;
    }
    return null;
}

fn parseReg(tok: []const u8) Error!u4 {
    var buf: [8]u8 = undefined;
    const t = std.mem.trim(u8, tok, " \t\r\n");
    if (t.len == 0 or t.len >= buf.len) return error.BadRegister;
    for (t, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    const s = buf[0..t.len];
    if (std.mem.eql(u8, s, "zero")) return 0;
    if (std.mem.eql(u8, s, "sp")) return 13;
    if (std.mem.eql(u8, s, "fp")) return 14;
    if (std.mem.eql(u8, s, "lr")) return 15;
    if (s.len >= 2 and s[0] == 'r') {
        const n = std.fmt.parseInt(u8, s[1..], 10) catch return error.BadRegister;
        if (n < 16) return @intCast(n);
    }
    return error.BadRegister;
}

fn isIdent(s: []const u8) bool {
    if (s.len == 0) return false;
    const c0 = s[0];
    if (!(std.ascii.isAlphabetic(c0) or c0 == '_' or c0 == '.' or c0 == '$')) return false;
    for (s[1..]) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '$')) return false;
    }
    return true;
}

fn isWord(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    }
    return true;
}

const LabelOff = struct { name: []const u8, plus: bool, off: []const u8 };

fn splitLabelOffset(s: []const u8) ?LabelOff {
    var i: usize = 1;
    while (i < s.len) : (i += 1) {
        if (s[i] == '+' or s[i] == '-') {
            const name = std.mem.trim(u8, s[0..i], " \t");
            const off = std.mem.trim(u8, s[i + 1 ..], " \t");
            if (isIdent(name) and isWord(off)) return .{ .name = name, .plus = s[i] == '+', .off = off };
            return null;
        }
    }
    return null;
}

fn mask32(v: i64) u32 {
    return @truncate(@as(u64, @bitCast(v)));
}

fn appendLE16(list: *std.ArrayList(u8), v: u16) !void {
    try list.append(@truncate(v));
    try list.append(@truncate(v >> 8));
}
fn appendLE32(list: *std.ArrayList(u8), v: u32) !void {
    try list.append(@truncate(v));
    try list.append(@truncate(v >> 8));
    try list.append(@truncate(v >> 16));
    try list.append(@truncate(v >> 24));
}

const PKind = enum { label, space, word, byte, raw, insn };
const Pending = struct {
    kind: PKind,
    sec: usize,
    off: u32,
    name: []const u8 = "",
    n: u32 = 0,
    items: [][]const u8 = &.{},
    data: []const u8 = "",
    mnem: []const u8 = "",
    args: [][]const u8 = &.{},
};

const Reloc = struct { vaddr: u32, typ: u32, addend: u32 };
const LabelEntry = struct { name: []const u8, value: i64 };

const Assembler = struct {
    a: std.mem.Allocator,
    labels: std.StringHashMap(i64),
    equ: std.StringHashMap(i64),
    sections: [4]std.ArrayList(u8),
    sec_base: [4]u32,
    cur: usize,
    entry_label: []const u8,
    relocs: std.ArrayList(Reloc),
    pending: std.ArrayList(Pending),
    label_order: std.ArrayList(LabelEntry),

    fn init(a: std.mem.Allocator) Assembler {
        var self: Assembler = .{
            .a = a,
            .labels = std.StringHashMap(i64).init(a),
            .equ = std.StringHashMap(i64).init(a),
            .sections = undefined,
            .sec_base = .{ 0, 0, 0, 0 },
            .cur = 0,
            .entry_label = "_start",
            .relocs = std.ArrayList(Reloc).init(a),
            .pending = std.ArrayList(Pending).init(a),
            .label_order = std.ArrayList(LabelEntry).init(a),
        };
        for (&self.sections) |*s| s.* = std.ArrayList(u8).init(a);
        return self;
    }

    fn isSym(self: *Assembler, s: []const u8) bool {
        const t = std.mem.trim(u8, s, " \t\r\n");
        if (self.equ.contains(t)) return false;
        if (self.labels.contains(t)) return true;
        if (std.fmt.parseInt(i64, t, 0)) |_| return false else |_| {}
        if (splitLabelOffset(t)) |lo| return self.labels.contains(lo.name);
        return false;
    }

    fn evalImm(self: *Assembler, s: []const u8, allow_unresolved: bool) Error!i64 {
        const t = std.mem.trim(u8, s, " \t\r\n");
        if (self.equ.get(t)) |v| return v;
        if (self.labels.get(t)) |v| return v;
        if (std.fmt.parseInt(i64, t, 0)) |v| return v else |_| {}
        if (splitLabelOffset(t)) |lo| {
            const base = self.labels.get(lo.name);
            if (base == null and !allow_unresolved) return error.UnresolvedSymbol;
            const off = std.fmt.parseInt(i64, lo.off, 0) catch return error.CannotEvaluate;
            const b = base orelse 0;
            return if (lo.plus) b + off else b - off;
        }
        if (allow_unresolved) return 0;
        return error.CannotEvaluate;
    }

    fn sizeOf(mnem: []const u8) u32 {
        if (std.mem.eql(u8, mnem, "li")) return 8;
        if (std.mem.eql(u8, mnem, "push") or std.mem.eql(u8, mnem, "pop")) return 8;
        return 4;
    }

    fn layout(self: *Assembler, src: []const u8) Error!void {
        var loc = [_]u32{ 0, 0, 0, 0 };
        var it = std.mem.splitScalar(u8, src, '\n');
        while (it.next()) |raw_line| {
            var line = stripComment(raw_line);
            line = std.mem.trim(u8, line, " \t\r\n");
            if (line.len == 0) continue;
            while (line.len > 0) {
                const colon = labelPrefix(line) orelse break;
                const name = line[0..colon];
                try self.pending.append(.{ .kind = .label, .sec = self.cur, .off = loc[self.cur], .name = name });
                line = std.mem.trim(u8, line[colon + 1 ..], " \t\r\n");
            }
            if (line.len == 0) continue;
            if (line[0] == '.') {
                const sp = std.mem.indexOfAny(u8, line, " \t");
                const d = if (sp) |p| line[0..p] else line;
                const rest = if (sp) |p| std.mem.trim(u8, line[p..], " \t\r\n") else "";
                try self.doDirSizing(d, rest, &loc);
            } else {
                const sp = std.mem.indexOfAny(u8, line, " \t");
                const mnem = try lowerDup(self.a, if (sp) |p| line[0..p] else line);
                const argstr = if (sp) |p| std.mem.trim(u8, line[p..], " \t\r\n") else "";
                const args = try splitArgs(self.a, argstr);
                try self.pending.append(.{ .kind = .insn, .sec = self.cur, .off = loc[self.cur], .mnem = mnem, .args = args });
                loc[self.cur] += sizeOf(mnem);
            }
        }
        var base: u32 = isa.TEXT_BASE;
        for (0..4) |s| {
            base = (base + 3) & ~@as(u32, 3);
            self.sec_base[s] = base;
            base += loc[s];
        }
        for (self.pending.items) |p| {
            if (p.kind == .label) {
                const v: i64 = @intCast(self.sec_base[p.sec] + p.off);
                try self.labels.put(p.name, v);
                try self.label_order.append(.{ .name = p.name, .value = v });
            }
        }
    }

    fn doDirSizing(self: *Assembler, d: []const u8, rest: []const u8, loc: *[4]u32) Error!void {
        if (secIndex(d)) |si| {
            self.cur = si;
            return;
        }
        if (std.mem.eql(u8, d, ".section")) {
            self.cur = secIndex(std.mem.trim(u8, rest, " \t\r\n")) orelse return error.UnknownDirective;
            return;
        }
        if (std.mem.eql(u8, d, ".globl") or std.mem.eql(u8, d, ".global")) return;
        if (std.mem.eql(u8, d, ".equ") or std.mem.eql(u8, d, ".set")) {
            const comma = std.mem.indexOfScalar(u8, rest, ',') orelse return error.BadArgs;
            const name = std.mem.trim(u8, rest[0..comma], " \t\r\n");
            const val = std.mem.trim(u8, rest[comma + 1 ..], " \t\r\n");
            try self.equ.put(name, try self.evalImm(val, true));
            return;
        }
        if (std.mem.eql(u8, d, ".align")) {
            const n = std.fmt.parseInt(u32, std.mem.trim(u8, rest, " \t\r\n"), 0) catch return error.BadArgs;
            const cur = loc[self.cur];
            const pad = if (n == 0) 0 else (n - (cur % n)) % n;
            try self.pending.append(.{ .kind = .space, .sec = self.cur, .off = cur, .n = pad });
            loc[self.cur] += pad;
            return;
        }
        if (std.mem.eql(u8, d, ".word")) {
            const items = try splitArgs(self.a, rest);
            try self.pending.append(.{ .kind = .word, .sec = self.cur, .off = loc[self.cur], .items = items });
            loc[self.cur] += 4 * @as(u32, @intCast(items.len));
            return;
        }
        if (std.mem.eql(u8, d, ".byte")) {
            const items = try splitArgs(self.a, rest);
            try self.pending.append(.{ .kind = .byte, .sec = self.cur, .off = loc[self.cur], .items = items });
            loc[self.cur] += @intCast(items.len);
            return;
        }
        if (std.mem.eql(u8, d, ".asciz") or std.mem.eql(u8, d, ".ascii") or std.mem.eql(u8, d, ".string")) {
            const s = std.mem.trim(u8, rest, " \t\r\n");
            if (s.len < 2 or s[0] != '"' or s[s.len - 1] != '"') return error.BadString;
            var data = try unescape(self.a, s[1 .. s.len - 1]);
            if (std.mem.eql(u8, d, ".asciz") or std.mem.eql(u8, d, ".string")) {
                const nd = try self.a.alloc(u8, data.len + 1);
                @memcpy(nd[0..data.len], data);
                nd[data.len] = 0;
                data = nd;
            }
            try self.pending.append(.{ .kind = .raw, .sec = self.cur, .off = loc[self.cur], .data = data });
            loc[self.cur] += @intCast(data.len);
            return;
        }
        if (std.mem.eql(u8, d, ".space") or std.mem.eql(u8, d, ".skip")) {
            const n = std.fmt.parseInt(u32, std.mem.trim(u8, rest, " \t\r\n"), 0) catch return error.BadArgs;
            try self.pending.append(.{ .kind = .space, .sec = self.cur, .off = loc[self.cur], .n = n });
            loc[self.cur] += n;
            return;
        }
        if (std.mem.eql(u8, d, ".entry")) {
            self.entry_label = std.mem.trim(u8, rest, " \t\r\n");
            return;
        }
        return error.UnknownDirective;
    }

    fn emit(self: *Assembler) Error!void {
        for (self.pending.items) |p| {
            var buf = &self.sections[p.sec];
            while (buf.items.len < p.off) try buf.append(0);
            switch (p.kind) {
                .label => {},
                .space => {
                    var i: u32 = 0;
                    while (i < p.n) : (i += 1) try buf.append(0);
                },
                .raw => try buf.appendSlice(p.data),
                .byte => {
                    for (p.items) |it| try buf.append(@truncate(mask32(try self.evalImm(it, false)) & 0xFF));
                },
                .word => {
                    var wa = self.sec_base[p.sec] + p.off;
                    for (p.items) |it| {
                        const v = mask32(try self.evalImm(it, false));
                        if (self.isSym(it)) try self.relocs.append(.{ .vaddr = wa, .typ = 2, .addend = v });
                        try appendLE32(buf, v);
                        wa += 4;
                    }
                },
                .insn => {
                    const addr = self.sec_base[p.sec] + p.off;
                    if (std.mem.eql(u8, p.mnem, "li") and p.args.len >= 2 and self.isSym(p.args[1])) {
                        try self.relocs.append(.{ .vaddr = addr, .typ = 1, .addend = mask32(try self.evalImm(p.args[1], false)) });
                    }
                    const enc = try self.encode(p.mnem, p.args, addr);
                    var k: usize = 0;
                    while (k < enc.n) : (k += 1) try appendLE32(buf, enc.w[k]);
                },
            }
        }
    }

    const Enc = struct { w: [2]u32, n: u8 };

    fn encode(self: *Assembler, mnem: []const u8, args: [][]const u8, addr: u32) Error!Enc {
        if (std.mem.eql(u8, mnem, "nop")) return .{ .w = .{ isa.encR(isa.ADD, 0, 0, 0), 0 }, .n = 1 };
        if (std.mem.eql(u8, mnem, "mov")) {
            if (args.len < 2) return error.BadArgs;
            return .{ .w = .{ isa.encR(isa.ADD, try parseReg(args[0]), try parseReg(args[1]), 0), 0 }, .n = 1 };
        }
        if (std.mem.eql(u8, mnem, "li")) {
            if (args.len < 2) return error.BadArgs;
            const rd = try parseReg(args[0]);
            const imm = mask32(try self.evalImm(args[1], false));
            return .{ .w = .{
                isa.encI(isa.LUI, rd, 0, @truncate(imm >> 16)),
                isa.encI(isa.ORI, rd, rd, @truncate(imm & 0xFFFF)),
            }, .n = 2 };
        }
        if (std.mem.eql(u8, mnem, "push")) {
            const r = try parseReg(args[0]);
            return .{ .w = .{
                isa.encI(isa.ADDI, 13, 13, @truncate(mask32(-4) & 0xFFFF)),
                isa.encI(isa.SW, r, 13, 0),
            }, .n = 2 };
        }
        if (std.mem.eql(u8, mnem, "pop")) {
            const r = try parseReg(args[0]);
            return .{ .w = .{
                isa.encI(isa.LW, r, 13, 0),
                isa.encI(isa.ADDI, 13, 13, 4),
            }, .n = 2 };
        }
        if (std.mem.eql(u8, mnem, "j")) {
            const off = (try self.evalImm(args[0], false)) - @as(i64, addr);
            return .{ .w = .{ isa.encJ(isa.BRA, @intCast(@as(u64, @bitCast(off >> 2)) & 0x1FFFFFF)), 0 }, .n = 1 };
        }

        const info = isa.lookup(mnem) orelse return error.UnknownInstruction;
        const op = info.code;
        switch (info.fmt) {
            .r => {
                if (std.mem.eql(u8, mnem, "cmp") or std.mem.eql(u8, mnem, "tst")) {
                    return .{ .w = .{ isa.encR(op, 0, try parseReg(args[0]), try parseReg(args[1])), 0 }, .n = 1 };
                }
                if (args.len < 3) return error.BadArgs;
                return .{ .w = .{ isa.encR(op, try parseReg(args[0]), try parseReg(args[1]), try parseReg(args[2])), 0 }, .n = 1 };
            },
            .i => {
                if (std.mem.eql(u8, mnem, "lui")) {
                    return .{ .w = .{ isa.encI(op, try parseReg(args[0]), 0, @truncate(mask32(try self.evalImm(args[1], false)) & 0xFFFF)), 0 }, .n = 1 };
                }
                if (std.mem.eql(u8, mnem, "cmpi")) {
                    return .{ .w = .{ isa.encI(op, 0, try parseReg(args[0]), @truncate(mask32(try self.evalImm(args[1], false)) & 0xFFFF)), 0 }, .n = 1 };
                }
                if (args.len < 3) return error.BadArgs;
                return .{ .w = .{ isa.encI(op, try parseReg(args[0]), try parseReg(args[1]), @truncate(mask32(try self.evalImm(args[2], false)) & 0xFFFF)), 0 }, .n = 1 };
            },
            .ld, .st => {
                const rd = try parseReg(args[0]);
                const m = try parseMem(self, args[1]);
                return .{ .w = .{ isa.encI(op, rd, m.base, @truncate(mask32(m.imm) & 0xFFFF)), 0 }, .n = 1 };
            },
            .j => {
                const off = (try self.evalImm(args[0], false)) - @as(i64, addr);
                return .{ .w = .{ isa.encJ(op, @intCast(@as(u64, @bitCast(off >> 2)) & 0x1FFFFFF)), 0 }, .n = 1 };
            },
            .reg => return .{ .w = .{ isa.encReg(op, try parseReg(args[0])), 0 }, .n = 1 },
            .non => return .{ .w = .{ @as(u32, op) << 25, 0 }, .n = 1 },
        }
    }

    fn buildTbx(self: *Assembler, gpa: std.mem.Allocator) Error![]u8 {
        const entry: u32 = if (self.labels.get(self.entry_label)) |v| mask32(v) else isa.TEXT_BASE;
        const mem_size: u32 = 1 << 20;

        var strtab = std.ArrayList(u8).init(self.a);
        try strtab.append(0);
        const add_str = struct {
            fn f(st: *std.ArrayList(u8), name: []const u8) !u32 {
                const off: u32 = @intCast(st.items.len);
                try st.appendSlice(name);
                try st.append(0);
                return off;
            }
        }.f;

        const SecRec = struct { s: usize, vaddr: u32, data: []const u8 };
        var sec_records = std.ArrayList(SecRec).init(self.a);
        for (0..4) |s| {
            const data = self.sections[s].items;
            if (data.len == 0 and s != 0) continue;
            try sec_records.append(.{ .s = s, .vaddr = self.sec_base[s], .data = data });
        }

        const order = try self.a.dupe(LabelEntry, self.label_order.items);
        std.sort.insertion(LabelEntry, order, {}, struct {
            fn lt(_: void, a: LabelEntry, b: LabelEntry) bool {
                return a.value < b.value;
            }
        }.lt);
        var symtab = std.ArrayList(u8).init(self.a);
        for (order) |e| {
            const noff = try add_str(&strtab, e.name);
            try appendLE32(&symtab, noff);
            try appendLE32(&symtab, mask32(e.value));
            try symtab.append(1);
            try appendLE16(&symtab, 0);
            try symtab.append(0);
        }

        var rela = std.ArrayList(u8).init(self.a);
        for (self.relocs.items) |r| {
            try appendLE32(&rela, r.vaddr);
            try appendLE32(&rela, r.typ);
            try appendLE32(&rela, r.addend);
        }

        const Hdr = struct { noff: u32, typ: u16, flags: u16, vaddr: u32, off: u32, size: u32 };
        var headers = std.ArrayList(Hdr).init(self.a);
        var blobs = std.ArrayList(u8).init(self.a);
        const sh_off: u32 = 32;
        const sh_entsize: u32 = 20;
        const n_sh: u32 = @intCast(sec_records.items.len + 3);
        var cursor: u32 = sh_off + n_sh * sh_entsize;
        for (sec_records.items) |rec| {
            const noff = try add_str(&strtab, SEC_ORDER[rec.s]);
            const typ = SEC_TYPE[rec.s];
            const off: u32 = if (typ == 1) cursor else 0;
            try headers.append(.{ .noff = noff, .typ = typ, .flags = 0, .vaddr = rec.vaddr, .off = off, .size = @intCast(rec.data.len) });
            if (typ == 1) {
                try blobs.appendSlice(rec.data);
                cursor += @intCast(rec.data.len);
            }
        }
        const sym_off = cursor;
        try headers.append(.{ .noff = try add_str(&strtab, ".symtab"), .typ = 3, .flags = 0, .vaddr = 0, .off = sym_off, .size = @intCast(symtab.items.len) });
        try blobs.appendSlice(symtab.items);
        cursor += @intCast(symtab.items.len);
        const str_off = cursor;
        const str_noff = try add_str(&strtab, ".strtab");
        try headers.append(.{ .noff = str_noff, .typ = 4, .flags = 0, .vaddr = 0, .off = str_off, .size = @intCast(strtab.items.len) });
        try blobs.appendSlice(strtab.items);
        cursor += @intCast(strtab.items.len);
        const rela_off = cursor;
        try headers.append(.{ .noff = try add_str(&strtab, ".rela"), .typ = 5, .flags = 0, .vaddr = 0, .off = rela_off, .size = @intCast(rela.items.len) });
        try blobs.appendSlice(rela.items);
        cursor += @intCast(rela.items.len);

        var out = std.ArrayList(u8).init(gpa);
        errdefer out.deinit();
        try out.appendSlice("TBX\x7f");
        try appendLE16(&out, 1);
        try appendLE16(&out, 0);
        try appendLE32(&out, entry);
        try appendLE32(&out, mem_size);
        try appendLE32(&out, sh_off);
        try appendLE16(&out, @intCast(n_sh));
        try appendLE16(&out, @intCast(sh_entsize));
        try appendLE32(&out, 0);
        try appendLE32(&out, 0);
        for (headers.items) |h| {
            try appendLE32(&out, h.noff);
            try appendLE16(&out, h.typ);
            try appendLE16(&out, h.flags);
            try appendLE32(&out, h.vaddr);
            try appendLE32(&out, h.off);
            try appendLE32(&out, h.size);
        }
        try out.appendSlice(blobs.items);
        const crc = std.hash.crc.Crc32IsoHdlc.hash(out.items[32..]);
        out.items[28] = @truncate(crc);
        out.items[29] = @truncate(crc >> 8);
        out.items[30] = @truncate(crc >> 16);
        out.items[31] = @truncate(crc >> 24);
        return out.toOwnedSlice();
    }
};

const Mem = struct { base: u4, imm: i64 };
fn parseMem(asm_: *Assembler, tok_in: []const u8) Error!Mem {
    var tok = std.mem.trim(u8, tok_in, " \t\r\n");
    if (tok.len > 0 and tok[0] == '[') tok = tok[1..];
    if (tok.len > 0 and tok[tok.len - 1] == ']') tok = tok[0 .. tok.len - 1];
    tok = std.mem.trim(u8, tok, " \t\r\n");
    if (std.mem.indexOfScalar(u8, tok, ',')) |c| {
        const base = try parseReg(std.mem.trim(u8, tok[0..c], " \t\r\n"));
        const imm = try asm_.evalImm(std.mem.trim(u8, tok[c + 1 ..], " \t\r\n"), false);
        return .{ .base = base, .imm = imm };
    }
    return .{ .base = try parseReg(tok), .imm = 0 };
}

fn stripComment(line: []const u8) []const u8 {
    var in_str = false;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c == '"') {
            in_str = !in_str;
        } else if (!in_str and (c == ';' or c == '#')) {
            return line[0..i];
        } else if (!in_str and c == '/' and i + 1 < line.len and line[i + 1] == '/') {
            return line[0..i];
        }
    }
    return line;
}

fn labelPrefix(line: []const u8) ?usize {
    if (line.len == 0) return null;
    if (!(std.ascii.isAlphabetic(line[0]) or line[0] == '_' or line[0] == '.' or line[0] == '$')) return null;
    var i: usize = 1;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c == ':') return i;
        if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '.' or c == '$')) return null;
    }
    return null;
}

fn lowerDup(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    const buf = try a.alloc(u8, s.len);
    for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf;
}

fn splitArgs(a: std.mem.Allocator, s: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(a);
    var in_str = false;
    var depth: i32 = 0;
    var start: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '"') {
            in_str = !in_str;
        } else if (c == ',' and !in_str and depth == 0) {
            const seg = std.mem.trim(u8, s[start..i], " \t\r\n");
            try out.append(seg);
            start = i + 1;
        } else if (c == '(' or c == '[') {
            depth += 1;
        } else if (c == ')' or c == ']') {
            depth -= 1;
        }
    }
    const last = std.mem.trim(u8, s[start..], " \t\r\n");
    if (last.len > 0) try out.append(last);
    return out.toOwnedSlice();
}

fn unescape(a: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(a);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] != '\\') {
            try out.append(s[i]);
            i += 1;
            continue;
        }
        if (i + 1 >= s.len) {
            try out.append('\\');
            i += 1;
            continue;
        }
        const c = s[i + 1];
        switch (c) {
            'n' => {
                try out.append('\n');
                i += 2;
            },
            't' => {
                try out.append('\t');
                i += 2;
            },
            'r' => {
                try out.append('\r');
                i += 2;
            },
            '\\' => {
                try out.append('\\');
                i += 2;
            },
            '"' => {
                try out.append('"');
                i += 2;
            },
            '\'' => {
                try out.append('\'');
                i += 2;
            },
            '0'...'7' => {
                var j: usize = i + 1;
                var val: u32 = 0;
                var count: usize = 0;
                while (j < s.len and count < 3 and s[j] >= '0' and s[j] <= '7') : (j += 1) {
                    val = val * 8 + (s[j] - '0');
                    count += 1;
                }
                try out.append(@truncate(val));
                i = j;
            },
            'a' => {
                try out.append(7);
                i += 2;
            },
            'b' => {
                try out.append(8);
                i += 2;
            },
            'f' => {
                try out.append(12);
                i += 2;
            },
            'v' => {
                try out.append(11);
                i += 2;
            },
            'x' => {
                if (i + 3 < s.len + 1 and i + 3 <= s.len and isHex(s[i + 2]) and isHex(s[i + 3])) {
                    try out.append((hexVal(s[i + 2]) << 4) | hexVal(s[i + 3]));
                    i += 4;
                } else {
                    try out.append('\\');
                    i += 1;
                }
            },
            else => {
                try out.append('\\');
                i += 1;
            },
        }
    }
    return out.toOwnedSlice();
}

fn isHex(c: u8) bool {
    return std.ascii.isHex(c);
}
fn hexVal(c: u8) u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    return c - 'A' + 10;
}

/// Assembles TB32 source into a TBX object. Caller owns the returned bytes; free with `gpa.free`.
pub fn assemble(gpa: std.mem.Allocator, src: []const u8) Error![]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var asm_ = Assembler.init(arena.allocator());
    try asm_.layout(src);
    try asm_.emit();
    return asm_.buildTbx(gpa);
}

test "assembles and round-trips a small program" {
    const gpa = std.testing.allocator;
    const src =
        ".text\n_start:\nli r1, 5\nli r2, 37\nadd r3, r1, r2\nhlt\n";
    const tbx = try assemble(gpa, src);
    defer gpa.free(tbx);
    try std.testing.expect(tbx.len > 32);
    try std.testing.expectEqualSlices(u8, "TBX\x7f", tbx[0..4]);
}
