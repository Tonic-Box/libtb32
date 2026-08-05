//! Single-instruction TB32 disassembler.

const std = @import("std");
const isa = @import("isa.zig");

/// Renders one instruction word as assembly text into `buf` (64 bytes suffices) and
/// returns the used slice. `addr` is the instruction's own address, used to resolve
/// relative branch targets.
pub fn disasm(word: u32, addr: u32, buf: []u8) []const u8 {
    const d = isa.decode(word);
    const info = for (isa.OPS) |o| {
        if (o.code == d.op) break o;
    } else return std.fmt.bufPrint(buf, ".word 0x{x:0>8}", .{word}) catch buf[0..0];

    const rd = isa.regName(d.rd);
    const rs1 = isa.regName(d.rs1);
    const rs2 = isa.regName(d.rs2);
    const simm: i32 = @bitCast(isa.signext16(d.imm16));

    const s = switch (info.fmt) {
        .r => if (d.op == isa.CMP or d.op == isa.TST)
            std.fmt.bufPrint(buf, "{s} {s}, {s}", .{ info.name, rs1, rs2 })
        else
            std.fmt.bufPrint(buf, "{s} {s}, {s}, {s}", .{ info.name, rd, rs1, rs2 }),
        .i => if (d.op == isa.LUI)
            std.fmt.bufPrint(buf, "{s} {s}, 0x{x}", .{ info.name, rd, d.imm16 })
        else if (d.op == isa.CMPI)
            std.fmt.bufPrint(buf, "{s} {s}, {d}", .{ info.name, rs1, simm })
        else
            std.fmt.bufPrint(buf, "{s} {s}, {s}, {d}", .{ info.name, rd, rs1, simm }),
        .ld => std.fmt.bufPrint(buf, "{s} {s}, [{s}, {d}]", .{ info.name, rd, rs1, simm }),
        .st => std.fmt.bufPrint(buf, "{s} {s}, [{s}, {d}]", .{ info.name, rd, rs1, simm }),
        .j => blk: {
            const target = addr +% @as(u32, @bitCast(isa.signext25(word) *% 4));
            break :blk std.fmt.bufPrint(buf, "{s} 0x{x}", .{ info.name, target });
        },
        .reg => std.fmt.bufPrint(buf, "{s} {s}", .{ info.name, rs1 }),
        .non => std.fmt.bufPrint(buf, "{s}", .{info.name}),
        .csr_r => std.fmt.bufPrint(buf, "{s} {s}, 0x{x}", .{ info.name, rd, d.imm16 }),
        .csr_w => std.fmt.bufPrint(buf, "{s} 0x{x}, {s}", .{ info.name, d.imm16, rs1 }),
    };
    return s catch buf[0..0];
}

test "disassembles common forms" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("add r3, r1, r2", disasm(isa.encR(isa.ADD, 3, 1, 2), 0, &buf));
    try std.testing.expectEqualStrings("addi r5, r5, -4", disasm(isa.encI(isa.ADDI, 5, 5, @bitCast(@as(i16, -4))), 0, &buf));
    try std.testing.expectEqualStrings("lw r1, [r13, 0]", disasm(isa.encI(isa.LW, 1, 13, 0), 0, &buf));
    try std.testing.expectEqualStrings("ret", disasm(@as(u32, isa.RET) << 25, 0, &buf));
    try std.testing.expectEqualStrings("bra 0x1008", disasm(isa.encJ(isa.BRA, (8 >> 2)), 0x1000, &buf));
    try std.testing.expectEqualStrings("csrr r3, 0x142", disasm(isa.encI(isa.CSRR, 3, 0, 0x142), 0, &buf));
    try std.testing.expectEqualStrings("csrw 0x680, r1", disasm(isa.encI(isa.CSRW, 0, 1, 0x680), 0, &buf));
    try std.testing.expectEqualStrings("sret", disasm(@as(u32, isa.SRET) << 25, 0, &buf));
    try std.testing.expectEqualStrings("hret", disasm(@as(u32, isa.HRET) << 25, 0, &buf));
}
