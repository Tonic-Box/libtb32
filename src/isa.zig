//! TB32 opcodes and instruction encoding.

const std = @import("std");

/// The four TB32 instruction encoding formats. `ld` and `st` are I-form variants
/// distinguished only by operand syntax.
pub const Fmt = enum { r, i, ld, st, j, reg, non };

pub const ADD: u7 = 0x10;
pub const SUB: u7 = 0x11;
pub const AND: u7 = 0x12;
pub const OR: u7 = 0x13;
pub const XOR: u7 = 0x14;
pub const SLL: u7 = 0x15;
pub const SRL: u7 = 0x16;
pub const SRA: u7 = 0x17;
pub const SLT: u7 = 0x18;
pub const SLTU: u7 = 0x19;
pub const MUL: u7 = 0x1A;
pub const DIVU: u7 = 0x1B;
pub const REMU: u7 = 0x1C;
pub const CMP: u7 = 0x1D;
pub const TST: u7 = 0x1E;
pub const DIV: u7 = 0x1F;
pub const ADDI: u7 = 0x20;
pub const ANDI: u7 = 0x21;
pub const ORI: u7 = 0x22;
pub const XORI: u7 = 0x23;
pub const SLLI: u7 = 0x24;
pub const SRLI: u7 = 0x25;
pub const SRAI: u7 = 0x26;
pub const SLTI: u7 = 0x27;
pub const SLTIU: u7 = 0x28;
pub const LUI: u7 = 0x29;
pub const CMPI: u7 = 0x2A;
pub const REM: u7 = 0x2B;
pub const LB: u7 = 0x30;
pub const LBU: u7 = 0x31;
pub const LH: u7 = 0x32;
pub const LHU: u7 = 0x33;
pub const LW: u7 = 0x34;
pub const SB: u7 = 0x38;
pub const SH: u7 = 0x39;
pub const SW: u7 = 0x3A;
pub const BRA: u7 = 0x40;
pub const BEQ: u7 = 0x41;
pub const BNE: u7 = 0x42;
pub const BLT: u7 = 0x43;
pub const BGE: u7 = 0x44;
pub const BLTU: u7 = 0x45;
pub const BGEU: u7 = 0x46;
pub const CALL: u7 = 0x48;
pub const CALLR: u7 = 0x49;
pub const RET: u7 = 0x4A;
pub const JMP: u7 = 0x4B;
pub const SYS: u7 = 0x50;
pub const HLT: u7 = 0x51;
pub const BRK: u7 = 0x52;

/// Link-time base address of the `.text` section.
pub const TEXT_BASE: u32 = 0x1000;

/// A mnemonic with its opcode and encoding format.
pub const OpInfo = struct { name: []const u8, code: u7, fmt: Fmt };

/// The instruction mnemonic table. Pseudo-ops are handled by the assembler.
pub const OPS = [_]OpInfo{
    .{ .name = "add", .code = ADD, .fmt = .r },
    .{ .name = "sub", .code = SUB, .fmt = .r },
    .{ .name = "and", .code = AND, .fmt = .r },
    .{ .name = "or", .code = OR, .fmt = .r },
    .{ .name = "xor", .code = XOR, .fmt = .r },
    .{ .name = "sll", .code = SLL, .fmt = .r },
    .{ .name = "srl", .code = SRL, .fmt = .r },
    .{ .name = "sra", .code = SRA, .fmt = .r },
    .{ .name = "slt", .code = SLT, .fmt = .r },
    .{ .name = "sltu", .code = SLTU, .fmt = .r },
    .{ .name = "mul", .code = MUL, .fmt = .r },
    .{ .name = "divu", .code = DIVU, .fmt = .r },
    .{ .name = "remu", .code = REMU, .fmt = .r },
    .{ .name = "cmp", .code = CMP, .fmt = .r },
    .{ .name = "tst", .code = TST, .fmt = .r },
    .{ .name = "div", .code = DIV, .fmt = .r },
    .{ .name = "rem", .code = REM, .fmt = .r },
    .{ .name = "addi", .code = ADDI, .fmt = .i },
    .{ .name = "andi", .code = ANDI, .fmt = .i },
    .{ .name = "ori", .code = ORI, .fmt = .i },
    .{ .name = "xori", .code = XORI, .fmt = .i },
    .{ .name = "slli", .code = SLLI, .fmt = .i },
    .{ .name = "srli", .code = SRLI, .fmt = .i },
    .{ .name = "srai", .code = SRAI, .fmt = .i },
    .{ .name = "slti", .code = SLTI, .fmt = .i },
    .{ .name = "sltiu", .code = SLTIU, .fmt = .i },
    .{ .name = "lui", .code = LUI, .fmt = .i },
    .{ .name = "cmpi", .code = CMPI, .fmt = .i },
    .{ .name = "lb", .code = LB, .fmt = .ld },
    .{ .name = "lbu", .code = LBU, .fmt = .ld },
    .{ .name = "lh", .code = LH, .fmt = .ld },
    .{ .name = "lhu", .code = LHU, .fmt = .ld },
    .{ .name = "lw", .code = LW, .fmt = .ld },
    .{ .name = "sb", .code = SB, .fmt = .st },
    .{ .name = "sh", .code = SH, .fmt = .st },
    .{ .name = "sw", .code = SW, .fmt = .st },
    .{ .name = "bra", .code = BRA, .fmt = .j },
    .{ .name = "beq", .code = BEQ, .fmt = .j },
    .{ .name = "bne", .code = BNE, .fmt = .j },
    .{ .name = "blt", .code = BLT, .fmt = .j },
    .{ .name = "bge", .code = BGE, .fmt = .j },
    .{ .name = "bltu", .code = BLTU, .fmt = .j },
    .{ .name = "bgeu", .code = BGEU, .fmt = .j },
    .{ .name = "call", .code = CALL, .fmt = .j },
    .{ .name = "callr", .code = CALLR, .fmt = .reg },
    .{ .name = "jmp", .code = JMP, .fmt = .reg },
    .{ .name = "ret", .code = RET, .fmt = .non },
    .{ .name = "sys", .code = SYS, .fmt = .non },
    .{ .name = "hlt", .code = HLT, .fmt = .non },
    .{ .name = "brk", .code = BRK, .fmt = .non },
};

/// Looks up a mnemonic's opcode and format; null if unknown.
pub fn lookup(name: []const u8) ?OpInfo {
    for (OPS) |o| {
        if (std.mem.eql(u8, o.name, name)) return o;
    }
    return null;
}

/// The mnemonic for `code`; null if unknown.
pub fn mnemonic(code: u7) ?[]const u8 {
    for (OPS) |o| {
        if (o.code == code) return o.name;
    }
    return null;
}

/// The encoding format for `code`; null if unknown.
pub fn fmtOf(code: u7) ?Fmt {
    for (OPS) |o| {
        if (o.code == code) return o.fmt;
    }
    return null;
}

/// The name (`r0`..`r15`) of register `r`.
pub fn regName(r: u4) []const u8 {
    return ([_][]const u8{
        "r0", "r1", "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    })[r];
}

/// Sign-extends a 16-bit immediate to 32 bits.
pub fn signext16(imm: u16) u32 {
    return @bitCast(@as(i32, @as(i16, @bitCast(imm))));
}

/// Sign-extends the 25-bit J-form immediate carried in the low bits of `word`.
pub fn signext25(word: u32) i32 {
    const v: u32 = word & 0x1FFFFFF;
    if (v & 0x1000000 != 0) return @bitCast(v | 0xFE000000);
    return @bitCast(v);
}

/// The decoded fields of an instruction word.
pub const Decoded = struct {
    op: u7,
    rd: u4,
    rs1: u4,
    rs2: u4,
    imm16: u16,
    word: u32,
};

/// Decodes an instruction word into its fields.
pub fn decode(word: u32) Decoded {
    return .{
        .op = @truncate(word >> 25),
        .rd = @truncate(word >> 21),
        .rs1 = @truncate(word >> 17),
        .rs2 = @truncate(word >> 13),
        .imm16 = @truncate(word >> 1),
        .word = word,
    };
}

/// Encodes an R-format instruction word.
pub fn encR(op: u7, rd: u4, rs1: u4, rs2: u4) u32 {
    return (@as(u32, op) << 25) | (@as(u32, rd) << 21) | (@as(u32, rs1) << 17) | (@as(u32, rs2) << 13);
}

/// Encodes an I-format instruction word.
pub fn encI(op: u7, rd: u4, rs1: u4, imm: u16) u32 {
    return (@as(u32, op) << 25) | (@as(u32, rd) << 21) | (@as(u32, rs1) << 17) | (@as(u32, imm) << 1);
}

/// Encodes a J-format instruction word.
pub fn encJ(op: u7, imm25: u32) u32 {
    return (@as(u32, op) << 25) | (imm25 & 0x1FFFFFF);
}

/// Encodes a REG-format instruction word.
pub fn encReg(op: u7, rs1: u4) u32 {
    return (@as(u32, op) << 25) | (@as(u32, rs1) << 17);
}

test "encode/decode round-trip" {
    const w = encR(ADD, 3, 1, 2);
    const d = decode(w);
    try std.testing.expectEqual(ADD, d.op);
    try std.testing.expectEqual(@as(u4, 3), d.rd);
    try std.testing.expectEqual(@as(u4, 1), d.rs1);
    try std.testing.expectEqual(@as(u4, 2), d.rs2);

    const wi = encI(ADDI, 5, 5, @bitCast(@as(i16, -4)));
    const di = decode(wi);
    try std.testing.expectEqual(ADDI, di.op);
    try std.testing.expectEqual(@as(u32, @bitCast(@as(i32, -4))), signext16(di.imm16));
}
