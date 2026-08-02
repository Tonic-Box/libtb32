//! The TB32 CPU: register and flag state with a host-agnostic single-instruction executor.

const std = @import("std");
const isa = @import("isa.zig");

/// Condition flags. `c` is the unsigned no-borrow bit; `v` is signed overflow.
pub const Flags = struct {
    z: bool = false,
    n: bool = false,
    c: bool = false,
    v: bool = false,
};

/// Why `step` returned. `ok` retired an instruction; `syscall`/`halt`/`breakpoint`
/// came from `sys`/`hlt`/`brk`; `fault` leaves the code in `cpu.trap`.
pub const Stop = enum {
    ok,
    syscall,
    halt,
    breakpoint,
    fault,
};

/// Misaligned instruction fetch.
pub const FAULT_ALIGN: u32 = 1;
/// Out-of-range or rejected data access.
pub const FAULT_MEM: u32 = 2;
/// Illegal or unknown opcode.
pub const FAULT_OPCODE: u32 = 3;
/// Divide by zero.
pub const FAULT_DIV0: u32 = 4;

/// The CPU state: 16 registers, program counter, and flags. After a `.fault`, `trap`
/// holds the fault code and `insn_pc` the address of the faulting instruction.
pub const Cpu = struct {
    r: [16]u32 = [_]u32{0} ** 16,
    pc: u32 = 0,
    f: Flags = .{},
    trap: u32 = 0,
    insn_pc: u32 = 0,

    fn setReg(self: *Cpu, rd: u4, v: u32) void {
        if (rd != 0) self.r[rd] = v;
    }

    fn setFlagsSub(self: *Cpu, a: u32, b: u32) void {
        const diff = a -% b;
        self.f.z = (a == b);
        self.f.n = (diff >> 31) != 0;
        self.f.c = (a >= b);
        const sa = (a >> 31) & 1;
        const sb = (b >> 31) & 1;
        const sd = (diff >> 31) & 1;
        self.f.v = (sa != sb) and (sa != sd);
    }
};

inline fn busRead16(bus: anytype, a: u32) ?u16 {
    if (@hasDecl(@TypeOf(bus.*), "read16")) return bus.read16(a);
    const b0 = bus.read8(a) orelse return null;
    const b1 = bus.read8(a +% 1) orelse return null;
    return @as(u16, b0) | (@as(u16, b1) << 8);
}
inline fn busRead32(bus: anytype, a: u32) ?u32 {
    if (@hasDecl(@TypeOf(bus.*), "read32")) return bus.read32(a);
    var v: u32 = 0;
    inline for (0..4) |i| {
        const b = bus.read8(a +% @as(u32, i)) orelse return null;
        v |= @as(u32, b) << @as(u5, @intCast(i * 8));
    }
    return v;
}
inline fn busWrite16(bus: anytype, a: u32, v: u16) bool {
    if (@hasDecl(@TypeOf(bus.*), "write16")) return bus.write16(a, v);
    if (!bus.write8(a, @truncate(v))) return false;
    return bus.write8(a +% 1, @truncate(v >> 8));
}
inline fn busWrite32(bus: anytype, a: u32, v: u32) bool {
    if (@hasDecl(@TypeOf(bus.*), "write32")) return bus.write32(a, v);
    inline for (0..4) |i| {
        if (!bus.write8(a +% @as(u32, i), @truncate(v >> @as(u5, @intCast(i * 8))))) return false;
    }
    return true;
}

/// Executes one instruction at `cpu.pc` against `bus` and returns why it stopped.
/// `bus` is any type with `read8(u32) ?u8` and `write8(u32, u8) bool` (null/false mean
/// access fault); optional `read16`/`read32`/`write16`/`write32` are used when present.
/// On a `.fault` return the code is in `cpu.trap`. Kept `inline` so a host interpreter
/// loop pays no call overhead.
pub inline fn step(cpu: *Cpu, bus: anytype) Stop {
    if (cpu.pc & 3 != 0) {
        cpu.trap = FAULT_ALIGN;
        return .fault;
    }
    const ipc = cpu.pc;
    cpu.insn_pc = ipc;
    const word = busRead32(bus, ipc) orelse {
        cpu.trap = FAULT_MEM;
        return .fault;
    };
    const d = isa.decode(word);
    const a = cpu.r[d.rs1];
    const b = cpu.r[d.rs2];
    const si = isa.signext16(d.imm16);
    const boff: u32 = @bitCast(isa.signext25(word) *% 4);
    cpu.pc = ipc +% 4;
    switch (d.op) {
        isa.ADD => cpu.setReg(d.rd, a +% b),
        isa.SUB => cpu.setReg(d.rd, a -% b),
        isa.AND => cpu.setReg(d.rd, a & b),
        isa.OR => cpu.setReg(d.rd, a | b),
        isa.XOR => cpu.setReg(d.rd, a ^ b),
        isa.SLL => cpu.setReg(d.rd, a << @as(u5, @truncate(b & 31))),
        isa.SRL => cpu.setReg(d.rd, a >> @as(u5, @truncate(b & 31))),
        isa.SRA => cpu.setReg(d.rd, @bitCast(@as(i32, @bitCast(a)) >> @as(u5, @truncate(b & 31)))),
        isa.SLT => cpu.setReg(d.rd, if (@as(i32, @bitCast(a)) < @as(i32, @bitCast(b))) 1 else 0),
        isa.SLTU => cpu.setReg(d.rd, if (a < b) 1 else 0),
        isa.MUL => cpu.setReg(d.rd, a *% b),
        isa.DIVU => {
            if (b == 0) {
                cpu.trap = FAULT_DIV0;
                return .fault;
            }
            cpu.setReg(d.rd, a / b);
        },
        isa.REMU => {
            if (b == 0) {
                cpu.trap = FAULT_DIV0;
                return .fault;
            }
            cpu.setReg(d.rd, a % b);
        },
        isa.DIV => {
            if (b == 0) {
                cpu.trap = FAULT_DIV0;
                return .fault;
            } else if (a == 0x80000000 and b == 0xFFFFFFFF) {
                cpu.setReg(d.rd, a);
            } else {
                cpu.setReg(d.rd, @bitCast(@divTrunc(@as(i32, @bitCast(a)), @as(i32, @bitCast(b)))));
            }
        },
        isa.REM => {
            if (b == 0) {
                cpu.trap = FAULT_DIV0;
                return .fault;
            } else if (a == 0x80000000 and b == 0xFFFFFFFF) {
                cpu.setReg(d.rd, 0);
            } else {
                cpu.setReg(d.rd, @bitCast(@rem(@as(i32, @bitCast(a)), @as(i32, @bitCast(b)))));
            }
        },
        isa.CMP => cpu.setFlagsSub(a, b),
        isa.TST => {
            const r = a & b;
            cpu.f.z = (r == 0);
            cpu.f.n = (r >> 31) != 0;
        },
        isa.ADDI => cpu.setReg(d.rd, a +% si),
        isa.ANDI => cpu.setReg(d.rd, a & @as(u32, d.imm16)),
        isa.ORI => cpu.setReg(d.rd, a | @as(u32, d.imm16)),
        isa.XORI => cpu.setReg(d.rd, a ^ @as(u32, d.imm16)),
        isa.SLLI => cpu.setReg(d.rd, a << @as(u5, @truncate(d.imm16 & 31))),
        isa.SRLI => cpu.setReg(d.rd, a >> @as(u5, @truncate(d.imm16 & 31))),
        isa.SRAI => cpu.setReg(d.rd, @bitCast(@as(i32, @bitCast(a)) >> @as(u5, @truncate(d.imm16 & 31)))),
        isa.SLTI => cpu.setReg(d.rd, if (@as(i32, @bitCast(a)) < @as(i32, @bitCast(si))) 1 else 0),
        isa.SLTIU => cpu.setReg(d.rd, if (a < si) 1 else 0),
        isa.LUI => cpu.setReg(d.rd, @as(u32, d.imm16) << 16),
        isa.CMPI => cpu.setFlagsSub(a, si),
        isa.LB => {
            const x = bus.read8(a +% si) orelse {
                cpu.trap = FAULT_MEM;
                return .fault;
            };
            cpu.setReg(d.rd, @bitCast(@as(i32, @as(i8, @bitCast(x)))));
        },
        isa.LBU => {
            const x = bus.read8(a +% si) orelse {
                cpu.trap = FAULT_MEM;
                return .fault;
            };
            cpu.setReg(d.rd, x);
        },
        isa.LH => {
            const x = busRead16(bus, a +% si) orelse {
                cpu.trap = FAULT_MEM;
                return .fault;
            };
            cpu.setReg(d.rd, @bitCast(@as(i32, @as(i16, @bitCast(x)))));
        },
        isa.LHU => {
            const x = busRead16(bus, a +% si) orelse {
                cpu.trap = FAULT_MEM;
                return .fault;
            };
            cpu.setReg(d.rd, x);
        },
        isa.LW => {
            const x = busRead32(bus, a +% si) orelse {
                cpu.trap = FAULT_MEM;
                return .fault;
            };
            cpu.setReg(d.rd, x);
        },
        isa.SB => {
            if (!bus.write8(a +% si, @truncate(cpu.r[d.rd]))) {
                cpu.trap = FAULT_MEM;
                return .fault;
            }
        },
        isa.SH => {
            if (!busWrite16(bus, a +% si, @truncate(cpu.r[d.rd]))) {
                cpu.trap = FAULT_MEM;
                return .fault;
            }
        },
        isa.SW => {
            if (!busWrite32(bus, a +% si, cpu.r[d.rd])) {
                cpu.trap = FAULT_MEM;
                return .fault;
            }
        },
        isa.BRA => cpu.pc = ipc +% boff,
        isa.BEQ => if (cpu.f.z) {
            cpu.pc = ipc +% boff;
        },
        isa.BNE => if (!cpu.f.z) {
            cpu.pc = ipc +% boff;
        },
        isa.BLT => if (cpu.f.n != cpu.f.v) {
            cpu.pc = ipc +% boff;
        },
        isa.BGE => if (cpu.f.n == cpu.f.v) {
            cpu.pc = ipc +% boff;
        },
        isa.BLTU => if (!cpu.f.c) {
            cpu.pc = ipc +% boff;
        },
        isa.BGEU => if (cpu.f.c) {
            cpu.pc = ipc +% boff;
        },
        isa.CALL => {
            cpu.r[15] = ipc +% 4;
            cpu.pc = ipc +% boff;
        },
        isa.CALLR => {
            cpu.r[15] = ipc +% 4;
            cpu.pc = a;
        },
        isa.RET => cpu.pc = cpu.r[15],
        isa.JMP => cpu.pc = a,
        isa.SYS => return .syscall,
        isa.HLT => return .halt,
        isa.BRK => return .breakpoint,
        else => {
            cpu.trap = FAULT_OPCODE;
            return .fault;
        },
    }
    return .ok;
}

test "runs a small program on a flat bus" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 256;
    var bus = FlatBus{ .ram = &ram };

    const prog = [_]u32{
        isa.encI(isa.LUI, 1, 0, 0),
        isa.encI(isa.ORI, 1, 1, 5),
        isa.encI(isa.LUI, 2, 0, 0),
        isa.encI(isa.ORI, 2, 2, 37),
        isa.encR(isa.ADD, 3, 1, 2),
        (@as(u32, isa.HLT) << 25),
    };
    for (prog, 0..) |w, i| {
        _ = busWrite32(&bus, @intCast(i * 4), w);
    }
    var cpu = Cpu{ .pc = 0 };
    var guard: u32 = 0;
    while (guard < 100) : (guard += 1) {
        switch (step(&cpu, &bus)) {
            .ok => {},
            .halt => break,
            else => return error.Unexpected,
        }
    }
    try std.testing.expectEqual(@as(u32, 42), cpu.r[3]);
}
