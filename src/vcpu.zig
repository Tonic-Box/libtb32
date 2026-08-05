//! TB32-V privileged execution: privilege modes, control registers, and traps layered over
//! the base TB32 core as a superset. `stepV` reuses `execOne` for every base instruction and
//! adds mode-aware handling of the privileged opcodes and trap delivery.

const std = @import("std");
const isa = @import("isa.zig");
const base = @import("cpu.zig");

/// Privilege level, least to most privileged.
pub const Mode = enum(u2) { user = 0, supervisor = 1, hypervisor = 2 };

/// Why `stepV` returned. Traps are taken internally (mode change + vector jump); the machine
/// only needs to know when the hart stopped.
pub const VStop = enum { ok, halt, breakpoint };

pub const CAUSE_MISALIGN: u32 = 0;
pub const CAUSE_FETCH_FAULT: u32 = 1;
pub const CAUSE_ILLEGAL: u32 = 2;
pub const CAUSE_BREAK: u32 = 3;
pub const CAUSE_ACCESS_FAULT: u32 = 5;
pub const CAUSE_ECALL_U: u32 = 8;
pub const CAUSE_ECALL_S: u32 = 9;
pub const CAUSE_DIV0: u32 = 16;

pub const CSR_SSTATUS: u16 = 0x100;
pub const CSR_STVEC: u16 = 0x105;
pub const CSR_SSCRATCH: u16 = 0x140;
pub const CSR_SEPC: u16 = 0x141;
pub const CSR_SCAUSE: u16 = 0x142;
pub const CSR_STVAL: u16 = 0x143;

const SSTATUS_SIE: u32 = 1 << 1;
const SSTATUS_SPIE: u32 = 1 << 5;
const SSTATUS_SPP: u32 = 1 << 8;

/// The supervisor control and status registers.
pub const Csr = struct {
    stvec: u32 = 0,
    sepc: u32 = 0,
    scause: u32 = 0,
    stval: u32 = 0,
    sscratch: u32 = 0,
    sie: bool = false,
    spie: bool = false,
    spp: Mode = .user,
};

/// A hardware thread: the base CPU state plus its current privilege mode and CSRs.
pub const Hart = struct {
    cpu: base.Cpu = .{},
    mode: Mode = .supervisor,
    csr: Csr = .{},
};

fn atLeast(mode: Mode, need: Mode) bool {
    return @intFromEnum(mode) >= @intFromEnum(need);
}

/// Enters the supervisor trap handler: records cause/epc/tval, saves the interrupted mode,
/// masks interrupts, and vectors to `stvec`.
fn trap(h: *Hart, cause: u32, epc: u32, tval: u32) void {
    h.csr.scause = cause;
    h.csr.sepc = epc;
    h.csr.stval = tval;
    h.csr.spp = h.mode;
    h.csr.spie = h.csr.sie;
    h.csr.sie = false;
    h.mode = .supervisor;
    h.cpu.pc = h.csr.stvec;
}

fn causeOf(code: u32) u32 {
    return switch (code) {
        base.FAULT_ALIGN => CAUSE_MISALIGN,
        base.FAULT_MEM => CAUSE_ACCESS_FAULT,
        base.FAULT_DIV0 => CAUSE_DIV0,
        else => CAUSE_ILLEGAL,
    };
}

fn csrRead(h: *Hart, csr: u16) ?u32 {
    return switch (csr) {
        CSR_SSTATUS => (if (h.csr.sie) SSTATUS_SIE else 0) | (if (h.csr.spie) SSTATUS_SPIE else 0) | (if (h.csr.spp == .supervisor) SSTATUS_SPP else 0),
        CSR_STVEC => h.csr.stvec,
        CSR_SSCRATCH => h.csr.sscratch,
        CSR_SEPC => h.csr.sepc,
        CSR_SCAUSE => h.csr.scause,
        CSR_STVAL => h.csr.stval,
        else => null,
    };
}

fn csrWrite(h: *Hart, csr: u16, v: u32) bool {
    switch (csr) {
        CSR_SSTATUS => {
            h.csr.sie = (v & SSTATUS_SIE) != 0;
            h.csr.spie = (v & SSTATUS_SPIE) != 0;
            h.csr.spp = if ((v & SSTATUS_SPP) != 0) .supervisor else .user;
        },
        CSR_STVEC => h.csr.stvec = v,
        CSR_SSCRATCH => h.csr.sscratch = v,
        CSR_SEPC => h.csr.sepc = v,
        CSR_SCAUSE => h.csr.scause = v,
        CSR_STVAL => h.csr.stval = v,
        else => return false,
    }
    return true;
}

fn setReg(h: *Hart, rd: u4, v: u32) void {
    if (rd != 0) h.cpu.r[rd] = v;
}

/// Executes one instruction with privilege enforcement and trap delivery. Base instructions
/// run through `execOne`; `sys` and faults become supervisor traps rather than host returns.
pub fn stepV(h: *Hart, bus: anytype) VStop {
    const cpu = &h.cpu;
    if (cpu.pc & 3 != 0) {
        trap(h, CAUSE_MISALIGN, cpu.pc, cpu.pc);
        return .ok;
    }
    const ipc = cpu.pc;
    cpu.insn_pc = ipc;
    const word = base.busRead32(bus, ipc) orelse {
        trap(h, CAUSE_FETCH_FAULT, ipc, ipc);
        return .ok;
    };
    const d = isa.decode(word);
    switch (d.op) {
        isa.CSRR => {
            if (!atLeast(h.mode, .supervisor)) {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            }
            const v = csrRead(h, d.imm16) orelse {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            };
            setReg(h, d.rd, v);
            cpu.pc = ipc +% 4;
            return .ok;
        },
        isa.CSRW => {
            if (!atLeast(h.mode, .supervisor)) {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            }
            if (!csrWrite(h, d.imm16, cpu.r[d.rs1])) {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            }
            cpu.pc = ipc +% 4;
            return .ok;
        },
        isa.SRET => {
            if (!atLeast(h.mode, .supervisor)) {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            }
            h.mode = h.csr.spp;
            h.csr.sie = h.csr.spie;
            h.csr.spie = true;
            h.csr.spp = .user;
            cpu.pc = h.csr.sepc;
            return .ok;
        },
        else => switch (base.execOne(cpu, bus, d, ipc)) {
            .ok => return .ok,
            .halt => return .halt,
            .breakpoint => return .breakpoint,
            .syscall => {
                trap(h, if (h.mode == .user) CAUSE_ECALL_U else CAUSE_ECALL_S, ipc, 0);
                return .ok;
            },
            .fault => {
                trap(h, causeOf(cpu.trap), ipc, 0);
                return .ok;
            },
        },
    }
}

fn put(ram: []u8, addr: u32, word: u32) void {
    ram[addr] = @truncate(word);
    ram[addr + 1] = @truncate(word >> 8);
    ram[addr + 2] = @truncate(word >> 16);
    ram[addr + 3] = @truncate(word >> 24);
}

fn runToStop(h: *Hart, bus: anytype) VStop {
    var guard: u32 = 0;
    while (guard < 1000) : (guard += 1) {
        switch (stepV(h, bus)) {
            .ok => {},
            .halt => return .halt,
            .breakpoint => return .breakpoint,
        }
    }
    return .ok;
}

test "user ecall traps to the supervisor handler and returns" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 512;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, isa.encI(isa.ORI, 1, 0, 0x40));
    put(&ram, 0x04, isa.encI(isa.CSRW, 0, 1, CSR_STVEC));
    put(&ram, 0x08, isa.encI(isa.ORI, 2, 0, 0x80));
    put(&ram, 0x0C, isa.encI(isa.CSRW, 0, 2, CSR_SEPC));
    put(&ram, 0x10, isa.encI(isa.CSRW, 0, 0, CSR_SSTATUS));
    put(&ram, 0x14, @as(u32, isa.SRET) << 25);

    put(&ram, 0x40, isa.encI(isa.CSRR, 3, 0, CSR_SCAUSE));
    put(&ram, 0x44, isa.encI(isa.CSRR, 4, 0, CSR_SEPC));
    put(&ram, 0x48, isa.encI(isa.ADDI, 4, 4, 4));
    put(&ram, 0x4C, isa.encI(isa.CSRW, 0, 4, CSR_SEPC));
    put(&ram, 0x50, @as(u32, isa.SRET) << 25);

    put(&ram, 0x80, @as(u32, isa.SYS) << 25);
    put(&ram, 0x84, isa.encI(isa.ORI, 5, 0, 0xAA));
    put(&ram, 0x88, @as(u32, isa.HLT) << 25);

    var h = Hart{};
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_ECALL_U, h.cpu.r[3]);
    try std.testing.expectEqual(@as(u32, 0x80), h.cpu.r[4] -% 4);
    try std.testing.expectEqual(@as(u32, 0xAA), h.cpu.r[5]);
    try std.testing.expectEqual(Mode.user, h.mode);
}

test "privileged CSR access from user mode traps as illegal" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 512;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, isa.encI(isa.ORI, 1, 0, 0x40));
    put(&ram, 0x04, isa.encI(isa.CSRW, 0, 1, CSR_STVEC));
    put(&ram, 0x08, isa.encI(isa.ORI, 2, 0, 0x80));
    put(&ram, 0x0C, isa.encI(isa.CSRW, 0, 2, CSR_SEPC));
    put(&ram, 0x10, isa.encI(isa.CSRW, 0, 0, CSR_SSTATUS));
    put(&ram, 0x14, @as(u32, isa.SRET) << 25);

    put(&ram, 0x40, isa.encI(isa.CSRR, 3, 0, CSR_SCAUSE));
    put(&ram, 0x44, @as(u32, isa.HLT) << 25);

    put(&ram, 0x80, isa.encI(isa.CSRW, 0, 0, CSR_STVEC));

    var h = Hart{};
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_ILLEGAL, h.cpu.r[3]);
    try std.testing.expectEqual(Mode.supervisor, h.mode);
}

test "base program runs unchanged under stepV" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 64;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, isa.encI(isa.ORI, 1, 0, 5));
    put(&ram, 0x04, isa.encI(isa.ORI, 2, 0, 37));
    put(&ram, 0x08, isa.encR(isa.ADD, 3, 1, 2));
    put(&ram, 0x0C, @as(u32, isa.HLT) << 25);

    var h = Hart{};
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(@as(u32, 42), h.cpu.r[3]);
}
