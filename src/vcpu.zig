//! TB32-V privileged execution: privilege modes, control registers, traps, and two-stage
//! address translation layered over the base TB32 core as a superset. `stepV` reuses `execOne`
//! for every base instruction and adds mode-aware handling of the privileged opcodes, trap
//! delivery, and an MMU. The hypervisor level and the virtualization (V) bit give guest
//! supervisor (VS) and guest user (VU) contexts with trap delegation and nested paging
//! (guest-virtual -> guest-physical -> host-physical), following the RISC-V hypervisor extension.

const std = @import("std");
const isa = @import("isa.zig");
const base = @import("cpu.zig");

/// Privilege level, least to most privileged.
pub const Mode = enum(u2) { user = 0, supervisor = 1, hypervisor = 2 };

/// Why `stepV` returned. Traps are taken internally (mode change + vector jump); the machine
/// only needs to know when the hart stopped.
pub const VStop = enum { ok, halt, breakpoint };

/// The kind of memory access being translated, selecting the required page permission.
pub const AccessKind = enum { fetch, load, store };

pub const CAUSE_MISALIGN: u32 = 0;
pub const CAUSE_FETCH_FAULT: u32 = 1;
pub const CAUSE_ILLEGAL: u32 = 2;
pub const CAUSE_BREAK: u32 = 3;
pub const CAUSE_ACCESS_FAULT: u32 = 5;
pub const CAUSE_ECALL_U: u32 = 8;
pub const CAUSE_ECALL_S: u32 = 9;
pub const CAUSE_ECALL_VS: u32 = 10;
pub const CAUSE_FETCH_PAGE_FAULT: u32 = 12;
pub const CAUSE_LOAD_PAGE_FAULT: u32 = 13;
pub const CAUSE_STORE_PAGE_FAULT: u32 = 15;
pub const CAUSE_DIV0: u32 = 16;
pub const CAUSE_FETCH_GUEST_FAULT: u32 = 20;
pub const CAUSE_LOAD_GUEST_FAULT: u32 = 21;
pub const CAUSE_STORE_GUEST_FAULT: u32 = 23;

/// Set in a cause word to mark it an interrupt rather than an exception.
pub const INT_FLAG: u32 = 0x80000000;
pub const CAUSE_INT_TIMER: u32 = INT_FLAG | 5;
pub const CAUSE_INT_EXTERNAL: u32 = INT_FLAG | 9;

const IRQ_TIMER: u32 = 1 << 5;
const IRQ_EXTERNAL: u32 = 1 << 9;

pub const CSR_SSTATUS: u16 = 0x100;
pub const CSR_STVEC: u16 = 0x105;
pub const CSR_SSCRATCH: u16 = 0x140;
pub const CSR_SEPC: u16 = 0x141;
pub const CSR_SIE: u16 = 0x104;
pub const CSR_SCAUSE: u16 = 0x142;
pub const CSR_STVAL: u16 = 0x143;
pub const CSR_SIP: u16 = 0x144;
pub const CSR_STIMECMP: u16 = 0x14D;
pub const CSR_SATP: u16 = 0x180;

pub const CSR_HSTATUS: u16 = 0x600;
pub const CSR_HEDELEG: u16 = 0x602;
pub const CSR_HTVEC: u16 = 0x605;
pub const CSR_HSCRATCH: u16 = 0x640;
pub const CSR_HEPC: u16 = 0x641;
pub const CSR_HCAUSE: u16 = 0x642;
pub const CSR_HTVAL: u16 = 0x643;
pub const CSR_HTINST: u16 = 0x64A;
pub const CSR_HGATP: u16 = 0x680;

const SSTATUS_SIE: u32 = 1 << 1;
const SSTATUS_SPIE: u32 = 1 << 5;
const SSTATUS_SPP: u32 = 1 << 8;

const HSTATUS_SPV: u32 = 1 << 0;

const PTE_V: u32 = 1;
const PTE_R: u32 = 2;
const PTE_W: u32 = 4;
const PTE_X: u32 = 8;
const PTE_U: u32 = 16;

/// The supervisor control and status registers. When the V bit is set these are the guest's
/// (VS) registers; otherwise they are the host supervisor's. `satp` holds the stage-1
/// page-table base (enable bit 31, ASID bits 20-27, root frame bits 0-19).
pub const Csr = struct {
    stvec: u32 = 0,
    sepc: u32 = 0,
    scause: u32 = 0,
    stval: u32 = 0,
    sscratch: u32 = 0,
    satp: u32 = 0,
    sie_mask: u32 = 0,
    sip: u32 = 0,
    stimecmp: u32 = 0,
    sie: bool = false,
    spie: bool = false,
    spp: Mode = .user,
};

/// The hypervisor control and status registers, including the exception delegation mask, the
/// stage-2 page-table base `hgatp`, and the interrupted (mode, V) saved for `hret`.
pub const Hcsr = struct {
    htvec: u32 = 0,
    hepc: u32 = 0,
    hcause: u32 = 0,
    htval: u32 = 0,
    hscratch: u32 = 0,
    hedeleg: u32 = 0,
    hgatp: u32 = 0,
    htinst: u32 = 0,
    hpp: Mode = .supervisor,
    spv: bool = false,
};

/// A hardware thread: the base CPU state plus its privilege mode, virtualization bit, the
/// supervisor and hypervisor register banks, and the most recent MMU fault detail.
pub const Hart = struct {
    cpu: base.Cpu = .{},
    mode: Mode = .supervisor,
    v: bool = false,
    csr: Csr = .{},
    hcsr: Hcsr = .{},
    mmu_fault: bool = false,
    mmu_cause: u32 = 0,
    mmu_tval: u32 = 0,
    time: u32 = 0,
};

fn atLeast(mode: Mode, need: Mode) bool {
    return @intFromEnum(mode) >= @intFromEnum(need);
}

fn csrMinPriv(csr: u16) Mode {
    return if (csr >= 0x600) .hypervisor else .supervisor;
}

fn isGuestPageFault(cause: u32) bool {
    return cause == CAUSE_FETCH_GUEST_FAULT or cause == CAUSE_LOAD_GUEST_FAULT or cause == CAUSE_STORE_GUEST_FAULT;
}

/// Delivers a trap to the hypervisor or the (guest) supervisor per delegation: traps from the
/// hypervisor stay in the hypervisor; guest-physical (stage-2) faults always go to the
/// hypervisor; a delegated exception from a guest goes to the guest supervisor; everything
/// else from a guest goes to the hypervisor.
fn trap(h: *Hart, cause: u32, epc: u32, tval: u32) void {
    const from_priv = h.mode;
    const from_v = h.v;
    var to_h = false;
    if (from_priv == .hypervisor) {
        to_h = true;
    } else if (from_v) {
        if (isGuestPageFault(cause)) {
            to_h = true;
        } else {
            const deleg = cause < 32 and (h.hcsr.hedeleg & (@as(u32, 1) << @as(u5, @intCast(cause)))) != 0;
            to_h = !deleg;
        }
    }
    if (to_h) {
        h.hcsr.hcause = cause;
        h.hcsr.hepc = epc;
        h.hcsr.htval = tval;
        h.hcsr.hpp = from_priv;
        h.hcsr.spv = from_v;
        h.mode = .hypervisor;
        h.v = false;
        h.cpu.pc = h.hcsr.htvec;
    } else {
        h.csr.scause = cause;
        h.csr.sepc = epc;
        h.csr.stval = tval;
        h.csr.spp = from_priv;
        h.csr.spie = h.csr.sie;
        h.csr.sie = false;
        h.mode = .supervisor;
        h.cpu.pc = h.csr.stvec;
    }
}

fn causeOf(code: u32) u32 {
    return switch (code) {
        base.FAULT_ALIGN => CAUSE_MISALIGN,
        base.FAULT_MEM => CAUSE_ACCESS_FAULT,
        base.FAULT_DIV0 => CAUSE_DIV0,
        else => CAUSE_ILLEGAL,
    };
}

/// Returns the cause of a pending, enabled supervisor interrupt for the running guest, or null.
/// Interrupts target the guest supervisor and are taken in guest user mode, or in guest
/// supervisor mode when its global interrupt-enable is set.
fn pendingInterrupt(h: *Hart) ?u32 {
    if (!h.v) return null;
    const active = h.csr.sip & h.csr.sie_mask;
    if (active == 0) return null;
    if (h.mode == .supervisor and !h.csr.sie) return null;
    if (active & IRQ_EXTERNAL != 0) return CAUSE_INT_EXTERNAL;
    if (active & IRQ_TIMER != 0) return CAUSE_INT_TIMER;
    return null;
}

/// Delivers an interrupt to the guest supervisor, saving the interrupted state so the current
/// instruction re-executes after the handler returns.
fn takeInterrupt(h: *Hart, cause: u32) void {
    h.csr.scause = cause;
    h.csr.sepc = h.cpu.pc;
    h.csr.stval = 0;
    h.csr.spp = h.mode;
    h.csr.spie = h.csr.sie;
    h.csr.sie = false;
    h.mode = .supervisor;
    h.cpu.pc = h.csr.stvec;
}

fn setFault(h: *Hart, cause: u32, tval: u32) void {
    h.mmu_fault = true;
    h.mmu_cause = cause;
    h.mmu_tval = tval;
}

fn satpEnabled(h: *Hart) bool {
    return (h.csr.satp >> 31) != 0;
}

fn hgatpEnabled(h: *Hart) bool {
    return (h.hcsr.hgatp >> 31) != 0;
}

fn permOk(pte: u32, kind: AccessKind, eff_user: bool) bool {
    const need: u32 = switch (kind) {
        .fetch => PTE_X,
        .load => PTE_R,
        .store => PTE_W,
    };
    if (pte & need == 0) return false;
    if (eff_user) {
        if (pte & PTE_U == 0) return false;
    } else {
        if (pte & PTE_U != 0) return false;
    }
    return true;
}

fn permS2(pte: u32, kind: AccessKind) bool {
    const need: u32 = switch (kind) {
        .fetch => PTE_X,
        .load => PTE_R,
        .store => PTE_W,
    };
    return pte & need != 0;
}

fn spfCause(kind: AccessKind) u32 {
    return switch (kind) {
        .fetch => CAUSE_FETCH_PAGE_FAULT,
        .load => CAUSE_LOAD_PAGE_FAULT,
        .store => CAUSE_STORE_PAGE_FAULT,
    };
}

fn gpfCause(kind: AccessKind) u32 {
    return switch (kind) {
        .fetch => CAUSE_FETCH_GUEST_FAULT,
        .load => CAUSE_LOAD_GUEST_FAULT,
        .store => CAUSE_STORE_GUEST_FAULT,
    };
}

/// Walks the stage-2 (guest-physical to host-physical) tables. Its own page-table reads are
/// host-physical, so they do not translate further.
fn walkStage2(h: *Hart, phys: anytype, gpa: u32, kind: AccessKind) ?u32 {
    const root = (h.hcsr.hgatp & 0xFFFFF) << 12;
    const e1 = base.busRead32(phys, root +% ((gpa >> 22) & 0x3FF) *% 4) orelse {
        setFault(h, gpfCause(kind), gpa);
        return null;
    };
    if (e1 & PTE_V == 0 or (e1 & (PTE_R | PTE_W | PTE_X)) != 0) {
        setFault(h, gpfCause(kind), gpa);
        return null;
    }
    const e2 = base.busRead32(phys, (e1 & 0xFFFFF000) +% ((gpa >> 12) & 0x3FF) *% 4) orelse {
        setFault(h, gpfCause(kind), gpa);
        return null;
    };
    if (e2 & PTE_V == 0 or !permS2(e2, kind)) {
        setFault(h, gpfCause(kind), gpa);
        return null;
    }
    return (e2 & 0xFFFFF000) | (gpa & 0xFFF);
}

/// Reads a 32-bit word from a guest-physical address, applying stage-2 first when the guest's
/// stage-2 tables are active. Used to read guest page-table entries during a stage-1 walk.
fn gpaRead32(h: *Hart, phys: anytype, gpa: u32) ?u32 {
    if (h.v and hgatpEnabled(h)) {
        const hpa = walkStage2(h, phys, gpa, .load) orelse return null;
        return base.busRead32(phys, hpa);
    }
    return base.busRead32(phys, gpa);
}

/// Walks the stage-1 (guest-virtual to guest-physical) tables, reading entries through stage-2.
fn walkStage1(h: *Hart, phys: anytype, gva: u32, kind: AccessKind, eff_user: bool) ?u32 {
    const root = (h.csr.satp & 0xFFFFF) << 12;
    const e1 = gpaRead32(h, phys, root +% ((gva >> 22) & 0x3FF) *% 4) orelse return null;
    if (e1 & PTE_V == 0 or (e1 & (PTE_R | PTE_W | PTE_X)) != 0) {
        setFault(h, spfCause(kind), gva);
        return null;
    }
    const e2 = gpaRead32(h, phys, (e1 & 0xFFFFF000) +% ((gva >> 12) & 0x3FF) *% 4) orelse return null;
    if (e2 & PTE_V == 0 or !permOk(e2, kind, eff_user)) {
        setFault(h, spfCause(kind), gva);
        return null;
    }
    return (e2 & 0xFFFFF000) | (gva & 0xFFF);
}

/// Translates a guest-virtual (or host-virtual) address to host-physical, applying whichever of
/// stage-1 and stage-2 are active. Returns null and records the fault on a page fault.
fn xlate(h: *Hart, phys: anytype, gva: u32, kind: AccessKind) ?u32 {
    h.mmu_fault = false;
    const s1 = satpEnabled(h);
    const s2 = h.v and hgatpEnabled(h);
    if (!s1 and !s2) return gva;
    var gpa = gva;
    if (s1) {
        gpa = walkStage1(h, phys, gva, kind, h.mode == .user) orelse return null;
    }
    if (s2) {
        return walkStage2(h, phys, gpa, kind) orelse return null;
    }
    return gpa;
}

/// A bus adapter that translates each guest access through the MMU before forwarding it to the
/// physical bus, letting the base `execOne` run unchanged over virtual addresses.
fn TransBus(comptime P: type) type {
    return struct {
        h: *Hart,
        phys: *P,
        const Self = @This();
        pub fn read8(self: *Self, a: u32) ?u8 {
            const pa = xlate(self.h, self.phys, a, .load) orelse return null;
            return self.phys.read8(pa);
        }
        pub fn write8(self: *Self, a: u32, val: u8) bool {
            const pa = xlate(self.h, self.phys, a, .store) orelse return false;
            return self.phys.write8(pa, val);
        }
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
        CSR_SATP => h.csr.satp,
        CSR_SIE => h.csr.sie_mask,
        CSR_SIP => h.csr.sip,
        CSR_STIMECMP => h.csr.stimecmp,
        CSR_HSTATUS => (if (h.hcsr.spv) HSTATUS_SPV else 0) | (@as(u32, @intFromEnum(h.hcsr.hpp)) << 1),
        CSR_HEDELEG => h.hcsr.hedeleg,
        CSR_HTVEC => h.hcsr.htvec,
        CSR_HSCRATCH => h.hcsr.hscratch,
        CSR_HEPC => h.hcsr.hepc,
        CSR_HCAUSE => h.hcsr.hcause,
        CSR_HTVAL => h.hcsr.htval,
        CSR_HTINST => h.hcsr.htinst,
        CSR_HGATP => h.hcsr.hgatp,
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
        CSR_SATP => h.csr.satp = v,
        CSR_SIE => h.csr.sie_mask = v,
        CSR_SIP => h.csr.sip = v,
        CSR_STIMECMP => h.csr.stimecmp = v,
        CSR_HSTATUS => {
            h.hcsr.spv = (v & HSTATUS_SPV) != 0;
            const pp: u32 = (v >> 1) & 3;
            h.hcsr.hpp = @enumFromInt(@as(u2, @intCast(if (pp > 2) 2 else pp)));
        },
        CSR_HEDELEG => h.hcsr.hedeleg = v,
        CSR_HTVEC => h.hcsr.htvec = v,
        CSR_HSCRATCH => h.hcsr.hscratch = v,
        CSR_HEPC => h.hcsr.hepc = v,
        CSR_HCAUSE => h.hcsr.hcause = v,
        CSR_HTVAL => h.hcsr.htval = v,
        CSR_HTINST => h.hcsr.htinst = v,
        CSR_HGATP => h.hcsr.hgatp = v,
        else => return false,
    }
    return true;
}

fn setReg(h: *Hart, rd: u4, v: u32) void {
    if (rd != 0) h.cpu.r[rd] = v;
}

/// Executes one instruction with privilege enforcement, trap delivery, and address
/// translation. Base instructions run through `execOne` over a translating bus; `sys` and
/// faults become traps routed by delegation.
pub fn stepV(h: *Hart, bus: anytype) VStop {
    const cpu = &h.cpu;
    if (h.csr.stimecmp != 0 and h.time >= h.csr.stimecmp) h.csr.sip |= IRQ_TIMER;
    if (pendingInterrupt(h)) |icause| {
        takeInterrupt(h, icause);
        return .ok;
    }
    if (cpu.pc & 3 != 0) {
        trap(h, CAUSE_MISALIGN, cpu.pc, cpu.pc);
        return .ok;
    }
    const ipc = cpu.pc;
    cpu.insn_pc = ipc;
    const fpa = xlate(h, bus, ipc, .fetch) orelse {
        trap(h, h.mmu_cause, ipc, h.mmu_tval);
        return .ok;
    };
    const word = base.busRead32(bus, fpa) orelse {
        trap(h, CAUSE_FETCH_FAULT, ipc, ipc);
        return .ok;
    };
    const d = isa.decode(word);
    switch (d.op) {
        isa.CSRR => {
            if (!atLeast(h.mode, csrMinPriv(d.imm16))) {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            }
            const val = csrRead(h, d.imm16) orelse {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            };
            setReg(h, d.rd, val);
            cpu.pc = ipc +% 4;
            return .ok;
        },
        isa.CSRW => {
            if (!atLeast(h.mode, csrMinPriv(d.imm16))) {
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
        isa.HRET => {
            if (h.mode != .hypervisor) {
                trap(h, CAUSE_ILLEGAL, ipc, word);
                return .ok;
            }
            h.mode = h.hcsr.hpp;
            h.v = h.hcsr.spv;
            cpu.pc = h.hcsr.hepc;
            return .ok;
        },
        else => {
            var tb = TransBus(@TypeOf(bus.*)){ .h = h, .phys = bus };
            switch (base.execOne(cpu, &tb, d, ipc)) {
                .ok => return .ok,
                .halt => return .halt,
                .breakpoint => return .breakpoint,
                .syscall => {
                    const c = if (h.mode == .user) CAUSE_ECALL_U else if (h.v) CAUSE_ECALL_VS else CAUSE_ECALL_S;
                    trap(h, c, ipc, 0);
                    return .ok;
                },
                .fault => {
                    if (h.mmu_fault) {
                        if (isGuestPageFault(h.mmu_cause)) h.hcsr.htinst = word;
                        trap(h, h.mmu_cause, ipc, h.mmu_tval);
                    } else {
                        trap(h, causeOf(cpu.trap), ipc, 0);
                    }
                    return .ok;
                },
            }
        },
    }
}

fn put(ram: []u8, addr: u32, word: u32) void {
    ram[addr] = @truncate(word);
    ram[addr + 1] = @truncate(word >> 8);
    ram[addr + 2] = @truncate(word >> 16);
    ram[addr + 3] = @truncate(word >> 24);
}

fn peek(ram: []const u8, addr: u32) u32 {
    return @as(u32, ram[addr]) | (@as(u32, ram[addr + 1]) << 8) | (@as(u32, ram[addr + 2]) << 16) | (@as(u32, ram[addr + 3]) << 24);
}

fn ptMap(ram: []u8, root: u32, va: u32, pa: u32, perms: u32, nf: *u32) void {
    const l1a = root + ((va >> 22) & 0x3FF) * 4;
    var e1 = peek(ram, l1a);
    if (e1 & PTE_V == 0) {
        const f = nf.*;
        nf.* += 1;
        e1 = (f << 12) | PTE_V;
        put(ram, l1a, e1);
    }
    const l2a = (e1 & 0xFFFFF000) + ((va >> 12) & 0x3FF) * 4;
    put(ram, l2a, (pa & 0xFFFFF000) | perms | PTE_V);
}

fn runToStop(h: *Hart, bus: anytype) VStop {
    var guard: u32 = 0;
    while (guard < 2000) : (guard += 1) {
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

test "hypervisor launches a guest whose user ecall is delegated to the guest kernel" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 1024;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, isa.encI(isa.ORI, 1, 0, 1 << 8));
    put(&ram, 0x04, isa.encI(isa.CSRW, 0, 1, CSR_HEDELEG));
    put(&ram, 0x08, isa.encI(isa.ORI, 2, 0, 0x200));
    put(&ram, 0x0C, isa.encI(isa.CSRW, 0, 2, CSR_HEPC));
    put(&ram, 0x10, isa.encI(isa.ORI, 3, 0, 3));
    put(&ram, 0x14, isa.encI(isa.CSRW, 0, 3, CSR_HSTATUS));
    put(&ram, 0x18, @as(u32, isa.HRET) << 25);

    put(&ram, 0x200, isa.encI(isa.ORI, 4, 0, 0x260));
    put(&ram, 0x204, isa.encI(isa.CSRW, 0, 4, CSR_STVEC));
    put(&ram, 0x208, isa.encI(isa.ORI, 5, 0, 0x2A0));
    put(&ram, 0x20C, isa.encI(isa.CSRW, 0, 5, CSR_SEPC));
    put(&ram, 0x210, isa.encI(isa.CSRW, 0, 0, CSR_SSTATUS));
    put(&ram, 0x214, @as(u32, isa.SRET) << 25);

    put(&ram, 0x260, isa.encI(isa.CSRR, 7, 0, CSR_SCAUSE));
    put(&ram, 0x264, isa.encI(isa.CSRR, 8, 0, CSR_SEPC));
    put(&ram, 0x268, isa.encI(isa.ADDI, 8, 8, 4));
    put(&ram, 0x26C, isa.encI(isa.CSRW, 0, 8, CSR_SEPC));
    put(&ram, 0x270, @as(u32, isa.SRET) << 25);

    put(&ram, 0x2A0, @as(u32, isa.SYS) << 25);
    put(&ram, 0x2A4, isa.encI(isa.ORI, 6, 0, 0xBB));
    put(&ram, 0x2A8, @as(u32, isa.HLT) << 25);

    var h = Hart{ .mode = .hypervisor };
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_ECALL_U, h.cpu.r[7]);
    try std.testing.expectEqual(@as(u32, 0xBB), h.cpu.r[6]);
    try std.testing.expect(h.v);
    try std.testing.expectEqual(Mode.user, h.mode);
}

test "a hypervisor-only op from the guest kernel traps to the hypervisor" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 1024;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, isa.encI(isa.ORI, 1, 0, 0x40));
    put(&ram, 0x04, isa.encI(isa.CSRW, 0, 1, CSR_HTVEC));
    put(&ram, 0x08, isa.encI(isa.ORI, 2, 0, 0x200));
    put(&ram, 0x0C, isa.encI(isa.CSRW, 0, 2, CSR_HEPC));
    put(&ram, 0x10, isa.encI(isa.ORI, 3, 0, 3));
    put(&ram, 0x14, isa.encI(isa.CSRW, 0, 3, CSR_HSTATUS));
    put(&ram, 0x18, @as(u32, isa.HRET) << 25);

    put(&ram, 0x40, isa.encI(isa.CSRR, 6, 0, CSR_HCAUSE));
    put(&ram, 0x44, @as(u32, isa.HLT) << 25);

    put(&ram, 0x200, isa.encI(isa.CSRR, 5, 0, CSR_HSTATUS));

    var h = Hart{ .mode = .hypervisor };
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_ILLEGAL, h.cpu.r[6]);
    try std.testing.expect(!h.v);
    try std.testing.expectEqual(Mode.hypervisor, h.mode);
}

test "stage-2 translation isolates identical guest-physical addresses" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    const ram = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(ram);
    @memset(ram, 0);
    var bus = FlatBus{ .ram = ram };

    const RWX = PTE_R | PTE_W | PTE_X;
    var nf: u32 = 12;
    ptMap(ram, 1 << 12, 0x5000, 0xA000, RWX, &nf);
    ptMap(ram, 8 << 12, 0x5000, 0xB000, RWX, &nf);

    var h = Hart{ .mode = .supervisor, .v = true };
    h.hcsr.hgatp = (1 << 31) | 1;
    try std.testing.expectEqual(@as(u32, 0xA000), xlate(&h, &bus, 0x5000, .store).?);
    h.hcsr.hgatp = (1 << 31) | 8;
    try std.testing.expectEqual(@as(u32, 0xB000), xlate(&h, &bus, 0x5000, .store).?);
}

test "two-stage walk composes guest and hypervisor page tables" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    const ram = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(ram);
    @memset(ram, 0);
    var bus = FlatBus{ .ram = ram };

    const RWX = PTE_R | PTE_W | PTE_X;

    var nf_s1: u32 = 3;
    ptMap(ram, 2 << 12, 0x5000, 0x8000, RWX | PTE_U, &nf_s1);

    const s2root: u32 = 1 << 12;
    var nf_s2: u32 = 16;
    ptMap(ram, s2root, 0x2000, 0x2000, RWX, &nf_s2);
    ptMap(ram, s2root, 0x3000, 0x3000, RWX, &nf_s2);
    ptMap(ram, s2root, 0x8000, 0xC000, RWX, &nf_s2);

    var h = Hart{ .mode = .user, .v = true };
    h.csr.satp = (1 << 31) | 2;
    h.hcsr.hgatp = (1 << 31) | 1;
    try std.testing.expectEqual(@as(u32, 0xC000), xlate(&h, &bus, 0x5000, .store).?);
}

test "guest fetch and store run through the MMU with per-VM isolation" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    const ram = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(ram);
    @memset(ram, 0);
    var bus = FlatBus{ .ram = ram };

    put(ram, 0x2000, isa.encI(isa.ORI, 1, 0, 0xAA));
    put(ram, 0x2004, isa.encI(isa.ORI, 2, 0, 0x5000));
    put(ram, 0x2008, isa.encI(isa.SW, 1, 2, 0));
    put(ram, 0x200C, @as(u32, isa.HLT) << 25);

    var nf: u32 = 16;
    ptMap(ram, 1 << 12, 0x2000, 0x2000, PTE_R | PTE_X, &nf);
    ptMap(ram, 1 << 12, 0x5000, 0xC000, PTE_R | PTE_W, &nf);
    ptMap(ram, 8 << 12, 0x2000, 0x2000, PTE_R | PTE_X, &nf);
    ptMap(ram, 8 << 12, 0x5000, 0xD000, PTE_R | PTE_W, &nf);

    var h1 = Hart{ .mode = .supervisor, .v = true };
    h1.hcsr.hgatp = (1 << 31) | 1;
    h1.cpu.pc = 0x2000;
    try std.testing.expectEqual(VStop.halt, runToStop(&h1, &bus));
    try std.testing.expectEqual(@as(u8, 0xAA), ram[0xC000]);

    var h2 = Hart{ .mode = .supervisor, .v = true };
    h2.hcsr.hgatp = (1 << 31) | 8;
    h2.cpu.pc = 0x2000;
    try std.testing.expectEqual(VStop.halt, runToStop(&h2, &bus));
    try std.testing.expectEqual(@as(u8, 0xAA), ram[0xD000]);
    try std.testing.expectEqual(@as(u8, 0x00), ram[0xD001]);
}

test "an unmapped guest-physical store faults to the hypervisor" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    const ram = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(ram);
    @memset(ram, 0);
    var bus = FlatBus{ .ram = ram };

    put(ram, 0x40, isa.encI(isa.CSRR, 6, 0, CSR_HCAUSE));
    put(ram, 0x44, @as(u32, isa.HLT) << 25);

    put(ram, 0x2000, isa.encI(isa.ORI, 2, 0, 0x6000));
    put(ram, 0x2004, isa.encI(isa.SW, 2, 2, 0));
    put(ram, 0x2008, @as(u32, isa.HLT) << 25);

    var nf: u32 = 16;
    ptMap(ram, 1 << 12, 0x2000, 0x2000, PTE_R | PTE_X, &nf);

    var h = Hart{ .mode = .supervisor, .v = true };
    h.hcsr.hgatp = (1 << 31) | 1;
    h.hcsr.htvec = 0x40;
    h.cpu.pc = 0x2000;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_STORE_GUEST_FAULT, h.cpu.r[6]);
    try std.testing.expectEqual(Mode.hypervisor, h.mode);
    try std.testing.expect(!h.v);
}

test "guest takes an injected external interrupt and returns" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 512;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, @as(u32, isa.HLT) << 25);
    put(&ram, 0x40, isa.encI(isa.CSRR, 3, 0, CSR_SCAUSE));
    put(&ram, 0x44, isa.encI(isa.CSRW, 0, 0, CSR_SIP));
    put(&ram, 0x48, isa.encI(isa.ORI, 5, 0, 0xCC));
    put(&ram, 0x4C, @as(u32, isa.SRET) << 25);

    var h = Hart{ .mode = .supervisor, .v = true };
    h.csr.stvec = 0x40;
    h.csr.sie = true;
    h.csr.sie_mask = IRQ_EXTERNAL;
    h.csr.sip = IRQ_EXTERNAL;
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_INT_EXTERNAL, h.cpu.r[3]);
    try std.testing.expectEqual(@as(u32, 0xCC), h.cpu.r[5]);
    try std.testing.expectEqual(@as(u32, 0), h.csr.sip);
    try std.testing.expect(h.v);
}

test "guest timer interrupt fires when time reaches the compare" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 512;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, @as(u32, isa.HLT) << 25);
    put(&ram, 0x40, isa.encI(isa.CSRR, 3, 0, CSR_SCAUSE));
    put(&ram, 0x44, isa.encI(isa.CSRW, 0, 0, CSR_STIMECMP));
    put(&ram, 0x48, isa.encI(isa.CSRW, 0, 0, CSR_SIP));
    put(&ram, 0x4C, isa.encI(isa.ORI, 5, 0, 0xDD));
    put(&ram, 0x50, @as(u32, isa.SRET) << 25);

    var h = Hart{ .mode = .supervisor, .v = true };
    h.csr.stvec = 0x40;
    h.csr.sie = true;
    h.csr.sie_mask = 1 << 5;
    h.csr.stimecmp = 5;
    h.time = 10;
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(CAUSE_INT_TIMER, h.cpu.r[3]);
    try std.testing.expectEqual(@as(u32, 0xDD), h.cpu.r[5]);
}

test "hypervisor injects a guest interrupt by writing sip from H mode" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    var ram = [_]u8{0} ** 256;
    var bus = FlatBus{ .ram = &ram };

    put(&ram, 0x00, isa.encI(isa.ORI, 1, 0, 1 << 9));
    put(&ram, 0x04, isa.encI(isa.CSRW, 0, 1, CSR_SIP));
    put(&ram, 0x08, @as(u32, isa.HLT) << 25);

    var h = Hart{ .mode = .hypervisor };
    h.cpu.pc = 0;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(@as(u32, 1 << 9), h.csr.sip);
}

test "hypervisor records the trapping instruction on a guest MMIO fault" {
    const FlatBus = @import("flatbus.zig").FlatBus;
    const ram = try std.testing.allocator.alloc(u8, 128 * 1024);
    defer std.testing.allocator.free(ram);
    @memset(ram, 0);
    var bus = FlatBus{ .ram = ram };

    put(ram, 0x40, isa.encI(isa.CSRR, 6, 0, CSR_HTINST));
    put(ram, 0x44, @as(u32, isa.HLT) << 25);

    const store_word = isa.encI(isa.SW, 2, 2, 0);
    put(ram, 0x2000, isa.encI(isa.ORI, 2, 0, 0x6000));
    put(ram, 0x2004, store_word);
    put(ram, 0x2008, @as(u32, isa.HLT) << 25);

    var nf: u32 = 16;
    ptMap(ram, 1 << 12, 0x2000, 0x2000, PTE_R | PTE_X, &nf);

    var h = Hart{ .mode = .supervisor, .v = true };
    h.hcsr.hgatp = (1 << 31) | 1;
    h.hcsr.htvec = 0x40;
    h.cpu.pc = 0x2000;
    try std.testing.expectEqual(VStop.halt, runToStop(&h, &bus));
    try std.testing.expectEqual(store_word, h.cpu.r[6]);
}
