//! The libtb32 public API.

const std = @import("std");

pub const isa = @import("isa.zig");

const cpu = @import("cpu.zig");
pub const Cpu = cpu.Cpu;
pub const Flags = cpu.Flags;
pub const Stop = cpu.Stop;
pub const step = cpu.step;
pub const FAULT_ALIGN = cpu.FAULT_ALIGN;
pub const FAULT_MEM = cpu.FAULT_MEM;
pub const FAULT_OPCODE = cpu.FAULT_OPCODE;
pub const FAULT_DIV0 = cpu.FAULT_DIV0;

pub const disasm = @import("disasm.zig").disasm;
pub const FlatBus = @import("flatbus.zig").FlatBus;

pub const assembler = @import("asm.zig");
pub const assemble = assembler.assemble;
pub const assembleDiag = assembler.assembleDiag;
pub const assembleDebug = assembler.assembleDebug;
pub const Diagnostic = assembler.Diagnostic;
pub const LineEntry = assembler.LineEntry;

test {
    _ = isa;
    _ = @import("cpu.zig");
    _ = @import("disasm.zig");
    _ = @import("flatbus.zig");
    _ = @import("asm.zig");
}
