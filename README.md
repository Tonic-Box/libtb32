# libtb32

A small, standalone core for the **TB32** instruction set, a fixed-width 32-bit RISC 
architecture. It provides the ISA (encode/decode), an assembler, a host-agnostic CPU 
executor, a disassembler, a flat-memory bus, and an optional privileged extension 
(**TB32-V**) for virtualization.

- [Documentation](https://tonic-box.github.io/libtb32/)
- Powers TonicBoxOS (WASM) hosted at [tonicbox.dev](https://tonicbox.dev/) 

## Build / test

```
zig build          # builds the `tb32` CLI
zig build test     # unit tests
zig build docs     # generates docs/
```

The CLI assembles a source file to a TBX object (stdout if no `-o`):

```
tb32 in.s -o out.tbx
```

## Using it as a library

`build.zig` exposes a `tb32` module. The CPU runs one instruction at a time against a
caller-supplied *bus* - any value with `read8(addr) ?u8` and `write8(addr, v) bool`
(`null`/`false` signal a fault). `step` is generic over the bus, so its accesses inline.

```zig
const tb32 = @import("tb32");
var cpu = tb32.Cpu{ .pc = entry };
var bus = tb32.FlatBus{ .ram = my_memory };
while (true) switch (tb32.step(&cpu, &bus)) {
    .ok => {},
    .syscall => handleSyscall(&cpu),
    .halt => break,
    .breakpoint => pause(),
    .fault => reportFault(cpu.trap, cpu.insn_pc),
};
```

## Virtualization (TB32-V)

Beyond the unprivileged core, libtb32 implements an optional privileged extension that makes TB32
virtualizable - privilege modes (user / supervisor / hypervisor with a virtualization bit),
control/status registers, in-CPU traps with delegation, two-stage (nested) address translation,
and timers, modeled on the RISC-V hypervisor extension. A `Hart` (base CPU plus mode and CSR
banks) runs under `stepV` against a physical-memory bus. It is what the
[tb32hv](https://github.com/Tonic-Box/tb32hv) hypervisor is built on; the base `step` path is
untouched, so existing consumers are unaffected.

## License
[MIT](LICENSE)
