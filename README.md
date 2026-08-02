# libtb32

A small, standalone core for the **TB32** instruction set, a fixed-width 32-bit RISC 
architecture. It provides the ISA (encode/decode), an assembler, a host-agnostic CPU 
executor, a disassembler, and a flat-memory bus.

- [Documentation](https://tonic-box.github.io/libtb32/)

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

## License
[MIT](LICENSE)
