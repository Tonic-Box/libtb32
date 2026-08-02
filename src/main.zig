//! The tb32 command-line assembler.

const std = @import("std");
const tb32 = @import("tb32");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);

    var inp: ?[]const u8 = null;
    var outp: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-o")) {
            i += 1;
            if (i < args.len) outp = args[i];
        } else {
            inp = args[i];
        }
    }
    if (inp == null) {
        std.debug.print("usage: tb32 <in.s> [-o out.tbx]\n", .{});
        std.process.exit(2);
    }

    const src = try std.fs.cwd().readFileAlloc(a, inp.?, 64 * 1024 * 1024);
    defer a.free(src);

    var diag: tb32.Diagnostic = .{};
    const tbx = tb32.assembleDiag(a, src, &diag) catch {
        std.debug.print("{s}:{d}: error: {s}\n", .{ inp.?, diag.line, diag.message });
        std.process.exit(1);
    };
    defer a.free(tbx);

    if (outp) |o| {
        try std.fs.cwd().writeFile(.{ .sub_path = o, .data = tbx });
    } else {
        try std.io.getStdOut().writeAll(tbx);
    }
}
