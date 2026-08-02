//! A flat byte-array memory bus for the TB32 CPU.

/// Memory in which every in-range address is valid; access past `ram` faults.
pub const FlatBus = struct {
    ram: []u8,

    /// Reads one byte, or null if `a` is out of range.
    pub fn read8(self: *FlatBus, a: u32) ?u8 {
        if (a >= self.ram.len) return null;
        return self.ram[a];
    }

    /// Writes one byte; returns false if `a` is out of range.
    pub fn write8(self: *FlatBus, a: u32, v: u8) bool {
        if (a >= self.ram.len) return false;
        self.ram[a] = v;
        return true;
    }
};
