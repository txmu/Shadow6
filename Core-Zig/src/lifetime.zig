const std = @import("std");
// Ownership is local and explicit. A fixed slab bounds Arena growth. No global
// allocator and no allocations in the packet processing/retransmission path.
pub const Lifetime = struct {
    parent: std.mem.Allocator,
    slab: []u8,
    fixed: std.heap.FixedBufferAllocator,
    arena: std.heap.ArenaAllocator,
    pub fn init(self: *Lifetime, parent: std.mem.Allocator, limit: usize) !void {
        self.parent = parent;
        self.slab = parent.alloc(u8, limit) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return err;
        };
        self.fixed = std.heap.FixedBufferAllocator.init(self.slab);
        self.arena = std.heap.ArenaAllocator.init(self.fixed.allocator());
    }
    pub fn allocator(self: *Lifetime) std.mem.Allocator {
        return self.arena.allocator();
    }
    pub fn deinit(self: *Lifetime) void {
        self.arena.deinit();
        std.crypto.secureZero(u8, self.slab);
        self.parent.free(self.slab);
    }
};
