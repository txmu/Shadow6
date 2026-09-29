const std = @import("std");
const builtin = @import("builtin");
const p = @import("platform.zig");
const linux = std.os.linux;
const is_linux = builtin.os.tag == .linux;
pub const Backend = struct {
    const Outgoing = struct { bytes: [1200]u8 = undefined, len: usize = 0, fd: c_int = -1, to: p.Address = .{}, iov: std.posix.iovec_const = undefined, msg: if (is_linux) linux.msghdr_const else void = undefined };
    ring: if (is_linux) linux.IoUring else void = undefined,
    outgoing: [1024]Outgoing = @splat(.{}),
    queued: usize = 0,
    // The 1024-slot send queue is ~1.3 MiB; initialize it in place inside the
    // heap-allocated Tunnel rather than returning it by value on a caller stack.
    pub fn init(self: *Backend) !void {
        self.queued = 0;
        if (is_linux) self.ring = try linux.IoUring.init(1024, 0);
    }
    pub fn deinit(self: *Backend) void {
        self.flush() catch {};
        if (is_linux) self.ring.deinit();
    }
    // All polls are drained (including cancellation completions) before any
    // descriptor or stack-backed request buffer may be released/reused.
    pub fn poll(self: *Backend, fds: []p.c.pollfd, timeout_ms: u32) !void {
        try self.flush();
        if (!is_linux) {
            if (p.c.poll(fds.ptr, @intCast(fds.len), @intCast(timeout_ms)) < 0) return error.PollFailed;
            return;
        }
        if (fds.len > 32) return error.TooManySockets;
        for (fds, 0..) |*fd, i| {
            fd.revents = 0;
            _ = try self.ring.poll_add(i, fd.fd, @intCast(fd.events));
        }
        const ts = linux.kernel_timespec{ .sec = timeout_ms / 1000, .nsec = @as(i64, timeout_ms % 1000) * 1000000 };
        _ = try self.ring.timeout(32, &ts, 0, 0);
        _ = try self.ring.submit();
        const first = try self.ring.copy_cqe();
        if (first.user_data < fds.len and first.res > 0) fds[@intCast(first.user_data)].revents = @intCast(first.res);
        for (0..fds.len + 1) |i| {
            const id: u64 = if (i == fds.len) 32 else i;
            _ = try self.ring.cancel(64 + i, id, 0);
        }
        _ = try self.ring.submit();
        var remaining = (fds.len + 1) * 2 - 1;
        while (remaining > 0) : (remaining -= 1) {
            const done = try self.ring.copy_cqe();
            if (done.user_data < fds.len and done.res > 0) fds[@intCast(done.user_data)].revents = @intCast(done.res);
        }
    }
    pub fn receive(self: *Backend, fd: c_int, buf: []u8, from: *p.Address) !usize {
        _ = self;
        // Poll established readiness. A synchronous nonblocking receive avoids
        // a submit/CQE pair per datagram; the caller reserves an oversize byte.
        const flags = p.c.MSG_DONTWAIT | (if (is_linux) p.c.MSG_TRUNC else 0);
        const n = p.c.recvfrom(fd, buf.ptr, buf.len, flags, from.mut(), &from.len);
        if (n < 0) return error.WouldBlock;
        if (n > buf.len) return error.Oversize;
        return @intCast(n);
    }
    pub fn send(self: *Backend, fd: c_int, data: []const u8, to: *const p.Address) !void {
        if (!is_linux) {
            const n = p.c.sendto(fd, data.ptr, data.len, p.c.MSG_DONTWAIT, to.ptr(), to.len);
            if (n < 0 or n != data.len) return error.SendFailed;
            return;
        }
        if (data.len > 1200) return error.Oversize;
        if (self.queued == self.outgoing.len) try self.flush();
        const slot = &self.outgoing[self.queued];
        @memcpy(slot.bytes[0..data.len], data);
        slot.len = data.len;
        slot.fd = fd;
        slot.to = to.*;
        self.queued += 1;
    }
    pub fn flush(self: *Backend) !void {
        if (!is_linux or self.queued == 0) return;
        const count = self.queued;
        for (self.outgoing[0..count], 0..) |*slot, i| {
            slot.iov = .{ .base = &slot.bytes, .len = slot.len };
            slot.msg = std.mem.zeroes(linux.msghdr_const);
            slot.msg.name = @ptrCast(slot.to.ptr());
            slot.msg.namelen = slot.to.len;
            slot.msg.iov = (&slot.iov)[0..1].ptr;
            slot.msg.iovlen = 1;
            _ = try self.ring.sendmsg(i, slot.fd, &slot.msg, linux.MSG.DONTWAIT);
        }
        _ = try self.ring.submit();
        // Drain every CQE, even when a datagram failed. Reliable frames remain
        // in the retransmit window and ACKs are regenerated on retransmission.
        for (0..count) |_| _ = try self.ring.copy_cqe();
        self.queued = 0;
    }
    // Readiness has already been established by poll. Immediate nonblocking
    // TCP operations avoid a submit/CQE round trip for each 1144-byte cell.
    pub fn tcpRead(self: *Backend, fd: c_int, buf: []u8) !usize {
        _ = self;
        const n = p.c.recv(fd, buf.ptr, buf.len, p.c.MSG_DONTWAIT);
        if (n < 0) return error.WouldBlock;
        return @intCast(n);
    }
    pub fn tcpWrite(self: *Backend, fd: c_int, buf: []const u8) !usize {
        _ = self;
        const n = p.c.send(fd, buf.ptr, buf.len, p.c.MSG_DONTWAIT | (if (is_linux) p.c.MSG_NOSIGNAL else 0));
        if (n < 0) return error.WouldBlock;
        return @intCast(n);
    }
};

test "nonblocking stream I/O preserves bytes, backpressure and EOF without ring requests" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), p.c.socketpair(p.c.AF_UNIX, p.c.SOCK_STREAM, 0, &fds));
    defer p.close(fds[0]);
    defer p.close(fds[1]);
    // TCP helpers must not touch the ring: no requests or buffer lifetimes
    // should be introduced by an immediate nonblocking operation.
    var backend: Backend = undefined;
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, backend.tcpRead(fds[0], &buf));
    try std.testing.expectEqual(@as(usize, 5), try backend.tcpWrite(fds[1], "hello"));
    const n = try backend.tcpRead(fds[0], &buf);
    try std.testing.expectEqualStrings("hello", buf[0..n]);
    try std.testing.expectError(error.WouldBlock, backend.tcpRead(fds[0], &buf));
    try std.testing.expectEqual(@as(c_int, 0), p.c.shutdown(fds[1], p.c.SHUT_WR));
    try std.testing.expectEqual(@as(usize, 0), try backend.tcpRead(fds[0], &buf));
}

test "oversized datagrams cannot look like a valid MTU frame" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), p.c.socketpair(p.c.AF_UNIX, p.c.SOCK_DGRAM, 0, &fds));
    defer p.close(fds[0]);
    defer p.close(fds[1]);
    const packet: [1202]u8 = @splat(0);
    try std.testing.expectEqual(@as(isize, packet.len), p.c.send(fds[0], &packet, packet.len, 0));
    var backend: Backend = undefined;
    var from = p.Address{};
    var buf: [1201]u8 = undefined;
    if (is_linux) {
        try std.testing.expectError(error.Oversize, backend.receive(fds[1], &buf, &from));
    } else {
        // Portable recvfrom truncates to the extra byte, which is still
        // strictly larger than the authenticated protocol's 1200-byte MTU.
        try std.testing.expectEqual(@as(usize, 1201), try backend.receive(fds[1], &buf, &from));
    }
}
