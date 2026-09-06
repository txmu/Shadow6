const std = @import("std");
pub const c = @cImport({
    // Fortified variadic C wrappers cannot be translated by translate-c.
    // Zig slices and explicit lengths provide bounds at this FFI boundary.
    @cUndef("_FORTIFY_SOURCE");
    @cDefine("_FORTIFY_SOURCE", "0");
    // Android Bionic annotates array parameters with Clang nullability
    // tokens. translate-c treats those tokens as types and rejects valid
    // declarations (notably pipe/socketpair/getopt). They carry no ABI
    // information for this FFI, so erase them during translation.
    @cDefine("_Nonnull", "");
    @cDefine("_Nullable", "");
    @cDefine("_Null_unspecified", "");
    @cInclude("sys/socket.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/time.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("netdb.h");
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
    @cInclude("poll.h");
    @cInclude("time.h");
    @cInclude("signal.h");
});
pub fn close(fd: c_int) void {
    _ = c.close(fd);
}
pub fn now() i64 {
    var t: c.timespec = undefined;
    _ = c.clock_gettime(c.CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + @divTrunc(t.tv_nsec, 1000000);
}
pub fn wait(fd: c_int, events: c_short, timeout: c_int) !void {
    var p = c.pollfd{ .fd = fd, .events = events, .revents = 0 };
    if (c.poll(&p, 1, timeout) <= 0) return error.Timeout;
    if (p.revents & (c.POLLERR | c.POLLNVAL) != 0) return error.SocketClosed;
}
pub fn write(fd: c_int, data: []const u8) !void {
    var n: usize = 0;
    while (n < data.len) {
        try wait(fd, c.POLLOUT, 10000);
        const r = c.write(fd, data[n..].ptr, data.len - n);
        if (r <= 0) return error.WriteFailed;
        n += @intCast(r);
    }
}
pub fn read(fd: c_int, data: []u8) !void {
    return readBefore(fd, data, now() + 10000);
}
pub fn readBefore(fd: c_int, data: []u8, deadline: i64) !void {
    var n: usize = 0;
    while (n < data.len) {
        const remaining = deadline - now();
        if (remaining <= 0) return error.Timeout;
        try wait(fd, c.POLLIN, @intCast(@min(remaining, 10000)));
        const r = c.read(fd, data[n..].ptr, data.len - n);
        if (r <= 0) return error.EndOfStream;
        n += @intCast(r);
    }
}
pub const Address = struct {
    storage: c.sockaddr_storage = std.mem.zeroes(c.sockaddr_storage),
    len: c.socklen_t = @sizeOf(c.sockaddr_storage),
    pub fn loopback(self: *const Address) bool {
        if (self.storage.ss_family == c.AF_INET) return @as(*const [4]u8, @ptrCast(&@as(*const c.sockaddr_in, @ptrCast(&self.storage)).sin_addr))[0] == 127;
        const bytes: *const [16]u8 = @ptrCast(&@as(*const c.sockaddr_in6, @ptrCast(&self.storage)).sin6_addr);
        return std.mem.allEqual(u8, bytes[0..15], 0) and bytes[15] == 1;
    }
    pub fn ptr(self: *const Address) *const c.sockaddr {
        return @ptrCast(&self.storage);
    }
    pub fn mut(self: *Address) *c.sockaddr {
        return @ptrCast(&self.storage);
    }
    pub fn port(self: *const Address) u16 {
        if (self.storage.ss_family == c.AF_INET) return std.mem.bigToNative(u16, @as(*const c.sockaddr_in, @ptrCast(&self.storage)).sin_port);
        return std.mem.bigToNative(u16, @as(*const c.sockaddr_in6, @ptrCast(&self.storage)).sin6_port);
    }
    pub fn ip(self: *const Address, out: []u8) ![]const u8 {
        const src: *const anyopaque = if (self.storage.ss_family == c.AF_INET) &@as(*const c.sockaddr_in, @ptrCast(&self.storage)).sin_addr else &@as(*const c.sockaddr_in6, @ptrCast(&self.storage)).sin6_addr;
        if (c.inet_ntop(self.storage.ss_family, src, out.ptr, @intCast(out.len)) == null) return error.InvalidAddress;
        return std.mem.sliceTo(out, 0);
    }
    pub fn equal(self: *const Address, other: *const Address) bool {
        var a: [128]u8 = undefined;
        var b: [128]u8 = undefined;
        return self.port() == other.port() and std.mem.eql(u8, self.ip(&a) catch return false, other.ip(&b) catch return false);
    }
};
pub fn address(host: []const u8, port: u16) !Address {
    var text: [256:0]u8 = @splat(0);
    if (host.len >= text.len) return error.InvalidAddress;
    @memcpy(text[0..host.len], host);
    var out = Address{};
    const v4: *c.sockaddr_in = @ptrCast(&out.storage);
    if (c.inet_pton(c.AF_INET, &text, &v4.sin_addr) == 1) {
        v4.sin_family = c.AF_INET;
        v4.sin_port = std.mem.nativeToBig(u16, port);
        out.len = @sizeOf(c.sockaddr_in);
        return out;
    }
    const v6: *c.sockaddr_in6 = @ptrCast(&out.storage);
    if (c.inet_pton(c.AF_INET6, &text, &v6.sin6_addr) == 1) {
        v6.sin6_family = c.AF_INET6;
        v6.sin6_port = std.mem.nativeToBig(u16, port);
        out.len = @sizeOf(c.sockaddr_in6);
        return out;
    }
    return error.InvalidAddress;
}
pub fn resolve(host: []const u8, port: u16) !Address {
    if (address(host, port)) |a| return a else |_| {}
    var text: [256:0]u8 = @splat(0);
    if (host.len >= text.len) return error.InvalidAddress;
    @memcpy(text[0..host.len], host);
    var hints = std.mem.zeroes(c.addrinfo);
    hints.ai_socktype = c.SOCK_STREAM;
    var result: [*c]c.addrinfo = null;
    if (c.getaddrinfo(&text, null, &hints, &result) != 0) return error.NameResolutionFailed;
    defer c.freeaddrinfo(result);
    var out = Address{};
    if (result == null or result.*.ai_addrlen > @sizeOf(c.sockaddr_storage)) return error.InvalidAddress;
    out.len = result.*.ai_addrlen;
    @memcpy(@as([*]u8, @ptrCast(&out.storage))[0..out.len], @as([*]const u8, @ptrCast(result.*.ai_addr))[0..out.len]);
    if (out.storage.ss_family == c.AF_INET) @as(*c.sockaddr_in, @ptrCast(&out.storage)).sin_port = std.mem.nativeToBig(u16, port) else @as(*c.sockaddr_in6, @ptrCast(&out.storage)).sin6_port = std.mem.nativeToBig(u16, port);
    return out;
}
pub fn socket(a: *const Address, udp: bool) !c_int {
    const fd = c.socket(a.storage.ss_family, if (udp) c.SOCK_DGRAM else c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketResources;
    _ = c.fcntl(fd, c.F_SETFD, @as(c_int, c.FD_CLOEXEC));
    const timeout = c.timeval{ .tv_sec = 10, .tv_usec = 0 };
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_RCVTIMEO, &timeout, @sizeOf(c.timeval));
    _ = c.setsockopt(fd, c.SOL_SOCKET, c.SO_SNDTIMEO, &timeout, @sizeOf(c.timeval));
    return fd;
}
pub fn bind(a: *const Address, udp: bool) !c_int {
    const fd = try socket(a, udp);
    errdefer close(fd);
    if (c.bind(fd, a.ptr(), a.len) != 0) return error.BindFailed;
    if (!udp and c.listen(fd, 32) != 0) return error.ListenFailed;
    return fd;
}
pub fn connect(a: *const Address) !c_int {
    const fd = try socket(a, false);
    errdefer close(fd);
    _ = c.fcntl(fd, c.F_SETFL, @as(c_int, c.O_NONBLOCK));
    if (c.connect(fd, a.ptr(), a.len) != 0) {
        try wait(fd, c.POLLOUT, 10000);
        var e: c_int = 0;
        var len: c.socklen_t = @sizeOf(c_int);
        if (c.getsockopt(fd, c.SOL_SOCKET, c.SO_ERROR, &e, &len) != 0 or e != 0) return error.ConnectFailed;
    }
    _ = c.fcntl(fd, c.F_SETFL, @as(c_int, 0));
    return fd;
}
pub fn local(fd: c_int) !Address {
    var a = Address{};
    if (c.getsockname(fd, a.mut(), &a.len) != 0) return error.InvalidAddress;
    return a;
}
pub fn secretRead(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var name: [4096:0]u8 = @splat(0);
    if (path.len == 0 or path.len >= name.len) return error.InvalidPath;
    @memcpy(name[0..path.len], path);
    var before: c.struct_stat = undefined;
    if (c.lstat(&name, &before) != 0) return error.ConfigNotFound;
    const fd = c.open(&name, c.O_RDONLY | c.O_NOFOLLOW | c.O_CLOEXEC | c.O_NONBLOCK);
    if (fd < 0) return error.UnsafeConfig;
    defer close(fd);
    var after: c.struct_stat = undefined;
    if (c.fstat(fd, &after) != 0 or after.st_uid != c.geteuid() or after.st_mode & 0o7777 != 0o600 or after.st_mode & c.S_IFMT != c.S_IFREG or after.st_ino != before.st_ino or after.st_dev != before.st_dev or after.st_size < 0 or after.st_size > 1048576) return error.UnsafeConfig;
    const data = try allocator.alloc(u8, @intCast(after.st_size));
    errdefer allocator.free(data);
    try read(fd, data);
    var extra: [1]u8 = undefined;
    if (c.read(fd, &extra, 1) != 0) return error.ConfigChanged;
    var final: c.struct_stat = undefined;
    if (c.fstat(fd, &final) != 0 or final.st_uid != after.st_uid or final.st_mode != after.st_mode or final.st_size != after.st_size) return error.ConfigChanged;
    return data;
}
pub fn secretWrite(path: [*:0]const u8, data: []const u8) !void {
    const fd = c.open(path, c.O_WRONLY | c.O_CREAT | c.O_EXCL | c.O_NOFOLLOW | c.O_CLOEXEC, @as(c_uint, 0o600));
    if (fd < 0) return error.FileExistsOrUnsafe;
    defer close(fd);
    try write(fd, data);
    if (c.fsync(fd) != 0) return error.WriteFailed;
}
