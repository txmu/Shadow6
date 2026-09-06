const std = @import("std");
const p = @import("platform.zig");
const cfg = @import("config.zig");
const enet = @import("enet.zig");
const Backend = @import("backend.zig").Backend;
const Lifetime = @import("lifetime.zig").Lifetime;
const Channel = struct {
    secure: enet.Session,
    remote: p.Address,
    tcp: c_int,
    last: i64,
    opened: bool = false,
    local_fin: bool = false,
    remote_fin: bool = false,
    retired: bool = false,
    output_offset: usize = 0,
};
pub const Tunnel = struct {
    parent: std.mem.Allocator,
    life: Lifetime = undefined,
    backend: Backend,
    udp: c_int,
    master: [32]u8,
    authorized: p.Address,
    target_port: u16,
    client: bool,
    deadline: i64,
    channels: []?Channel,
    slots: *std.atomic.Value(u32),
    pub fn create(a: std.mem.Allocator, master: [32]u8, authorized: p.Address, target: u16, seconds: u32, client: bool, slots: *std.atomic.Value(u32)) !*Tunnel {
        if (slots.fetchAdd(1, .seq_cst) >= 16) {
            _ = slots.fetchSub(1, .seq_cst);
            return error.TunnelLimit;
        }
        errdefer _ = slots.fetchSub(1, .seq_cst);
        const self = try a.create(Tunnel);
        errdefer a.destroy(self);
        var backend = try Backend.init();
        errdefer backend.deinit();
        const bind_addr = try p.address(if (authorized.storage.ss_family == p.c.AF_INET) "0.0.0.0" else "::", 0);
        const udp = try p.bind(&bind_addr, true);
        errdefer p.close(udp);
        self.* = .{ .parent = a, .backend = backend, .udp = udp, .master = master, .authorized = authorized, .target_port = target, .client = client, .deadline = p.now() + @as(i64, seconds) * 1000, .channels = undefined, .slots = slots };
        try self.life.init(a, 2 * 1024 * 1024);
        errdefer self.life.deinit();
        self.channels = try self.life.allocator().alloc(?Channel, 16);
        @memset(self.channels, null);
        return self;
    }
    pub fn destroy(self: *Tunnel) void {
        for (self.channels) |*entry| if (entry.*) |*ch| {
            if (ch.tcp >= 0) p.close(ch.tcp);
            ch.secure.deinit();
        };
        self.backend.deinit();
        p.close(self.udp);
        self.life.deinit();
        std.crypto.secureZero(u8, &self.master);
        _ = self.slots.fetchSub(1, .seq_cst);
        const a = self.parent;
        a.destroy(self);
    }
    pub fn start(self: *Tunnel) !void {
        const thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, worker, .{self});
        thread.detach();
    }
    fn worker(self: *Tunnel) void {
        defer self.destroy();
        self.loop() catch |err| {
            if (err == error.OutOfMemory) p.write(2, "Tunnel refused: out of memory\n") catch {};
        };
    }
    fn send(self: *Tunnel, ch: *Channel, packet: *const enet.Packet) !void {
        try self.backend.send(self.udp, packet.bytes[0..packet.len], &ch.remote);
    }
    pub fn attach(self: *Tunnel, tcp: c_int, io: std.Io) !void {
        errdefer if (self.channels[0] == null) p.close(tcp);
        var sid: [16]u8 = undefined;
        try io.randomSecure(&sid);
        self.channels[0] = .{ .secure = enet.Session.init(self.master, sid, true), .remote = self.authorized, .tcp = tcp, .last = p.now() };
        const ch = &self.channels[0].?;
        try self.send(ch, try ch.secure.queue(.open, "", p.now()));
    }
    fn receive(self: *Tunnel, bytes: []const u8, from: p.Address) !void {
        if (bytes.len < enet.header + 16) return;
        var ip_a: [128]u8 = undefined;
        var ip_b: [128]u8 = undefined;
        if (!cfg.eq(try self.authorized.ip(&ip_a), try from.ip(&ip_b))) return;
        var found: ?*Channel = null;
        for (self.channels) |*entry| if (entry.*) |*ch| {
            if (cfg.eq(&ch.secure.sid, bytes[8..24])) {
                found = ch;
                break;
            }
        };
        if (found == null) {
            if (self.client) return;
            var secure = enet.Session.init(self.master, bytes[8..24].*, false);
            const decoded = secure.decode(bytes) catch return;
            if (decoded.kind != .open or decoded.seq != 0) return;
            var slot: ?*?Channel = null;
            for (self.channels) |*entry| {
                if (entry.* == null) {
                    slot = entry;
                    break;
                }
            }
            const entry = slot orelse return;
            // The fixed loopback target is opened only after AEAD key possession.
            const target = try p.address("127.0.0.1", self.target_port);
            const tcp = p.connect(&target) catch return;
            entry.* = .{ .secure = secure, .remote = from, .tcp = tcp, .last = p.now(), .opened = true };
            found = &entry.*.?;
        }
        const ch = found.?;
        if (ch.retired or !ch.remote.equal(&from)) return;
        const data = ch.secure.decode(bytes) catch return;
        ch.last = p.now();
        if (data.kind == .ack) {
            ch.secure.acknowledge(data.seq);
            if (self.client and data.seq == 0) ch.opened = true;
            return;
        }
        if (data.seq < ch.secure.next_rx) {
            const ack = try ch.secure.encode(.ack, data.seq, "");
            try self.send(ch, &ack);
            return;
        }
        if (data.seq - ch.secure.next_rx >= enet.window) return;
        const slot = &ch.secure.received[data.seq % enet.window];
        if (slot.* == null) slot.* = data;
        const ack = try ch.secure.encode(.ack, data.seq, "");
        try self.send(ch, &ack);
    }
    fn pump(self: *Tunnel, ch: *Channel) !void {
        while (ch.secure.received[ch.secure.next_rx % enet.window]) |data| {
            if (data.seq != ch.secure.next_rx) return error.InvalidSequence;
            if (data.kind == .data) {
                if (ch.remote_fin) return error.DataAfterFin;
                const n = self.backend.tcpWrite(ch.tcp, data.bytes[ch.output_offset..data.len]) catch |err| {
                    if (err == error.WouldBlock) return;
                    return err;
                };
                ch.output_offset += n;
                if (ch.output_offset != data.len) return;
            } else if (data.kind == .fin) {
                ch.remote_fin = true;
                _ = p.c.shutdown(ch.tcp, p.c.SHUT_WR);
            } else if (data.kind != .open or self.client or data.seq != 0) return error.InvalidSequence;
            ch.output_offset = 0;
            ch.secure.received[ch.secure.next_rx % enet.window] = null;
            if (ch.secure.next_rx == std.math.maxInt(u32)) return error.SessionLimit;
            ch.secure.next_rx += 1;
        }
    }
    fn retire(ch: *Channel) void {
        if (ch.tcp >= 0) p.close(ch.tcp);
        ch.tcp = -1;
        ch.retired = true;
    }
    fn loop(self: *Tunnel) !void {
        var packet: [enet.mtu + 1]u8 = undefined;
        var data: [enet.payload_max]u8 = undefined;
        while (p.now() < self.deadline) {
            var fds: [17]p.c.pollfd = undefined;
            var indices: [16]usize = undefined;
            var count: usize = 1;
            fds[0] = .{ .fd = self.udp, .events = p.c.POLLIN, .revents = 0 };
            var active: usize = 0;
            for (self.channels, 0..) |*entry, index| if (entry.*) |*ch| {
                if (ch.retired) continue;
                if (p.now() - ch.last > 60000 or (ch.local_fin and ch.remote_fin and ch.secure.in_flight == 0)) {
                    retire(ch);
                    continue;
                }
                active += 1;
                self.pump(ch) catch {
                    retire(ch);
                    continue;
                };
                for (&ch.secure.pending) |*out| {
                    const retry = ch.secure.retry(out, p.now()) catch {
                        retire(ch);
                        break;
                    };
                    if (retry) self.send(ch, out) catch {};
                }
                if (ch.retired) continue;
                if (ch.opened and !ch.local_fin and ch.secure.canQueue()) {
                    fds[count] = .{ .fd = ch.tcp, .events = p.c.POLLIN, .revents = 0 };
                    indices[count - 1] = index;
                    count += 1;
                }
            };
            if (self.client and active == 0) return;
            try self.backend.poll(fds[0..count], 20);
            if (fds[0].revents & p.c.POLLIN != 0) {
                var budget: usize = 0;
                while (budget < 64) : (budget += 1) {
                    var from = p.Address{};
                    const n = self.backend.receive(self.udp, &packet, &from) catch break;
                    self.receive(packet[0..n], from) catch {};
                }
            }
            for (fds[1..count], 0..) |fd, i| {
                if (fd.revents == 0) continue;
                const ch = &self.channels[indices[i]].?;
                if (ch.retired) continue;
                const n = self.backend.tcpRead(ch.tcp, &data) catch continue;
                if (n == 0) ch.local_fin = true;
                const out = ch.secure.queue(if (n == 0) .fin else .data, data[0..n], p.now()) catch continue;
                try self.send(ch, out);
            }
        }
    }
};
