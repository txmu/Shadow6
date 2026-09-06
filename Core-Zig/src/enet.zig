// Shadow6 ENet v1: an intentionally distinct ENet-style reliable UDP wire
// protocol, not wire-compatible with upstream ENet, KCP or QUIC.
const std = @import("std");
const cfg = @import("config.zig");
const AEAD = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
pub const mtu = 1200;
pub const header = 40;
pub const payload_max = mtu - header - AEAD.tag_length;
pub const window = 32;
pub const Kind = enum(u8) { open = 1, data = 2, ack = 3, fin = 4 };
pub const Packet = struct { bytes: [mtu]u8 = undefined, len: usize = 0, seq: u32 = 0, deadline: i64 = 0, attempts: u8 = 0, active: bool = false };
pub const Received = struct { kind: Kind, seq: u32, len: usize, bytes: [payload_max]u8 };
pub const Session = struct {
    sid: [16]u8,
    tx_key: [32]u8,
    rx_key: [32]u8,
    counter: u64 = 0,
    next_tx: u32 = 0,
    next_rx: u32 = 0,
    highest_rx: u64 = 0,
    replay: u64 = 0,
    pending: [window]Packet = @splat(.{}),
    received: [window]?Received = @splat(null),
    in_flight: usize = 0,
    congestion: usize = 4,
    pub fn canQueue(self: *const Session) bool {
        return self.in_flight < self.congestion and self.next_tx < std.math.maxInt(u32) and !self.pending[self.next_tx % window].active and self.counter < std.math.maxInt(u64);
    }
    pub fn init(master: [32]u8, sid: [16]u8, client: bool) Session {
        var input: [17]u8 = undefined;
        @memcpy(input[0..16], &sid);
        var c2a: [32]u8 = undefined;
        var a2c: [32]u8 = undefined;
        input[16] = 0;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&c2a, &input, &master);
        input[16] = 1;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&a2c, &input, &master);
        return .{ .sid = sid, .tx_key = if (client) c2a else a2c, .rx_key = if (client) a2c else c2a };
    }
    pub fn deinit(self: *Session) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
    pub fn encode(self: *Session, kind: Kind, seq: u32, data: []const u8) !Packet {
        if (data.len > payload_max or self.counter == std.math.maxInt(u64)) return error.SessionLimit;
        var out = Packet{ .len = header + data.len + 16, .seq = seq, .active = true };
        @memcpy(out.bytes[0..4], "S6EN");
        out.bytes[4] = 1;
        out.bytes[5] = @intFromEnum(kind);
        out.bytes[6] = 0;
        out.bytes[7] = 0;
        @memcpy(out.bytes[8..24], &self.sid);
        std.mem.writeInt(u64, out.bytes[24..32], self.counter, .big);
        std.mem.writeInt(u32, out.bytes[32..36], seq, .big);
        @memset(out.bytes[36..40], 0);
        var nonce: [12]u8 = @splat(0);
        std.mem.writeInt(u64, nonce[4..12], self.counter, .big);
        AEAD.encrypt(out.bytes[header..][0..data.len], out.bytes[header + data.len ..][0..16], data, out.bytes[0..header], nonce, self.tx_key);
        self.counter += 1;
        return out;
    }
    pub fn queue(self: *Session, kind: Kind, data: []const u8, now: i64) !*Packet {
        if (kind == .ack or !self.canQueue()) return error.Backpressure;
        const slot = &self.pending[self.next_tx % window];
        if (slot.active) return error.Backpressure;
        slot.* = try self.encode(kind, self.next_tx, data);
        slot.deadline = now + 200;
        slot.attempts = 1;
        self.in_flight += 1;
        self.next_tx += 1;
        return slot;
    }
    pub fn decode(self: *Session, packet: []const u8) !Received {
        if (packet.len < header + 16 or packet.len > mtu or !cfg.eq(packet[0..4], "S6EN") or packet[4] != 1 or packet[6] != 0 or packet[7] != 0 or !cfg.eq(packet[8..24], &self.sid) or !cfg.eq(packet[36..40], &.{ 0, 0, 0, 0 })) return error.InvalidPacket;
        const kind = std.enums.fromInt(Kind, packet[5]) orelse return error.InvalidPacket;
        const count = std.mem.readInt(u64, packet[24..32], .big);
        const seq = std.mem.readInt(u32, packet[32..36], .big);
        const len = packet.len - header - 16;
        if (kind != .data and len != 0) return error.InvalidPacket;
        var nonce: [12]u8 = @splat(0);
        std.mem.writeInt(u64, nonce[4..12], count, .big);
        var out = Received{ .kind = kind, .seq = seq, .len = len, .bytes = undefined };
        try AEAD.decrypt(out.bytes[0..len], packet[header..][0..len], packet[header + len ..][0..16].*, packet[0..header], nonce, self.rx_key);
        // Retransmissions retain the exact authenticated ciphertext; duplicate
        // DATA is re-ACKed by the receiver, but never delivered twice.
        // Reliable sequence numbers are the delivery replay window. An old
        // authenticated retransmission must still elicit an ACK after ACK loss.
        if (self.replay != 0 and count <= self.highest_rx and self.highest_rx - count >= 64) return out;
        if (self.replay == 0 or count > self.highest_rx) {
            const shift = if (self.replay == 0) 64 else count - self.highest_rx;
            self.replay = if (shift >= 64) 1 else (self.replay << @intCast(shift)) | 1;
            self.highest_rx = count;
        } else self.replay |= @as(u64, 1) << @intCast(self.highest_rx - count);
        return out;
    }
    pub fn acknowledge(self: *Session, seq: u32) void {
        const slot = &self.pending[seq % window];
        if (!slot.active or slot.seq != seq) return;
        slot.active = false;
        self.in_flight -= 1;
        if (self.congestion < window) self.congestion += 1;
    }
    pub fn retry(self: *Session, packet: *Packet, now: i64) !bool {
        if (!packet.active or packet.deadline > now) return false;
        if (packet.attempts >= 8) return error.RetryLimit;
        packet.attempts += 1;
        packet.deadline = now + @min(@as(i64, 200) << @as(u6, @intCast(packet.attempts - 1)), 3000);
        self.congestion = @max(2, self.congestion / 2);
        return true;
    }
};
test "direction separation, authentication and reliable ACK" {
    var client = Session.init(@splat(7), @splat(3), true);
    var agent = Session.init(@splat(7), @splat(3), false);
    const packet = try client.queue(.data, "hello", 0);
    const decoded = try agent.decode(packet.bytes[0..packet.len]);
    try std.testing.expectEqualStrings("hello", decoded.bytes[0..decoded.len]);
    try std.testing.expectError(error.AuthenticationFailed, client.decode(packet.bytes[0..packet.len]));
    packet.bytes[40] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, agent.decode(packet.bytes[0..packet.len]));
    packet.bytes[40] ^= 1;
    client.acknowledge(decoded.seq);
    try std.testing.expectEqual(@as(usize, 0), client.in_flight);
}
test "lost ACK, retransmission, bounded retries and window wrap" {
    var sender = Session.init(@splat(1), @splat(2), true);
    var receiver = Session.init(@splat(1), @splat(2), false);
    const first = try sender.queue(.data, "first", 0);
    const bytes = first.bytes;
    _ = try receiver.decode(first.bytes[0..first.len]);
    try std.testing.expect(!try sender.retry(first, 199));
    try std.testing.expect(try sender.retry(first, 200));
    try std.testing.expectEqualSlices(u8, bytes[0..first.len], first.bytes[0..first.len]);
    // Keep sequence zero outstanding while later packets are ACKed.
    sender.congestion = window;
    for (1..window) |_| {
        const next = try sender.queue(.data, "later", 201);
        sender.acknowledge(next.seq);
    }
    try std.testing.expect(!sender.canQueue());
    try std.testing.expectError(error.Backpressure, sender.queue(.data, "must not consume TCP input", 202));
    sender.acknowledge(0);
    try std.testing.expect(sender.canQueue());
    const pending = try sender.queue(.fin, "", 203);
    pending.attempts = 8;
    try std.testing.expectError(error.RetryLimit, sender.retry(pending, pending.deadline));
}
