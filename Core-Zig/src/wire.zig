const std = @import("std");
const p = @import("platform.zig");
const cfg = @import("config.zig");
const crypt = @import("crypto.zig");
pub const Message = struct { version: u8 = 1, type: []const u8, id: u64 = 0, method: []const u8 = "", params: ?std.json.Value = null, result: ?std.json.Value = null, @"error": []const u8 = "", peer_id: []const u8 = "", nonce: []const u8 = "", signature: []const u8 = "" };
pub const Request = struct { client_id: []const u8, target_agent: []const u8, client_ip: []const u8, e2ee_pubkey: []const u8, client_sig: []const u8 };
pub const Response = struct { success: bool = false, target_ip: []const u8 = "", dynamic_port: u16 = 0, kcp_port: u16 = 0, e2ee_pubkey: []const u8 = "", error_msg: []const u8 = "", agent_sig: []const u8 = "", transport: []const u8 = "enet", sni: []const u8 = "", alpn: []const u8 = "" };
pub fn clientPayload(a: std.mem.Allocator, r: Request) ![]u8 {
    const key = try crypt.unb64(32, r.e2ee_pubkey);
    return crypt.signed(a, "shadow6-client-access-v1", &.{ r.client_id, r.target_agent, r.client_ip, &key });
}
pub fn agentPayload(a: std.mem.Allocator, r: Request, resp: Response) ![]u8 {
    var port: [4]u8 = undefined;
    std.mem.writeInt(u32, &port, resp.kcp_port, .big);
    const ck = try crypt.unb64(32, r.e2ee_pubkey);
    const ak = try crypt.unb64(32, resp.e2ee_pubkey);
    return crypt.signed(a, "shadow6-agent-access-v1", &.{ r.client_id, r.target_agent, &ck, &ak, &port });
}
pub fn clientPayloadFor(a: std.mem.Allocator, r: Request, rust: bool) ![]u8 {
    if (!rust) return clientPayload(a, r);
    return crypt.signed(a, "shadow6-rust-client-access-v1", &.{ r.client_id, r.target_agent, r.client_ip, r.e2ee_pubkey });
}
pub fn agentPayloadFor(a: std.mem.Allocator, r: Request, resp: Response, rust: bool) ![]u8 {
    if (!rust) return agentPayload(a, r, resp);
    var dynamic: [2]u8 = undefined;
    var port: [2]u8 = undefined;
    std.mem.writeInt(u16, &dynamic, resp.dynamic_port, .big);
    std.mem.writeInt(u16, &port, resp.kcp_port, .big);
    return crypt.signed(a, "shadow6-rust-agent-access-v1", &.{ r.client_id, r.target_agent, r.client_ip, r.e2ee_pubkey, resp.e2ee_pubkey, &dynamic, &port, resp.sni, resp.alpn, resp.transport });
}
const RustAuth = struct { id: []const u8, signature: []const u8 };
const RustRequest = struct { jsonrpc: []const u8, id: u64, method: []const u8, params: std.json.Value };
const RustResponse = struct { jsonrpc: []const u8, id: u64, result: ?std.json.Value = null, @"error": ?[]const u8 = null };
fn rename(a: std.mem.Allocator, v: *std.json.Value, from: []const u8, to: []const u8) !void {
    if (v.* != .object) return;
    if (v.object.fetchSwapRemove(from)) |entry| {
        if (v.object.contains(to)) return error.DuplicateField;
        try v.object.put(a, to, entry.value);
    }
}
fn fields(a: std.mem.Allocator, input: ?std.json.Value, outgoing: bool, rust: bool) !?std.json.Value {
    var v = input orelse return null;
    if (v != .object) return v;
    // Clone so dialect adaptation never mutates a pending signed request.
    v = try value(a, v);
    if (rust) {
        const mappings = [_][2][]const u8{ .{ "ip", "ipv6" }, .{ "client_ip", "client_ipv6" }, .{ "client_sig", "client_signature" }, .{ "target_ip", "target_ipv6" }, .{ "agent_sig", "agent_signature" } };
        for (mappings) |pair| try rename(a, &v, pair[@intFromBool(!outgoing)], pair[@intFromBool(outgoing)]);
    } else if (outgoing) {
        _ = v.object.swapRemove("sni");
        _ = v.object.swapRemove("alpn");
    }
    return v;
}
pub fn value(a: std.mem.Allocator, v: anytype) !std.json.Value {
    return cfg.parse(std.json.Value, a, try std.json.Stringify.valueAlloc(a, v, .{}));
}
pub fn typed(comptime T: type, a: std.mem.Allocator, v: ?std.json.Value) !T {
    return cfg.parse(T, a, try std.json.Stringify.valueAlloc(a, v orelse return error.MissingParams, .{}));
}
pub const WS = struct {
    fd: c_int,
    client: bool,
    rust: bool = false,
    authenticated: bool = false,
    read_deadline: i64 = 0,
    io: std.Io,
    a: std.mem.Allocator,
    tls: ?std.crypto.tls.Client = null,
    input: std.Io.net.Stream.Reader = undefined,
    output: std.Io.net.Stream.Writer = undefined,
    ca: std.crypto.Certificate.Bundle = .{ .map = .empty, .bytes = .empty },
    ca_lock: std.Io.RwLock = .init,
    pub fn init(self: *WS, fd: c_int, client: bool, a: std.mem.Allocator, io: std.Io) void {
        self.* = .{ .fd = fd, .client = client, .a = a, .io = io, .read_deadline = p.now() + 10000 };
    }
    pub fn ready(self: *WS, timeout: c_int) !void {
        if (self.tls) |*tls| if (tls.reader.bufferedLen() > 0 or self.input.interface.bufferedLen() > 0) return;
        try p.wait(self.fd, p.c.POLLIN, timeout);
    }
    fn authDomain(self: *WS) []const u8 {
        return if (self.rust) "shadow6-rust-control-auth-v1" else "shadow6-control-auth-v1";
    }
    pub fn enableTLS(self: *WS, host: []const u8) !void {
        const stream = std.Io.net.Stream{ .socket = .{ .handle = self.fd, .address = .{ .ip4 = .loopback(0) } } };
        const size = std.crypto.tls.Client.min_buffer_len;
        self.input = stream.reader(self.io, try self.a.alloc(u8, size));
        self.output = stream.writer(self.io, try self.a.alloc(u8, size));
        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        try self.io.randomSecure(&entropy);
        const now = std.Io.Clock.real.now(self.io);
        if (@import("builtin").abi == .android) {
            try self.ca.addCertsFromDirPathAbsolute(self.a, self.io, now, "/system/etc/security/cacerts");
        } else try self.ca.rescan(self.a, self.io, now);
        self.tls = try std.crypto.tls.Client.init(&self.input.interface, &self.output.interface, .{
            .host = .{ .explicit = host },
            .ca = .{ .bundle = .{ .gpa = self.a, .io = self.io, .lock = &self.ca_lock, .bundle = &self.ca } },
            .write_buffer = try self.a.alloc(u8, size),
            .read_buffer = try self.a.alloc(u8, size),
            .entropy = &entropy,
            .realtime_now = now,
        });
    }
    pub fn post(self: *WS, url: cfg.URL, body: []const u8) !void {
        try self.enableTLS(url.host);
        var header_bytes: [4096]u8 = undefined;
        const request = try std.fmt.bufPrint(&header_bytes, "POST {s} HTTP/1.1\r\nHost: {s}:{d}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ url.path, url.host, url.port, body.len });
        try self.rawWrite(request);
        try self.rawWrite(body);
        self.read_deadline = p.now() + 5000;
        const reply = try self.http(&header_bytes);
        if (!std.mem.startsWith(u8, reply, "HTTP/1.1 2")) return error.WebhookRejected;
    }
    fn rawRead(self: *WS, bytes: []u8) !void {
        if (p.now() >= self.read_deadline) return error.Timeout;
        if (self.tls) |*tls| try tls.reader.readSliceAll(bytes) else try p.readBefore(self.fd, bytes, self.read_deadline);
    }
    fn rawWrite(self: *WS, bytes: []const u8) !void {
        if (self.tls) |*tls| {
            try tls.writer.writeAll(bytes);
            try tls.writer.flush();
        } else try p.write(self.fd, bytes);
    }
    fn http(self: *WS, buffer: []u8) ![]const u8 {
        var n: usize = 0;
        while (n < buffer.len) {
            try self.rawRead(buffer[n..][0..1]);
            n += 1;
            if (n >= 4 and cfg.eq(buffer[n - 4 .. n], "\r\n\r\n")) return buffer[0..n];
        }
        return error.HeaderTooLarge;
    }
    fn header(data: []const u8, key: []const u8) ![]const u8 {
        var lines = std.mem.splitSequence(u8, data, "\r\n");
        _ = lines.next();
        var result: ?[]const u8 = null;
        while (lines.next()) |line| {
            const off = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[0..off], key)) {
                if (result != null) return error.DuplicateHeader;
                result = std.mem.trim(u8, line[off + 1 ..], " \t");
            }
        }
        return result orelse error.MissingHeader;
    }
    fn acceptKey(key: []const u8, out: *[28]u8) []const u8 {
        var hash = std.crypto.hash.Sha1.init(.{});
        hash.update(key);
        hash.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        var digest: [20]u8 = undefined;
        hash.final(&digest);
        return std.base64.standard.Encoder.encode(out, &digest);
    }
    pub fn upgrade(self: *WS, destination: ?cfg.URL) !void {
        var buf: [8192]u8 = undefined;
        var accept: [28]u8 = undefined;
        if (destination) |url| {
            if (url.tls) try self.enableTLS(url.host);
            var random: [16]u8 = undefined;
            try self.io.randomSecure(&random);
            var key: [24]u8 = undefined;
            const encoded = std.base64.standard.Encoder.encode(&key, &random);
            const request = try std.fmt.bufPrint(&buf, "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n", .{ url.path, url.host, url.port, encoded });
            try self.rawWrite(request);
            const response = try self.http(&buf);
            if (!std.mem.startsWith(u8, response, "HTTP/1.1 101 ") or !cfg.eq(try header(response, "Sec-WebSocket-Accept"), acceptKey(encoded, &accept))) return error.InvalidUpgrade;
            if (!std.ascii.eqlIgnoreCase(try header(response, "Upgrade"), "websocket")) return error.InvalidUpgrade;
        } else {
            const request = try self.http(&buf);
            self.rust = std.mem.startsWith(u8, request, "GET /ws?control=rust HTTP/1.1\r\n");
            if ((!self.rust and !std.mem.startsWith(u8, request, "GET /ws HTTP/1.1\r\n")) or !std.ascii.eqlIgnoreCase(try header(request, "Upgrade"), "websocket") or !cfg.eq(try header(request, "Sec-WebSocket-Version"), "13")) return error.InvalidUpgrade;
            if (header(request, "Origin")) |_| return error.OriginForbidden else |e| if (e != error.MissingHeader) return e;
            _ = try crypt.unb64(16, try header(request, "Sec-WebSocket-Key"));
            const accepted = acceptKey(try header(request, "Sec-WebSocket-Key"), &accept);
            var reply: [256]u8 = undefined;
            try self.rawWrite(try std.fmt.bufPrint(&reply, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{accepted}));
        }
    }
    fn frame(self: *WS, opcode: u8, data: []const u8) !void {
        if (data.len > 65536) return error.FrameTooLarge;
        var h: [14]u8 = undefined;
        h[0] = 0x80 | opcode;
        var n: usize = 2;
        if (data.len < 126) {
            h[1] = @intCast(data.len);
        } else if (data.len < 65536) {
            h[1] = 126;
            std.mem.writeInt(u16, h[2..4], @intCast(data.len), .big);
            n = 4;
        } else {
            h[1] = 127;
            std.mem.writeInt(u64, h[2..10], data.len, .big);
            n = 10;
        }
        if (self.client) {
            h[1] |= 0x80;
            var mask: [4]u8 = undefined;
            try self.io.randomSecure(&mask);
            @memcpy(h[n..][0..4], &mask);
            n += 4;
            var scratch: [65536]u8 = undefined;
            for (data, 0..) |b, i| scratch[i] = b ^ mask[i % 4];
            try self.rawWrite(h[0..n]);
            try self.rawWrite(scratch[0..data.len]);
        } else {
            try self.rawWrite(h[0..n]);
            try self.rawWrite(data);
        }
    }
    pub fn send(self: *WS, a: std.mem.Allocator, message: Message) !void {
        var m = message;
        m.params = try fields(a, m.params, true, self.rust);
        m.result = try fields(a, m.result, true, self.rust);
        if (self.rust) {
            if (cfg.eq(m.type, "challenge")) {
                const nonce = try crypt.unb64(32, m.nonce);
                return self.frame(2, &nonce);
            }
            if (cfg.eq(m.type, "auth")) return self.frame(1, try std.json.Stringify.valueAlloc(a, RustAuth{ .id = m.peer_id, .signature = m.signature }, .{}));
            if (cfg.eq(m.type, "request")) return self.frame(1, try std.json.Stringify.valueAlloc(a, RustRequest{ .jsonrpc = "2.0", .id = m.id, .method = if (cfg.eq(m.method, "Agent.GrantAccess")) "AgentRPC.GrantAccess" else m.method, .params = m.params orelse return error.MissingParams }, .{}));
            if (!cfg.eq(m.type, "response")) return error.InvalidProtocol;
            if (m.@"error".len != 0) return self.frame(1, try std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = m.id, .@"error" = m.@"error" }, .{}));
            return self.frame(1, try std.json.Stringify.valueAlloc(a, .{ .jsonrpc = "2.0", .id = m.id, .result = m.result }, .{}));
        }
        try self.frame(1, try std.json.Stringify.valueAlloc(a, m, .{}));
    }
    fn decodeMessage(self: *WS, a: std.mem.Allocator, data: []const u8) !Message {
        if (!self.rust) {
            const m = try cfg.parse(Message, a, data);
            if (m.version != 1 or m.id > 9007199254740991) return error.InvalidProtocol;
            return m;
        }
        const tree = try cfg.parse(std.json.Value, a, data);
        if (tree != .object) return error.InvalidProtocol;
        if (!tree.object.contains("jsonrpc")) {
            const auth = try cfg.parse(RustAuth, a, data);
            return .{ .type = "auth", .peer_id = auth.id, .signature = auth.signature };
        }
        if (tree.object.contains("method")) {
            const r = try cfg.parse(RustRequest, a, data);
            if (!cfg.eq(r.jsonrpc, "2.0") or r.id == 0) return error.InvalidProtocol;
            return .{ .type = "request", .id = r.id, .method = if (cfg.eq(r.method, "AgentRPC.GrantAccess")) "Agent.GrantAccess" else r.method, .params = try fields(a, r.params, false, true) };
        }
        const r = try cfg.parse(RustResponse, a, data);
        if (!cfg.eq(r.jsonrpc, "2.0") or r.id == 0 or (r.result == null) == (r.@"error" == null)) return error.InvalidProtocol;
        return .{ .type = "response", .id = r.id, .result = try fields(a, r.result, false, true), .@"error" = r.@"error" orelse "" };
    }
    pub fn receive(self: *WS, a: std.mem.Allocator) !Message {
        self.read_deadline = p.now() + 10000;
        const buffer = try a.alloc(u8, 65536);
        var used: usize = 0;
        var fragmented = false;
        var frames: usize = 0;
        while (frames < 128) : (frames += 1) {
            var head: [2]u8 = undefined;
            try self.rawRead(&head);
            const opcode = head[0] & 15;
            const fin = head[0] & 0x80 != 0;
            if (head[0] & 0x70 != 0 or (head[1] & 0x80 != 0) == self.client) return error.InvalidFrame;
            var len: u64 = head[1] & 127;
            if (len == 126) {
                var ext: [2]u8 = undefined;
                try self.rawRead(&ext);
                len = std.mem.readInt(u16, &ext, .big);
                if (len < 126) return error.InvalidFrame;
            } else if (len == 127) {
                var ext: [8]u8 = undefined;
                try self.rawRead(&ext);
                len = std.mem.readInt(u64, &ext, .big);
                if (len < 65536) return error.InvalidFrame;
            }
            if (len > buffer.len - used) return error.FrameTooLarge;
            var mask: [4]u8 = @splat(0);
            if (!self.client) try self.rawRead(&mask);
            const payload = buffer[used..][0..@intCast(len)];
            try self.rawRead(payload);
            for (payload, 0..) |*b, i| b.* ^= mask[i % 4];
            if (opcode >= 8) {
                if (!fin or len > 125) return error.InvalidFrame;
                if (opcode == 8) return error.EndOfStream;
                if (opcode == 9) try self.frame(10, payload) else if (opcode != 10) return error.InvalidFrame;
                continue;
            }
            if (opcode == 2 and !self.authenticated and (self.rust or self.client) and !fragmented and fin and len == 32) {
                self.rust = true;
                return .{ .type = "challenge", .nonce = try crypt.b64(a, payload) };
            }
            if ((!fragmented and opcode != 1) or (fragmented and opcode != 0)) return error.InvalidFrame;
            used += @intCast(len);
            fragmented = true;
            if (fin) return self.decodeMessage(a, buffer[0..used]);
        }
        return error.TooManyFragments;
    }
    pub fn authClient(self: *WS, a: std.mem.Allocator, id: []const u8, key: cfg.Ed.KeyPair, broker: cfg.Ed.PublicKey) !void {
        const challenge = try self.receive(a);
        if (!cfg.eq(challenge.type, "challenge")) return error.AuthenticationFailed;
        const nonce = try crypt.unb64(32, challenge.nonce);
        try self.send(a, .{ .type = "auth", .peer_id = id, .signature = try crypt.sign(a, key, try crypt.signed(a, self.authDomain(), &.{ id, &nonce })) });
        var own: [32]u8 = undefined;
        try self.io.randomSecure(&own);
        try self.send(a, .{ .type = "challenge", .nonce = try crypt.b64(a, &own) });
        const response = try self.receive(a);
        if (!cfg.eq(response.type, "auth") or !cfg.eq(response.peer_id, "broker")) return error.AuthenticationFailed;
        try crypt.verify(broker, try crypt.signed(a, self.authDomain(), &.{ "broker", &own }), response.signature);
        self.authenticated = true;
    }
    pub fn authServer(self: *WS, a: std.mem.Allocator, config: cfg.Broker) ![]const u8 {
        var own: [32]u8 = undefined;
        try self.io.randomSecure(&own);
        try self.send(a, .{ .type = "challenge", .nonce = try crypt.b64(a, &own) });
        const response = try self.receive(a);
        if (!cfg.eq(response.type, "auth")) return error.AuthenticationFailed;
        var key: ?cfg.Ed.PublicKey = null;
        for (config.agents) |agent| if (cfg.eq(agent.id, response.peer_id)) {
            key = try cfg.publicKey(agent.pubkey);
        };
        for (config.clients) |client| if (cfg.eq(client.id, response.peer_id)) {
            key = try cfg.publicKey(client.pubkey);
        };
        try crypt.verify(key orelse return error.AuthenticationFailed, try crypt.signed(a, self.authDomain(), &.{ response.peer_id, &own }), response.signature);
        const challenge = try self.receive(a);
        if (!cfg.eq(challenge.type, "challenge")) return error.AuthenticationFailed;
        const nonce = try crypt.unb64(32, challenge.nonce);
        try self.send(a, .{ .type = "auth", .peer_id = "broker", .signature = try crypt.sign(a, try cfg.privateKey(config.private_key), try crypt.signed(a, self.authDomain(), &.{ "broker", &nonce })) });
        self.authenticated = true;
        return response.peer_id;
    }
};
