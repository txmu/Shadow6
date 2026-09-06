const std = @import("std");
const cfg = @import("config.zig");
const crypt = @import("crypto.zig");
const wire = @import("wire.zig");
const p = @import("platform.zig");
const Lifetime = @import("lifetime.zig").Lifetime;
const Tunnel = @import("tunnel.zig").Tunnel;
fn logError(err: anyerror) void {
    if (err == error.OutOfMemory) {
        p.write(2, "shadow6-zig: connection refused: out of memory\n") catch {};
        return;
    }
    var buf: [256]u8 = undefined;
    p.write(2, std.fmt.bufPrint(&buf, "shadow6-zig: {s}\n", .{@errorName(err)}) catch "connection closed\n") catch {};
}
fn dial(ws: *wire.WS, a: std.mem.Allocator, io: std.Io, urls: []const []const u8, id: []const u8, private: []const u8, public: []const u8) !void {
    var last: anyerror = error.NoBroker;
    for (urls) |text| {
        const url = try cfg.url(text);
        const addr = p.resolve(url.host, url.port) catch |e| {
            last = e;
            continue;
        };
        const fd = p.connect(&addr) catch |e| {
            last = e;
            continue;
        };
        ws.init(fd, true, a, io);
        ws.upgrade(url) catch |e| {
            p.close(fd);
            last = e;
            continue;
        };
        ws.authClient(a, id, try cfg.privateKey(private), try cfg.publicKey(public)) catch |e| {
            p.close(fd);
            last = e;
            continue;
        };
        return;
    }
    return last;
}
const Peer = struct {
    life: Lifetime = undefined,
    ws: wire.WS = undefined,
    id: [64]u8 = undefined,
    id_len: usize = 0,
    ip: [128]u8 = undefined,
    ip_len: usize = 0,
    agent: bool = false,
    fn name(self: *const Peer) []const u8 {
        return self.id[0..self.id_len];
    }
};
const Pending = struct { used: bool = false, agent: usize = 0, client: usize = 0, id: u64 = 0, client_id: u64 = 0, expires: i64 = 0, request: [2048]u8 = undefined, len: usize = 0 };
fn drop(peers: []?*Peer, pending: []Pending, index: usize, a: std.mem.Allocator) void {
    if (peers[index]) |peer| {
        p.close(peer.ws.fd);
        peer.life.deinit();
        a.destroy(peer);
        peers[index] = null;
    }
    for (pending) |*item| if (item.used and (item.agent == index or item.client == index)) {
        item.used = false;
    };
}
fn runBroker(a: std.mem.Allocator, io: std.Io, config: cfg.Broker) !void {
    const ep = try cfg.endpoint(config.listen_addr);
    const addr = try p.resolve(ep.host, ep.port);
    const listener = try p.bind(&addr, false);
    defer p.close(listener);
    var peers: [32]?*Peer = @splat(null);
    var pending: [32]Pending = @splat(.{});
    var next_id: u64 = 1;
    defer for (0..peers.len) |i| drop(&peers, &pending, i, a);
    var messages: Lifetime = undefined;
    try messages.init(a, 2 * 1024 * 1024);
    defer messages.deinit();
    try p.write(2, "[Broker] Zig control plane listening\n");
    while (true) {
        _ = messages.arena.reset(.retain_capacity);
        const ma = messages.allocator();
        var fds: [33]p.c.pollfd = undefined;
        fds[0] = .{ .fd = listener, .events = p.c.POLLIN, .revents = 0 };
        for (peers, 0..) |peer, i| fds[i + 1] = .{ .fd = if (peer) |v| v.ws.fd else -1, .events = p.c.POLLIN, .revents = 0 };
        if (p.c.poll(&fds, fds.len, 1000) < 0) continue;
        for (&pending) |*item| if (item.used and item.expires < p.now()) {
            if (peers[item.client]) |client| client.ws.send(ma, .{ .type = "response", .id = item.client_id, .@"error" = "agent provisioning timeout" }) catch {};
            item.used = false;
        };
        if (fds[0].revents & p.c.POLLIN != 0) {
            const fd = p.c.accept(listener, null, null);
            if (fd < 0) continue;
            var index: ?usize = null;
            for (peers, 0..) |peer, i| {
                if (peer == null) {
                    index = i;
                    break;
                }
            }
            const slot = index orelse {
                p.close(fd);
                continue;
            };
            const peer = a.create(Peer) catch |e| {
                p.close(fd);
                logError(e);
                continue;
            };
            peer.* = .{};
            peer.life.init(a, 2 * 1024 * 1024) catch |e| {
                p.close(fd);
                a.destroy(peer);
                logError(e);
                continue;
            };
            peers[slot] = peer;
            peer.ws.init(fd, false, peer.life.allocator(), io);
            peer.ws.upgrade(null) catch |e| {
                logError(e);
                drop(&peers, &pending, slot, a);
                continue;
            };
            const id = peer.ws.authServer(ma, config) catch |e| {
                logError(e);
                drop(&peers, &pending, slot, a);
                continue;
            };
            @memcpy(peer.id[0..id.len], id);
            peer.id_len = id.len;
            for (config.agents) |agent| if (cfg.eq(agent.id, id)) {
                peer.agent = true;
            };
            for (peers, 0..) |other, i| if (i != slot) {
                if (other) |v| if (cfg.eq(v.name(), id)) {
                    drop(&peers, &pending, i, a);
                };
            };
        }
        for (fds[1..], 0..) |fd, index| {
            if (fd.revents == 0) continue;
            const peer = peers[index] orelse continue;
            const message = peer.ws.receive(ma) catch |e| {
                logError(e);
                drop(&peers, &pending, index, a);
                continue;
            };
            handleBroker(ma, config, &peers, &pending, &next_id, index, message) catch |e| {
                logError(e);
                peer.ws.send(ma, .{ .type = "response", .id = message.id, .@"error" = @errorName(e) }) catch {
                    drop(&peers, &pending, index, a);
                };
            };
        }
    }
}
fn handleBroker(a: std.mem.Allocator, config: cfg.Broker, peers: []?*Peer, pending: []Pending, next_id: *u64, index: usize, message: wire.Message) !void {
    const peer = peers[index] orelse return error.PeerOffline;
    if (cfg.eq(message.type, "response")) {
        for (pending) |*item| {
            if (!item.used or item.id != message.id or item.agent != index) continue;
            defer item.used = false;
            const client = peers[item.client] orelse return;
            if (message.@"error".len != 0) {
                try client.ws.send(a, .{ .type = "response", .id = item.client_id, .@"error" = message.@"error" });
                return;
            }
            const req = try cfg.parse(wire.Request, a, item.request[0..item.len]);
            var resp = try wire.typed(wire.Response, a, message.result);
            if (!resp.success or resp.kcp_port == 0 or !cfg.eq(resp.transport, "enet")) return error.InvalidAgentResponse;
            var key: ?cfg.Ed.PublicKey = null;
            for (config.agents) |agent| if (cfg.eq(agent.id, peer.name())) {
                key = try cfg.publicKey(agent.pubkey);
            };
            try crypt.verify(key orelse return error.UnknownAgent, try wire.agentPayloadFor(a, req, resp, peer.ws.rust), resp.agent_sig);
            resp.target_ip = peer.ip[0..peer.ip_len];
            resp.dynamic_port = 0;
            try client.ws.send(a, .{ .type = "response", .id = item.client_id, .result = try wire.value(a, resp) });
            @import("webhook.zig").send(peer.life.parent, peer.ws.io, config, "Access Granted", req.client_id, req.target_agent, req.client_ip) catch |err| logError(err);
            return;
        }
        return error.UnknownResponse;
    }
    if (!cfg.eq(message.type, "request") or message.id == 0) return error.InvalidRequest;
    if (cfg.eq(message.method, "Broker.UpdateIP")) {
        if (!peer.agent) return error.AgentRequired;
        const req = try wire.typed(struct { agent_id: []const u8, ip: []const u8 }, a, message.params);
        _ = try peerIP(req.ip);
        if (req.ip.len > peer.ip.len) return error.InvalidAddress;
        @memcpy(peer.ip[0..req.ip.len], req.ip);
        peer.ip_len = req.ip.len;
        try peer.ws.send(a, .{ .type = "response", .id = message.id, .result = try wire.value(a, .{ .success = true }) });
        return;
    }
    if (!cfg.eq(message.method, "Broker.RequestAccess") or peer.agent) return error.MethodNotAllowed;
    var req = try wire.typed(wire.Request, a, message.params);
    req.client_id = peer.name();
    _ = try peerIP(req.client_ip);
    var authorized = false;
    for (config.clients) |cl| if (cfg.eq(cl.id, peer.name())) {
        try crypt.verify(try cfg.publicKey(cl.pubkey), try wire.clientPayloadFor(a, req, peer.ws.rust), req.client_sig);
        for (cl.allowed_agents) |id| if (cfg.eq(id, req.target_agent)) {
            authorized = true;
        };
    };
    if (!authorized) {
        @import("webhook.zig").send(peer.life.parent, peer.ws.io, config, "Unauthorized access attempt", req.client_id, req.target_agent, req.client_ip) catch |err| logError(err);
        return error.AccessDenied;
    }
    var agent_index: ?usize = null;
    for (peers, 0..) |other, i| if (other) |v| {
        if (v.agent and v.ip_len != 0 and cfg.eq(v.name(), req.target_agent)) agent_index = i;
    };
    const target = agent_index orelse return error.AgentOffline;
    if (peer.ws.rust != peers[target].?.ws.rust) return error.ControlDialectMismatch;
    for (pending) |*item| if (!item.used) {
        if (next_id.* >= 9007199254740991) return error.RequestLimit;
        const encoded = try std.json.Stringify.valueAlloc(a, req, .{});
        if (encoded.len > item.request.len) return error.RequestTooLarge;
        item.* = .{ .used = true, .agent = target, .client = index, .id = next_id.*, .client_id = message.id, .expires = p.now() + 15000, .len = encoded.len };
        @memcpy(item.request[0..encoded.len], encoded);
        next_id.* += 1;
        try peers[target].?.ws.send(a, .{ .type = "request", .id = item.id, .method = "Agent.GrantAccess", .params = try wire.value(a, req) });
        return;
    };
    return error.RequestLimit;
}
fn peerIP(ip: []const u8) !p.Address {
    const addr = try p.address(ip, 0);
    if (cfg.eq(ip, "0.0.0.0") or cfg.eq(ip, "::") or std.mem.startsWith(u8, ip, "ff") or (addr.storage.ss_family == p.c.AF_INET and @as(*const p.c.sockaddr_in, @ptrCast(&addr.storage)).sin_addr.s_addr & 0xf0 == 0xe0)) return error.InvalidAddress;
    return addr;
}
const Replay = struct { key: [32]u8 = @splat(0), until: i64 = 0 };
fn runAgent(a: std.mem.Allocator, io: std.Io, config: cfg.Agent) !void {
    var slots = std.atomic.Value(u32).init(0);
    var replay: [256]Replay = @splat(.{});
    while (true) {
        agentConnection(a, io, config, &slots, &replay) catch |e| logError(e);
        var ts = p.c.timespec{ .tv_sec = 1, .tv_nsec = 0 };
        _ = p.c.nanosleep(&ts, null);
    }
}
fn agentConnection(a: std.mem.Allocator, io: std.Io, config: cfg.Agent, slots: *std.atomic.Value(u32), replay: []Replay) !void {
    var life: Lifetime = undefined;
    try life.init(a, 4 * 1024 * 1024);
    defer life.deinit();
    var ws: wire.WS = undefined;
    try dial(&ws, life.allocator(), io, config.broker_addrs, config.id, config.private_key, config.broker_pubkey);
    defer p.close(ws.fd);
    var messages: Lifetime = undefined;
    try messages.init(a, 2 * 1024 * 1024);
    defer messages.deinit();
    var text: [128]u8 = undefined;
    const local = try p.local(ws.fd);
    const ip = try local.ip(&text);
    try ws.send(messages.allocator(), .{ .type = "request", .id = 1, .method = "Broker.UpdateIP", .params = try wire.value(messages.allocator(), .{ .agent_id = config.id, .ip = ip }) });
    var next_update: i64 = p.now() + 10000;
    var update_id: u64 = 2;
    while (true) {
        _ = messages.arena.reset(.retain_capacity);
        const ma = messages.allocator();
        if (p.now() >= next_update) {
            try ws.send(ma, .{ .type = "request", .id = update_id, .method = "Broker.UpdateIP", .params = try wire.value(ma, .{ .agent_id = config.id, .ip = ip }) });
            update_id += 1;
            next_update = p.now() + 10000;
        }
        ws.ready(1000) catch |e| {
            if (e == error.Timeout) continue;
            return e;
        };
        const message = try ws.receive(ma);
        if (cfg.eq(message.type, "response")) continue;
        const response = grant(a, ma, io, config, slots, replay, message, ws.rust) catch |e| {
            logError(e);
            try ws.send(ma, .{ .type = "response", .id = message.id, .@"error" = @errorName(e) });
            continue;
        };
        try ws.send(ma, .{ .type = "response", .id = message.id, .result = try wire.value(ma, response) });
    }
}
fn grant(a: std.mem.Allocator, ma: std.mem.Allocator, io: std.Io, config: cfg.Agent, slots: *std.atomic.Value(u32), replay: []Replay, message: wire.Message, rust: bool) !wire.Response {
    if (!cfg.eq(message.type, "request") or message.id == 0 or !cfg.eq(message.method, "Agent.GrantAccess")) return error.MethodNotAllowed;
    const req = try wire.typed(wire.Request, ma, message.params);
    if (!cfg.eq(req.target_agent, config.id)) return error.WrongAgent;
    const client_key = config.client_pubkeys.object.get(req.client_id) orelse return error.AccessDenied;
    try crypt.verify(try cfg.publicKey(client_key.string), try wire.clientPayloadFor(ma, req, rust), req.client_sig);
    const authorized = try peerIP(req.client_ip);
    const client_public = try crypt.unb64(32, req.e2ee_pubkey);
    var free: ?*Replay = null;
    for (replay) |*entry| {
        if (entry.until > p.now() and cfg.eq(&entry.key, &client_public)) return error.Replay;
        if (entry.until <= p.now()) free = entry;
    }
    const entry = free orelse return error.ReplayCapacity;
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);
    defer std.crypto.secureZero(u8, &seed);
    var ephemeral = try crypt.X.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, &ephemeral.secret_key);
    var shared = try crypt.X.scalarmult(ephemeral.secret_key, client_public);
    defer std.crypto.secureZero(u8, &shared);
    const tunnel = try Tunnel.create(a, crypt.derive(shared, client_public, ephemeral.public_key), authorized, config.target_port, config.auto_close_after, false, slots);
    errdefer tunnel.destroy();
    var resp = wire.Response{ .success = true, .kcp_port = (try p.local(tunnel.udp)).port(), .e2ee_pubkey = try crypt.b64(ma, &ephemeral.public_key) };
    resp.agent_sig = try crypt.sign(ma, try cfg.privateKey(config.private_key), try wire.agentPayloadFor(ma, req, resp, rust));
    try tunnel.start();
    entry.* = .{ .key = client_public, .until = p.now() + 86400000 };
    return resp;
}
fn runClient(a: std.mem.Allocator, io: std.Io, config: cfg.Client) !void {
    var life: Lifetime = undefined;
    try life.init(a, 4 * 1024 * 1024);
    defer life.deinit();
    const ma = life.allocator();
    var ws: wire.WS = undefined;
    try dial(&ws, ma, io, config.broker_addrs, config.id, config.private_key, config.broker_pubkey);
    defer p.close(ws.fd);
    var seed: [32]u8 = undefined;
    try io.randomSecure(&seed);
    defer std.crypto.secureZero(u8, &seed);
    var ephemeral = try crypt.X.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, &ephemeral.secret_key);
    var text: [128]u8 = undefined;
    const local = try p.local(ws.fd);
    var req = wire.Request{ .client_id = config.id, .target_agent = config.target_agent, .client_ip = try local.ip(&text), .e2ee_pubkey = try crypt.b64(ma, &ephemeral.public_key), .client_sig = "" };
    req.client_sig = try crypt.sign(ma, try cfg.privateKey(config.private_key), try wire.clientPayloadFor(ma, req, ws.rust));
    try ws.send(ma, .{ .type = "request", .id = 1, .method = "Broker.RequestAccess", .params = try wire.value(ma, req) });
    const message = try ws.receive(ma);
    if (!cfg.eq(message.type, "response") or message.id != 1 or message.@"error".len != 0) {
        if (message.@"error".len != 0) try p.write(2, message.@"error");
        return error.AccessDenied;
    }
    const resp = try wire.typed(wire.Response, ma, message.result);
    if (!resp.success or resp.kcp_port == 0 or !cfg.eq(resp.transport, "enet")) return error.InvalidAgentResponse;
    try crypt.verify(try cfg.publicKey(config.agent_pubkey), try wire.agentPayloadFor(ma, req, resp, ws.rust), resp.agent_sig);
    const agent_public = try crypt.unb64(32, resp.e2ee_pubkey);
    var shared = try crypt.X.scalarmult(ephemeral.secret_key, agent_public);
    defer std.crypto.secureZero(u8, &shared);
    var master = crypt.derive(shared, ephemeral.public_key, agent_public);
    defer std.crypto.secureZero(u8, &master);
    _ = try peerIP(resp.target_ip);
    const remote = try p.address(resp.target_ip, resp.kcp_port);
    const bind_addr = try p.address("127.0.0.1", 0);
    const listener = try p.bind(&bind_addr, false);
    defer p.close(listener);
    var line: [256]u8 = undefined;
    try p.write(2, try std.fmt.bufPrint(&line, "[Client] Secure local proxy listening on 127.0.0.1:{d}\n", .{(try p.local(listener)).port()}));
    if (config.on_success.len != 0) {
        const argv = try @import("hook.zig").arguments(ma, config.on_success, (try p.local(listener)).port(), resp.target_ip);
        var child = try std.process.spawn(io, .{ .argv = argv, .expand_arg0 = .expand });
        const thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, reapHook, .{ child, io }) catch |err| {
            child.kill(io);
            return err;
        };
        thread.detach();
    }
    var slots = std.atomic.Value(u32).init(0);
    while (true) {
        const fd = p.c.accept(listener, null, null);
        if (fd < 0) continue;
        const tunnel = Tunnel.create(a, master, remote, 0, 86400, true, &slots) catch |e| {
            p.close(fd);
            logError(e);
            continue;
        };
        tunnel.attach(fd, io) catch |e| {
            tunnel.destroy();
            logError(e);
            continue;
        };
        tunnel.start() catch |e| {
            tunnel.destroy();
            logError(e);
            continue;
        };
    }
}
pub fn run(a: std.mem.Allocator, io: std.Io, config: cfg.Config) !void {
    if (config.broker) |b| return runBroker(a, io, b);
    if (config.agent) |ag| return runAgent(a, io, ag);
    return runClient(a, io, config.client.?);
}
fn reapHook(process: std.process.Child, io: std.Io) void {
    var child = process;
    _ = child.wait(io) catch {};
}
