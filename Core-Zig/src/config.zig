const std = @import("std");
const p = @import("platform.zig");
pub const Ed = std.crypto.sign.Ed25519;
pub const AgentRBAC = struct { id: []const u8, pubkey: []const u8 };
pub const ClientRBAC = struct { id: []const u8, pubkey: []const u8, allowed_agents: []const []const u8 };
pub const Broker = struct { listen_addr: []const u8, private_key: []const u8, agents: []const AgentRBAC, clients: []const ClientRBAC, webhook_url: []const u8 = "", stealth_mode: bool = true };
pub const Agent = struct { id: []const u8, broker_addrs: []const []const u8, broker_pubkey: []const u8, private_key: []const u8, target_port: u16, auto_close_after: u32, allow_local_discovery: bool = false, client_pubkeys: std.json.Value, transport: []const u8 = "enet", sni: ?[]const u8 = null, alpn: ?[]const u8 = null };
pub const Client = struct { id: []const u8, broker_addrs: []const []const u8, broker_pubkey: []const u8, private_key: []const u8, target_agent: []const u8, agent_pubkey: []const u8, on_success: []const u8 = "", allow_local_discovery: bool = false, transport: []const u8 = "enet", sni: ?[]const u8 = null, alpn: ?[]const u8 = null };
pub const Config = struct {
    role: []const u8,
    broker: ?Broker = null,
    agent: ?Agent = null,
    client: ?Client = null,
    pub fn validate(self: Config) !void {
        if (@as(u8, @intFromBool(self.broker != null)) + @intFromBool(self.agent != null) + @intFromBool(self.client != null) != 1) return error.InvalidRoleSection;
        if (eq(self.role, "broker")) {
            const b = self.broker orelse return error.InvalidRoleSection;
            _ = try endpoint(b.listen_addr);
            _ = try privateKey(b.private_key);
            if (b.webhook_url.len > 2048 or (b.webhook_url.len != 0 and !std.mem.startsWith(u8, b.webhook_url, "https://"))) return error.InvalidWebhook;
            if (b.webhook_url.len != 0) {
                var converted: [2048]u8 = undefined;
                _ = try url(try std.fmt.bufPrint(&converted, "wss://{s}", .{b.webhook_url[8..]}));
            }
            if (b.agents.len + b.clients.len > 256) return error.TooManyIdentities;
            for (b.agents, 0..) |a, i| {
                try identity(a.id);
                _ = try publicKey(a.pubkey);
                for (b.agents[0..i]) |other| if (eq(a.id, other.id)) return error.DuplicateIdentity;
            }
            for (b.clients, 0..) |cl, i| {
                try identity(cl.id);
                _ = try publicKey(cl.pubkey);
                for (b.clients[0..i]) |other| if (eq(cl.id, other.id)) return error.DuplicateIdentity;
                for (b.agents) |a| if (eq(cl.id, a.id)) return error.DuplicateIdentity;
                for (cl.allowed_agents) |id| {
                    var found = false;
                    for (b.agents) |a| {
                        if (eq(id, a.id)) found = true;
                    }
                    if (!found) return error.UnknownAgent;
                }
            }
        } else if (eq(self.role, "agent")) {
            const a = self.agent orelse return error.InvalidRoleSection;
            try identity(a.id);
            try urls(a.broker_addrs);
            _ = try publicKey(a.broker_pubkey);
            _ = try privateKey(a.private_key);
            if (a.target_port == 0 or a.auto_close_after == 0 or a.auto_close_after > 86400 or !eq(a.transport, "enet")) return error.InvalidAgent;
            if (a.allow_local_discovery) return error.LocalDiscoveryDisabledByRepositoryPolicy;
            if (a.client_pubkeys != .object or a.client_pubkeys.object.count() == 0 or a.client_pubkeys.object.count() > 256) return error.InvalidClientKeys;
            var it = a.client_pubkeys.object.iterator();
            while (it.next()) |v| {
                try identity(v.key_ptr.*);
                if (v.value_ptr.* != .string) return error.InvalidClientKeys;
                _ = try publicKey(v.value_ptr.string);
            }
        } else if (eq(self.role, "client")) {
            const cl = self.client orelse return error.InvalidRoleSection;
            try identity(cl.id);
            try identity(cl.target_agent);
            try urls(cl.broker_addrs);
            _ = try publicKey(cl.broker_pubkey);
            _ = try publicKey(cl.agent_pubkey);
            _ = try privateKey(cl.private_key);
            if (!eq(cl.transport, "enet") or cl.on_success.len > 4096) return error.InvalidClient;
            if (cl.allow_local_discovery) return error.LocalDiscoveryDisabledByRepositoryPolicy;
        } else return error.InvalidRole;
    }
};
pub fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
pub fn identity(value: []const u8) !void {
    if (value.len == 0 or value.len > 64) return error.InvalidIdentity;
    for (value) |b| if (!std.ascii.isAlphanumeric(b) and b != '-' and b != '_' and b != '.') return error.InvalidIdentity;
}
pub fn publicKey(value: []const u8) !Ed.PublicKey {
    var key: [32]u8 = undefined;
    if (value.len != 64) return error.InvalidKey;
    _ = try std.fmt.hexToBytes(&key, value);
    return Ed.PublicKey.fromBytes(key);
}
pub fn privateKey(value: []const u8) !Ed.KeyPair {
    var bytes: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    if (value.len != 64 and value.len != 128) return error.InvalidKey;
    _ = try std.fmt.hexToBytes(&bytes, value);
    const pair = try Ed.KeyPair.generateDeterministic(bytes[0..32].*);
    if (value.len == 128 and !eq(bytes[32..64], &pair.public_key.toBytes())) return error.InconsistentPrivateKey;
    return pair;
}
pub const Endpoint = struct { host: []const u8, port: u16 };
pub fn endpoint(value: []const u8) !Endpoint {
    const split = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidAddress;
    var host = value[0..split];
    if (host.len > 1 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    if (host.len == 0 or host.len > 253) return error.InvalidAddress;
    const port = try std.fmt.parseInt(u16, value[split + 1 ..], 10);
    return .{ .host = host, .port = port };
}
pub const URL = struct { host: []const u8, port: u16, path: []const u8, tls: bool };
pub fn url(value: []const u8) !URL {
    if (value.len == 0 or value.len > 2048) return error.InvalidURL;
    for (value) |b| if (b <= 32 or b == 127 or b == '@' or b == '#') return error.InvalidURL;
    const tls = !std.mem.startsWith(u8, value, "ws://");
    const rest = if (std.mem.startsWith(u8, value, "wss://")) value[6..] else if (!tls) value[5..] else value;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..slash];
    var ep = Endpoint{ .host = authority, .port = if (tls) 443 else 80 };
    if (std.mem.startsWith(u8, authority, "[")) {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidURL;
        ep.host = authority[1..end];
        if (end + 1 < authority.len) {
            if (authority[end + 1] != ':') return error.InvalidURL;
            ep.port = try std.fmt.parseInt(u16, authority[end + 2 ..], 10);
        }
        _ = try p.address(ep.host, ep.port);
    } else if (std.mem.indexOfScalar(u8, authority, ':') != null) {
        ep = try endpoint(authority);
    }
    if (ep.host.len == 0) return error.InvalidURL;
    if (ep.port == 0) return error.InvalidURL;
    for (ep.host) |b| if (!std.ascii.isAlphanumeric(b) and b != '.' and b != '-' and b != ':' and b != '%') return error.InvalidURL;
    if (!tls and !eq(ep.host, "localhost")) {
        const addr = p.address(ep.host, ep.port) catch return error.InsecureBrokerURL;
        if (!addr.loopback()) return error.InsecureBrokerURL;
    }
    return .{ .host = ep.host, .port = ep.port, .path = if (slash == rest.len) "/ws" else rest[slash..], .tls = tls };
}
fn urls(values: []const []const u8) !void {
    if (values.len == 0 or values.len > 16) return error.InvalidBrokerAddresses;
    for (values) |v| _ = try url(v);
}
// A lexical pass bounds nesting before the standard parser can allocate, and
// rejects floats even when the destination field is an integer.
pub fn lexical(data: []const u8) !void {
    if (data.len > 1048576 or !std.unicode.utf8ValidateSlice(data)) return error.InvalidJSON;
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    var number = false;
    for (data) |b| {
        if (quoted) {
            if (escaped) {
                escaped = false;
            } else if (b == '\\') {
                escaped = true;
            } else if (b == '"') {
                quoted = false;
            }
            continue;
        }
        if (b == '"') {
            quoted = true;
            number = false;
            continue;
        }
        if (b == '{' or b == '[') {
            depth += 1;
            if (depth > 32) return error.NestingLimit;
        }
        if (b == '}' or b == ']') {
            if (depth == 0) return error.InvalidJSON;
            depth -= 1;
        }
        if (std.ascii.isDigit(b) or b == '-') {
            number = true;
        } else if (number and (b == '.' or b == 'e' or b == 'E' or b == '+')) return error.FloatForbidden else number = false;
    }
    if (depth != 0 or quoted) return error.InvalidJSON;
}
pub fn parse(comptime T: type, a: std.mem.Allocator, data: []const u8) !T {
    try lexical(data);
    const options = std.json.ParseOptions{ .allocate = .alloc_always, .ignore_unknown_fields = false, .duplicate_field_behavior = .@"error", .max_value_len = 65536 };
    const tree = try std.json.parseFromSliceLeaky(std.json.Value, a, data, options);
    try portable(tree);
    try types(T, tree);
    return std.json.parseFromValueLeaky(T, a, tree, options);
}
fn portable(v: std.json.Value) anyerror!void {
    switch (v) {
        .integer => |n| if (n < -9007199254740991 or n > 9007199254740991) return error.IntegerOutOfRange,
        .float, .number_string => return error.FloatForbidden,
        .array => |arr| for (arr.items) |child| {
            try portable(child);
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |item| try portable(item.value_ptr.*);
        },
        else => {},
    }
}
fn types(comptime T: type, v: std.json.Value) anyerror!void {
    if (T == std.json.Value) return;
    switch (@typeInfo(T)) {
        .optional => |opt| {
            if (v != .null) try types(opt.child, v);
        },
        .int => if (v != .integer) return error.InvalidJSONType,
        .bool => if (v != .bool) return error.InvalidJSONType,
        .pointer => |ptr| {
            if (ptr.size != .slice) @compileError("unsupported JSON pointer");
            if (ptr.child == u8) {
                if (v != .string) return error.InvalidJSONType;
            } else {
                if (v != .array) return error.InvalidJSONType;
                for (v.array.items) |child| try types(ptr.child, child);
            }
        },
        .@"struct" => |s| {
            if (v != .object) return error.InvalidJSONType;
            inline for (s.fields) |field| {
                if (v.object.get(field.name)) |child| try types(field.type, child);
            }
        },
        else => @compileError("unsupported JSON type"),
    }
}
test "strict JSON bounds and OOM" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.FloatForbidden, lexical("{\"x\":1.0}"));
    try std.testing.expectError(error.DuplicateField, parse(struct { x: u8 }, a, "{\"x\":1,\"x\":2}"));
    try std.testing.expectError(error.UnknownField, parse(struct { x: u8 }, a, "{\"x\":1,\"y\":2}"));
    try std.testing.expectError(error.InvalidJSONType, parse(struct { x: u8 }, a, "{\"x\":\"1\"}"));
    var empty: [0]u8 = .{};
    var fba = std.heap.FixedBufferAllocator.init(&empty);
    try std.testing.expectError(error.OutOfMemory, parse(Config, fba.allocator(), "{\"role\":\"broker\"}"));
}
fn allocationProbe(a: std.mem.Allocator) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    _ = try parse(struct { id: []const u8, ports: []const u16 }, arena.allocator(), "{\"id\":\"agent\",\"ports\":[22,443]}");
}
test "all parser allocation failures propagate without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
test "plaintext broker URLs require parsed loopback literals" {
    try std.testing.expectError(error.InsecureBrokerURL, url("ws://127.attacker.example/ws"));
    try std.testing.expectError(error.InsecureBrokerURL, url("ws://192.0.2.1/ws"));
    _ = try url("ws://[::1]:1234/ws");
    _ = try url("ws://127.0.0.1:1234/ws");
}
