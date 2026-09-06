const std = @import("std");
const cfg = @import("config.zig");
const p = @import("platform.zig");
pub const features = .{ .core = "shadow6-zig", .version = "1.1.0", .crosed_compiled = false, .crosed_max_level = @as(u8, 0), .app_transport = false, .qubes_isolation = false, .gate_compiled = true, .gate_enabled_by_default = false, .utf8 = true, .crosed_capabilities = [0][]const u8{} };
fn run(init: std.process.Init) !void {
    _ = p.c.signal(p.c.SIGPIPE, p.c.SIG_IGN);
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try init.minimal.args.toSlice(a);
    var config: ?[]const u8 = null;
    var role: ?[]const u8 = null;
    var request: ?[]const u8 = null;
    var trust: ?[]const u8 = null;
    var report = false;
    var gen = false;
    var check = false;
    var daemon = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (cfg.eq(arg, "--feature-report")) {
            report = true;
        } else if (cfg.eq(arg, "--gen-key")) {
            gen = true;
        } else if (cfg.eq(arg, "--check-config")) {
            check = true;
        } else if (cfg.eq(arg, "--daemon")) {
            daemon = true;
        } else if (cfg.eq(arg, "--help")) {
            try p.write(1, "shadow6-zig --config FILE [--check-config|--daemon]\n--gen-key | --init-config ROLE | --feature-report | --crosed-request FILE --crosed-trust FILE\n");
            return;
        } else {
            i += 1;
            if (i == args.len) return error.MissingArgument;
            if (cfg.eq(arg, "--config")) {
                config = args[i];
            } else if (cfg.eq(arg, "--init-config")) {
                role = args[i];
            } else if (cfg.eq(arg, "--crosed-request")) {
                request = args[i];
            } else if (cfg.eq(arg, "--crosed-trust")) {
                trust = args[i];
            } else return error.UnknownArgument;
        }
    }
    if (gen) {
        var seed: [32]u8 = undefined;
        try init.io.randomSecure(&seed);
        defer std.crypto.secureZero(u8, &seed);
        const key = try cfg.Ed.KeyPair.generateDeterministic(seed);
        const private = std.fmt.bytesToHex(key.secret_key.toBytes(), .lower);
        const public = std.fmt.bytesToHex(key.public_key.toBytes(), .lower);
        try p.write(1, try std.fmt.allocPrint(a, "Private Key (Hex): {s}\nPublic Key (Hex):  {s}\n", .{ private, public }));
        return;
    }
    if (report) {
        try p.write(1, try std.json.Stringify.valueAlloc(a, features, .{}));
        try p.write(1, "\n");
        return;
    }
    if (request != null) {
        if (trust == null) return error.CrosedTrustRequired;
        var response = try @import("wire.zig").value(a, features);
        try response.object.put(a, "mod_id", .{ .string = "" });
        try response.object.put(a, "granted_level", .{ .integer = 0 });
        try response.object.put(a, "granted_capabilities", .{ .array = std.array_list.Managed(std.json.Value).init(a) });
        try response.object.put(a, "status", .{ .string = "denied" });
        try response.object.put(a, "reason", .{ .string = "crosed is not compiled into this core" });
        try p.write(1, try std.json.Stringify.valueAlloc(a, response, .{}));
        try p.write(1, "\n");
        return;
    }
    if (role) |r| {
        const body = if (cfg.eq(r, "broker"))
            "{\"role\":\"broker\",\"broker\":{\"listen_addr\":\"127.0.0.1:4433\",\"private_key\":\"<HEX_PRIVATE_KEY>\",\"agents\":[],\"clients\":[],\"webhook_url\":\"\",\"stealth_mode\":true}}\n"
        else if (cfg.eq(r, "agent"))
            "{\"role\":\"agent\",\"agent\":{\"id\":\"nas-1\",\"broker_addrs\":[\"wss://broker.example/ws\"],\"broker_pubkey\":\"<BROKER_PUB_KEY>\",\"private_key\":\"<HEX_PRIVATE_KEY>\",\"target_port\":22,\"auto_close_after\":7200,\"allow_local_discovery\":false,\"transport\":\"enet\",\"client_pubkeys\":{\"laptop-1\":\"<CLIENT_PUB_KEY>\"}}}\n"
        else if (cfg.eq(r, "client"))
            "{\"role\":\"client\",\"client\":{\"id\":\"laptop-1\",\"broker_addrs\":[\"wss://broker.example/ws\"],\"broker_pubkey\":\"<BROKER_PUB_KEY>\",\"private_key\":\"<HEX_PRIVATE_KEY>\",\"target_agent\":\"nas-1\",\"agent_pubkey\":\"<AGENT_PUB_KEY>\",\"on_success\":\"\",\"allow_local_discovery\":false,\"transport\":\"enet\"}}\n"
        else
            return error.InvalidRole;
        try p.secretWrite("config.json.example", body);
        try p.write(1, "Template written to config.json.example\n");
        return;
    }
    const path = config orelse return error.ConfigRequired;
    const data = try p.secretRead(a, path);
    const parsed = try cfg.parse(cfg.Config, a, data);
    try parsed.validate();
    if (check) {
        try p.write(1, try std.fmt.allocPrint(a, "Configuration {s} is valid for role {s}\n", .{ path, parsed.role }));
        return;
    }
    if (daemon) {
        if (args.len > 63) return error.TooManyArguments;
        var child_args: [64]?[*:0]const u8 = @splat(null);
        var count: usize = 0;
        for (args) |arg| {
            if (cfg.eq(arg, "--daemon")) continue;
            child_args[count] = arg.ptr;
            count += 1;
        }
        const pid = p.c.fork();
        if (pid < 0) return error.DaemonFailed;
        if (pid != 0) return;
        if (p.c.setsid() < 0) p.c._exit(2);
        _ = p.c.execv(args[0].ptr, @ptrCast(&child_args));
        p.c._exit(2);
    }
    try @import("runtime.zig").run(init.gpa, init.io, parsed);
}
pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        if (err == error.OutOfMemory) {
            p.write(2, "shadow6-zig: out of memory; operation refused\n") catch {};
        } else {
            var buf: [256]u8 = undefined;
            p.write(2, std.fmt.bufPrint(&buf, "shadow6-zig: {s}\n", .{@errorName(err)}) catch "shadow6-zig: failure\n") catch {};
        }
        std.process.exit(2);
    };
}
test {
    _ = @import("config.zig");
    _ = @import("enet.zig");
    _ = @import("hook.zig");
}
