const std = @import("std");
const cfg = @import("config.zig");
const p = @import("platform.zig");
const WS = @import("wire.zig").WS;
const Lifetime = @import("lifetime.zig").Lifetime;
var slots = std.atomic.Value(u32).init(0);
const Job = struct {
    life: Lifetime = undefined,
    url: []const u8,
    body: []const u8,
    io: std.Io,
    fn destroy(self: *Job) void {
        const a = self.life.parent;
        self.life.deinit();
        a.destroy(self);
        _ = slots.fetchSub(1, .seq_cst);
    }
    fn run(self: *Job) void {
        defer self.destroy();
        self.perform() catch {};
    }
    fn perform(self: *Job) !void {
        const url = try cfg.url(self.url);
        const addr = try p.resolve(url.host, url.port);
        const fd = try p.connect(&addr);
        defer p.close(fd);
        var ws: WS = undefined;
        ws.init(fd, true, self.life.allocator(), self.io);
        try ws.post(url, self.body);
    }
};
pub fn send(a: std.mem.Allocator, io: std.Io, config: cfg.Broker, status: []const u8, id: []const u8, target: []const u8, ip: []const u8) !void {
    if (config.webhook_url.len == 0) return;
    if (slots.fetchAdd(1, .seq_cst) >= 4) {
        _ = slots.fetchSub(1, .seq_cst);
        return error.WebhookCapacity;
    }
    errdefer _ = slots.fetchSub(1, .seq_cst);
    const job = try a.create(Job);
    errdefer a.destroy(job);
    job.* = .{ .url = undefined, .body = undefined, .io = io };
    try job.life.init(a, 4 * 1024 * 1024);
    errdefer job.life.deinit();
    const ma = job.life.allocator();
    job.url = try std.fmt.allocPrint(ma, "wss://{s}", .{config.webhook_url[8..]});
    var timestamp: [32]u8 = undefined;
    var clock: p.c.time_t = p.c.time(null);
    var tm: p.c.struct_tm = undefined;
    if (p.c.gmtime_r(&clock, &tm) == null) return error.InvalidTime;
    const count = p.c.strftime(&timestamp, timestamp.len, "%Y-%m-%dT%H:%M:%SZ", &tm);
    job.body = try std.json.Stringify.valueAlloc(ma, .{ .event = "AccessRequest", .status = status, .client_id = id, .target_agent = target, .client_ip = if (config.stealth_mode) "IP[MASKED]" else ip, .timestamp = timestamp[0..count] }, .{});
    const thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, Job.run, .{job});
    thread.detach();
}
