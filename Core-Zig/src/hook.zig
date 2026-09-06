const std = @import("std");
// This is the existing owner-authored client hook contract. No shell parsing,
// shell expansion, command substitution, or remotely supplied commands.
pub fn arguments(a: std.mem.Allocator, text: []const u8, port: u16, ip: []const u8) ![]const []const u8 {
    if (text.len > 4096 or std.mem.indexOfScalar(u8, text, 0) != null) return error.InvalidHook;
    const port_text = try std.fmt.allocPrint(a, "{d}", .{port});
    const first = try std.mem.replaceOwned(u8, a, text, "$LOCAL_TCP_PORT", port_text);
    const expanded = try std.mem.replaceOwned(u8, a, first, "$TARGET_IP", ip);
    if (expanded.len > 8192) return error.InvalidHook;
    const buffer = try a.alloc(u8, expanded.len);
    var args = std.ArrayList([]const u8).empty;
    var count: usize = 0;
    var start: usize = 0;
    var quote: u8 = 0;
    var escaped = false;
    for (expanded) |ch| {
        if (escaped) {
            buffer[count] = ch;
            count += 1;
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (quote != 0) {
            if (ch == quote) {
                quote = 0;
            } else {
                buffer[count] = ch;
                count += 1;
            }
            continue;
        }
        if (ch == '\'' or ch == '"') {
            quote = ch;
            continue;
        }
        if (std.ascii.isWhitespace(ch)) {
            if (count > start) {
                if (args.items.len == 64) return error.InvalidHook;
                try args.append(a, buffer[start..count]);
                start = count;
            }
        } else {
            buffer[count] = ch;
            count += 1;
        }
    }
    if (escaped or quote != 0) return error.InvalidHook;
    if (count > start) try args.append(a, buffer[start..count]);
    if (args.items.len == 0 or args.items.len > 64) return error.InvalidHook;
    return args.items;
}
test "hook substitution is argv only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const args = try arguments(arena.allocator(), "ssh 'user@localhost' -p $LOCAL_TCP_PORT '$TARGET_IP;touch forbidden'", 1234, "127.0.0.1");
    try std.testing.expectEqualStrings("1234", args[3]);
    try std.testing.expectEqualStrings("127.0.0.1;touch forbidden", args[4]);
}
