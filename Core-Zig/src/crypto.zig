const std = @import("std");
const cfg = @import("config.zig");
pub const X = std.crypto.dh.X25519;
pub fn signed(a: std.mem.Allocator, domain: []const u8, fields: []const []const u8) ![]u8 {
    var len = domain.len;
    for (fields) |f| {
        if (f.len > 65536) return error.FieldTooLarge;
        len += 4 + f.len;
    }
    const out = try a.alloc(u8, len);
    @memcpy(out[0..domain.len], domain);
    var off = domain.len;
    for (fields) |f| {
        std.mem.writeInt(u32, out[off..][0..4], @intCast(f.len), .big);
        off += 4;
        @memcpy(out[off..][0..f.len], f);
        off += f.len;
    }
    return out;
}
pub fn b64(a: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const out = try a.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    return std.base64.standard.Encoder.encode(out, bytes);
}
pub fn unb64(comptime n: usize, value: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    if (try std.base64.standard.Decoder.calcSizeForSlice(value) != n) return error.InvalidEncoding;
    try std.base64.standard.Decoder.decode(&out, value);
    return out;
}
pub fn verify(key: cfg.Ed.PublicKey, bytes: []const u8, signature: []const u8) !void {
    try cfg.Ed.Signature.fromBytes(try unb64(64, signature)).verify(bytes, key);
}
pub fn sign(a: std.mem.Allocator, key: cfg.Ed.KeyPair, bytes: []const u8) ![]const u8 {
    return b64(a, &(try key.sign(bytes, null)).toBytes());
}
pub fn derive(shared: [32]u8, client: [32]u8, agent: [32]u8) [32]u8 {
    const H = std.crypto.auth.hmac.sha2.HmacSha256;
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &client);
    @memcpy(input[32..64], &agent);
    var salt: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &salt, .{});
    var prk: [32]u8 = undefined;
    H.create(&prk, &shared, &salt);
    var key: [32]u8 = undefined;
    H.create(&key, "shadow6-enet-v1\x01", &prk);
    std.crypto.secureZero(u8, &prk);
    return key;
}
