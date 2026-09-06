module bounded;
import core.stdc.string : memcpy, memcmp;
@nogc nothrow:

enum MAX_JSON = 65536;
struct Buffer(size_t Capacity) {
    @nogc nothrow:
    private char[Capacity] storage;
    private size_t used;
    private bool failed;
    invariant { assert(used <= Capacity); }
    void clear() { used = 0; failed = false; }
    size_t length() const { return used; }
    bool good() const { return !failed; }
    const(char)[] text() const { return storage[0 .. used]; }
    const(ubyte)[] bytes() const { return cast(const(ubyte)[])text(); }
    bool append(const(char)[] s)
    in { assert(used <= Capacity); }
    out(ok) { assert(used <= Capacity); }
    do {
        if (failed || s.length > Capacity - used) { failed = true; return false; }
        if (s.length) memcpy(storage.ptr + used, s.ptr, s.length);
        used += s.length; return true;
    }
    bool chr(char c) { return append((&c)[0 .. 1]); }
    bool number(ulong v) {
        char[20] digits; size_t start = digits.length;
        do { digits[--start] = cast(char)('0' + v % 10); v /= 10; } while (v);
        return append(digits[start .. $]);
    }
    bool quoted(const(char)[] s) {
        if (!chr('"')) return false;
        foreach (char c; s) {
            if (c == '"' || c == '\\') { if (!chr('\\') || !chr(c)) return false; }
            else if (cast(ubyte)c < 32) {
                immutable hex = "0123456789abcdef";
                if (!append("\\u00") || !chr(hex[cast(ubyte)c / 16]) || !chr(hex[cast(ubyte)c % 16])) return false;
            } else if (!chr(c)) return false;
        }
        return chr('"');
    }
    const(char)* cstring() {
        if (failed || used == Capacity) { failed = true; return null; }
        storage[used] = 0; return storage.ptr;
    }
}
alias Text = Buffer!MAX_JSON;

bool equal(const(char)[] a, const(char)[] b) {
    return a.length == b.length && (a.length == 0 || memcmp(a.ptr, b.ptr, a.length) == 0);
}
bool starts(const(char)[] a, const(char)[] prefix) { return a.length >= prefix.length && equal(a[0 .. prefix.length], prefix); }
bool identity(const(char)[] s) {
    if (s.length == 0 || s.length > 64) return false;
    foreach (c; s) if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '.') return false;
    return true;
}
bool ascii(const(char)[] s) { foreach(c; s) if (cast(ubyte)c < 32 || cast(ubyte)c >= 127) return false; return true; }
bool utf8(const(char)[] s)
in { assert(s.length <= MAX_JSON); }
out(ok) { assert(s.length <= MAX_JSON); }
do {
    size_t i;
    while (i < s.length) {
        uint c = cast(ubyte)s[i++], n, min;
        if (c < 128) { if (c == 0) return false; continue; }
        if (c >= 0xc2 && c <= 0xdf) { c &= 31; n = 1; min = 128; }
        else if (c >= 0xe0 && c <= 0xef) { c &= 15; n = 2; min = 2048; }
        else if (c >= 0xf0 && c <= 0xf4) { c &= 7; n = 3; min = 65536; }
        else return false;
        if (n > s.length - i) return false;
        foreach (_; 0 .. n) { uint b = cast(ubyte)s[i++]; if ((b & 0xc0) != 0x80) return false; c = (c << 6) | (b & 63); }
        if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return false;
    }
    return true;
}
bool hexDecode(const(char)[] s, ubyte[] output)
in { assert(output.length <= MAX_JSON / 2); }
out(ok) { assert(!ok || s.length == output.length * 2); }
do {
    if (s.length != output.length * 2) return false;
    foreach (i; 0 .. output.length) {
        uint v;
        foreach (c; s[i * 2 .. i * 2 + 2]) { v *= 16;
            if (c >= '0' && c <= '9') v += c - '0'; else if (c >= 'a' && c <= 'f') v += c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v += c - 'A' + 10; else return false;
        }
        output[i] = cast(ubyte)v;
    }
    return true;
}
bool hexEncode(size_t N)(const(ubyte)[] data, ref Buffer!N outText)
in { assert(data.length <= MAX_JSON / 2); }
out(ok) { assert(!ok || outText.good); }
do { immutable h = "0123456789abcdef"; foreach(b; data) if (!outText.chr(h[b / 16]) || !outText.chr(h[b % 16])) return false; return true; }

bool base64Encode(size_t N)(const(ubyte)[] data, ref Buffer!N outText)
in { assert(data.length <= MAX_JSON / 2); }
out(ok) { assert(!ok || outText.good); }
do {
    immutable t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i; i < data.length; i += 3) {
        uint a = data[i], b = i + 1 < data.length ? data[i + 1] : 0, c = i + 2 < data.length ? data[i + 2] : 0;
        if (!outText.chr(t[a >> 2]) || !outText.chr(t[(a & 3) * 16 + (b >> 4)]) ||
            !outText.chr(i + 1 < data.length ? t[(b & 15) * 4 + (c >> 6)] : '=') || !outText.chr(i + 2 < data.length ? t[c & 63] : '=')) return false;
    }
    return true;
}
bool base64Decode(const(char)[] s, ubyte[] output)
in { assert(output.length <= MAX_JSON / 2); }
out(ok) { assert(!ok || s.length == (output.length + 2) / 3 * 4); }
do {
    if (s.length != (output.length + 2) / 3 * 4) return false;
    size_t outPos; uint bits, n;
    foreach (i, c; s) {
        if (c == '=') { if (outPos != output.length || i < s.length - 2 || bits != 0) return false; continue; }
        if (i && s[i - 1] == '=') return false;
        uint v;
        if(c >= 'A' && c <= 'Z') v = c - 'A'; else if(c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if(c >= '0' && c <= '9') v = c - '0' + 52; else if(c == '+') v = 62; else if(c == '/') v = 63; else return false;
        bits = (bits << 6) | v; n += 6;
        if (n >= 8) { n -= 8; if (outPos == output.length) return false; output[outPos++] = cast(ubyte)(bits >> n); bits &= (1u << n) - 1; }
    }
    return outPos == output.length && bits == 0;
}
