module json;
import bounded;
import core.stdc.string : memcpy;
@nogc nothrow:
enum Kind : ubyte { nil, object, array, str, number, boolean }
struct Node {
    Kind kind;
    ushort child, next;
    uint keyStart, keyLength, start, length, rawStart, rawLength;
    long integer;
}
struct Document {
    @nogc nothrow:
    private enum LIMIT = 512;
    private Node[LIMIT + 1] nodes;
    private char[MAX_JSON] source, pool;
    private size_t sourceLength, poolLength;
    private ushort count;
    private bool valid;
    invariant { assert(count <= LIMIT && poolLength <= MAX_JSON && sourceLength <= MAX_JSON); }
    bool parse(const(char)[] input)
    in { assert(input.length <= MAX_JSON); }
    out(ok) { assert(!ok || (valid && count > 0)); }
    do {
        valid = false; count = 0; poolLength = 0; sourceLength = input.length;
        if (!input.length || !utf8(input)) return false;
        memcpy(source.ptr, input.ptr, input.length);
        size_t pos; ushort root;
        if (!value(pos, 0, root)) return false;
        spaces(pos);
        valid = pos == sourceLength && root == 1;
        return valid;
    }
    Kind kind(ushort i) const { return i && i <= count ? nodes[i].kind : Kind.nil; }
    ushort child(ushort i) const { return i && i <= count ? nodes[i].child : 0; }
    ushort next(ushort i) const { return i && i <= count ? nodes[i].next : 0; }
    const(char)[] key(ushort i) const {
        if (!i || i > count) return null;
        auto n = nodes[i]; return pool[n.keyStart .. n.keyStart + n.keyLength];
    }
    const(char)[] text(ushort i) const {
        if (kind(i) != Kind.str) return null;
        auto n = nodes[i]; return pool[n.start .. n.start + n.length];
    }
    const(char)[] raw(ushort i) const {
        if (!valid || !i || i > count) return null;
        auto n = nodes[i]; return source[n.rawStart .. n.rawStart + n.rawLength];
    }
    long number(ushort i, long otherwise = -1) const { return kind(i) == Kind.number ? nodes[i].integer : otherwise; }
    bool boolean(ushort i) const { return kind(i) == Kind.boolean && nodes[i].integer == 1; }
    ushort get(ushort parent, const(char)[] name) const
    in { assert(parent <= LIMIT); }
    out(i) { assert(i <= count); }
    do {
        if (!valid || kind(parent) != Kind.object) return 0;
        for (ushort i = child(parent); i; i = next(i)) if (equal(key(i), name)) return i;
        return 0;
    }
    const(char)[] field(ushort parent, const(char)[] name) const { return text(get(parent, name)); }
    bool fields(ushort parent, const(char)[] allowed) const
    in { assert(parent <= LIMIT); }
    out(ok) { assert(!ok || kind(parent) == Kind.object); }
    do {
        if (!valid || kind(parent) != Kind.object) return false;
        for (ushort i = child(parent); i; i = next(i)) {
            bool found; size_t start;
            foreach (p; 0 .. allowed.length + 1) {
                if (p == allowed.length || allowed[p] == '|') {
                    if (equal(key(i), allowed[start .. p])) found = true;
                    start = p + 1;
                }
            }
            if (!found) return false;
        }
        return true;
    }
    private void spaces(ref size_t p)
    in { assert(p <= sourceLength); }
    out { assert(p <= sourceLength); }
    do { while (p < sourceLength && (source[p] == ' ' || source[p] == '\t' || source[p] == '\r' || source[p] == '\n')) ++p; }
    private bool take(ref size_t p, char c)
    in { assert(p <= sourceLength); }
    out(ok) { assert(p <= sourceLength); }
    do { if (p == sourceLength || source[p] != c) return false; ++p; return true; }
    private bool put(uint c)
    in { assert(poolLength <= MAX_JSON); }
    out(ok) { assert(poolLength <= MAX_JSON); }
    do {
        if (c == 0 || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return false;
        size_t n = c < 128 ? 1 : c < 2048 ? 2 : c < 65536 ? 3 : 4;
        if (n > MAX_JSON - poolLength) return false;
        if (n == 1) pool[poolLength++] = cast(char)c;
        else {
            pool[poolLength++] = cast(char)((n == 2 ? 0xc0 : n == 3 ? 0xe0 : 0xf0) | (c >> (6 * (n - 1))));
            for (size_t i = n - 1; i; --i) pool[poolLength++] = cast(char)(0x80 | ((c >> (6 * (i - 1))) & 63));
        }
        return true;
    }
    private bool hex4(ref size_t p, out uint v)
    in { assert(p <= sourceLength); }
    out(ok) { assert(p <= sourceLength && (!ok || v <= 65535)); }
    do {
        if (sourceLength - p < 4) return false;
        foreach (_; 0 .. 4) {
            char c = source[p++]; uint digit;
            if (c >= '0' && c <= '9') digit = c - '0'; else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10; else return false;
            v = v * 16 + digit;
        }
        return true;
    }
    private bool stringValue(ref size_t p, out uint start, out uint len)
    in { assert(p <= sourceLength && poolLength <= MAX_JSON); }
    out(ok) { assert(p <= sourceLength && (!ok || (start <= poolLength && len <= poolLength - start))); }
    do {
        if (!take(p, '"')) return false;
        start = cast(uint)poolLength;
        while (p < sourceLength) {
            char c = source[p++];
            if (c == '"') { len = cast(uint)poolLength - start; return len <= 16384; }
            if (cast(ubyte)c < 32 || poolLength - start >= 16384 || poolLength == MAX_JSON) return false;
            if (c != '\\') { pool[poolLength++] = c; continue; }
            if (p == sourceLength) return false;
            c = source[p++];
            switch (c) {
                case '"', '\\', '/': pool[poolLength++] = c; break;
                case 'b': pool[poolLength++] = '\b'; break;
                case 'f': pool[poolLength++] = '\f'; break;
                case 'n': pool[poolLength++] = '\n'; break;
                case 'r': pool[poolLength++] = '\r'; break;
                case 't': pool[poolLength++] = '\t'; break;
                case 'u':
                    uint v, w; if (!hex4(p, v)) return false;
                    if (v >= 0xd800 && v <= 0xdbff) {
                        if (!take(p, '\\') || !take(p, 'u') || !hex4(p, w) || w < 0xdc00 || w > 0xdfff) return false;
                        v = 65536 + (v - 0xd800) * 1024 + w - 0xdc00;
                    }
                    if (!put(v)) return false;
                    break;
                default: return false;
            }
        }
        return false;
    }
    private bool value(ref size_t p, uint depth, out ushort index)
    in { assert(p <= sourceLength && count <= LIMIT); }
    out(ok) { assert(p <= sourceLength && (!ok || (index > 0 && index <= count))); }
    do {
        spaces(p); if (p == sourceLength || depth > 16 || count == LIMIT) return false;
        index = ++count; nodes[index] = Node.init;
        nodes[index].rawStart = cast(uint)p;
        char c = source[p];
        if (c == '{' || c == '[') {
            bool obj = c == '{'; char closing = obj ? '}' : ']';
            nodes[index].kind = obj ? Kind.object : Kind.array; ++p; spaces(p);
            if (p < sourceLength && source[p] == closing) ++p;
            else {
                ushort previous;
                while (true) {
                    uint ks, kl;
                    if (obj) {
                        spaces(p); if (!stringValue(p, ks, kl)) return false; spaces(p); if (!take(p, ':')) return false;
                        for (ushort child = nodes[index].child; child; child = nodes[child].next)
                            if (equal(key(child), pool[ks .. ks + kl])) return false;
                    }
                    ushort child;
                    if (!value(p, depth + 1, child)) return false;
                    nodes[child].keyStart = ks; nodes[child].keyLength = kl;
                    if (previous) nodes[previous].next = child; else nodes[index].child = child;
                    previous = child; spaces(p);
                    if (take(p, closing)) break;
                    if (!take(p, ',')) return false;
                }
            }
        } else if (c == '"') {
            nodes[index].kind = Kind.str;
            if (!stringValue(p, nodes[index].start, nodes[index].length)) return false;
        } else if (c == 't' || c == 'f' || c == 'n') {
            immutable lit = c == 't' ? "true" : c == 'f' ? "false" : "null";
            if (!starts(source[p .. sourceLength], lit)) return false;
            p += lit.length; nodes[index].kind = c == 'n' ? Kind.nil : Kind.boolean; nodes[index].integer = c == 't';
        } else {
            bool negative = c == '-'; if (negative) ++p;
            if (p == sourceLength || source[p] < '0' || source[p] > '9') return false;
            ulong v;
            if (source[p] == '0') ++p;
            else while (p < sourceLength && source[p] >= '0' && source[p] <= '9') {
                uint digit = source[p++] - '0';
                if (v > (9007199254740991UL - digit) / 10) return false;
                v = v * 10 + digit;
            }
            nodes[index].kind = Kind.number; nodes[index].integer = negative ? -cast(long)v : cast(long)v;
        }
        nodes[index].rawLength = cast(uint)p - nodes[index].rawStart;
        return true;
    }
}

// Public network/config gate: oversized input never reaches a contract assertion.
bool parseUntrusted(ref Document doc, const(char)[] input) {
    if (input.length > MAX_JSON) return false;
    return doc.parse(input);
}
