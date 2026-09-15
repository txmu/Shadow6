module packet;
import bounded;
import native;
import core.stdc.string : memcpy, memcmp;
@nogc nothrow:
enum MAX_DATA = 1024;
enum HEADER = 39;
enum MAX_PACKET = HEADER + MAX_DATA + 1 + 16;
enum MAX_SEQUENCE = uint.max - 1;
enum PacketKind : ubyte { data = 1, ack = 2, close = 3, hello = 4 }
alias SessionId = ubyte[16];
enum HELLO_SIZE = 193;
alias Hello = ubyte[HELLO_SIZE];

bool makeHello(ubyte kind, ref const SessionId session, long now, ref const Key identity,
               ref const Key ephemeral, ref const Key binding, ref const Secret signer, out Hello wire) {
    if ((kind != 1 && kind != 2) || now < 0) return false;
    wire[0 .. 8] = cast(const(ubyte)[])"S6DHEL02";
    wire[8] = kind; wire[9 .. 25] = session[];
    foreach(i; 0 .. 8) wire[32 - i] = cast(ubyte)(cast(ulong)now >> (i * 8));
    wire[33 .. 65] = identity[]; wire[65 .. 97] = ephemeral[]; wire[97 .. 129] = binding[];
    Signature sig;
    if (!sign(signer, wire[0 .. 129], sig)) return false;
    wire[129 .. $] = sig[]; return true;
}
bool checkHello(const(ubyte)[] wire, ubyte kind, long now, ref const Key identity, ref const Key binding) {
    if (wire.length != HELLO_SIZE || now < 0 || memcmp(wire.ptr, "S6DHEL02".ptr, 8) || wire[8] != kind ||
        memcmp(wire.ptr + 33, identity.ptr, 32) || memcmp(wire.ptr + 97, binding.ptr, 32)) return false;
    ulong stamp; foreach(b; wire[25 .. 33]) stamp = (stamp << 8) | b;
    if (stamp > cast(ulong)now + 30 || (cast(ulong)now > stamp && cast(ulong)now - stamp > 30)) return false;
    Signature sig; sig[] = wire[129 .. $];
    return verify(identity, wire[0 .. 129], sig);
}
// HKDF-Extract with the signed transcript hash as salt; directional expand
// labels prevent reflection. Fresh X25519 keys make replayed hellos harmless.
bool trafficKeys(ref const Key secret, ref const Key peerEphemeral, ref const Hello request,
                 ref const Hello response, out Key c2s, out Key s2c) {
    Key dh, salt, prk; ubyte[HELLO_SIZE * 2] transcript;
    scope(exit) { d_wipe(dh.ptr, 32); d_wipe(prk.ptr, 32); }
    if (!deriveShared(secret, peerEphemeral, dh)) return false;
    transcript[0 .. HELLO_SIZE] = request[]; transcript[HELLO_SIZE .. $] = response[];
    if (!hash(transcript, salt) || d_hmac(salt.ptr, dh.ptr, 32, prk.ptr)) return false;
    immutable c = "shadow6-d-v2/client-to-server\x01";
    immutable s = "shadow6-d-v2/server-to-client\x01";
    return d_hmac(prk.ptr, c.ptr, cast(int)c.length, c2s.ptr) == 0 &&
           d_hmac(prk.ptr, s.ptr, cast(int)s.length, s2c.ptr) == 0;
}

bool rleEncode(const(ubyte)[] input, ubyte[] output, out size_t used)
in { assert(input.length <= MAX_DATA && output.length >= input.length + 1); }
out(ok) { assert(!ok || (used > 0 && used <= input.length + 1 && used <= output.length)); }
do {
    used = 1; output[0] = 1;
    size_t p;
    while (p < input.length) {
        ubyte n = 1;
        while (p + n < input.length && n < 255 && input[p + n] == input[p]) ++n;
        if (used + 2 >= input.length + 1) {
            output[0] = 0;
            if (input.length) memcpy(output.ptr + 1, input.ptr, input.length);
            used = input.length + 1; return true;
        }
        output[used++] = n; output[used++] = input[p]; p += n;
    }
    if (!input.length) output[0] = 0;
    return true;
}
bool rleDecode(const(ubyte)[] input, ubyte[] output, out size_t used)
in { assert(input.length <= MAX_DATA + 1 && output.length == MAX_DATA); }
out(ok) { assert(used <= MAX_DATA && (!ok || used <= output.length)); }
do {
    used = 0;
    if (!input.length) return false;
    if (input[0] == 0) { used = input.length - 1; if (used) memcpy(output.ptr, input.ptr + 1, used); return true; }
    if (input[0] != 1 || input.length == 1 || (input.length - 1) % 2) return false;
    for (size_t p = 1; p < input.length; p += 2) {
        size_t n = input[p]; if (!n || n > output.length - used) return false;
        output[used .. used + n] = input[p + 1]; used += n;
    }
    return true;
}
void put32(ubyte[] b, uint v)
in { assert(b.length == 4); }
out { assert(b.length == 4); }
do { foreach(i; 0 .. 4) b[3 - i] = cast(ubyte)(v >> (i * 8)); }
uint get32(const(ubyte)[] b)
in { assert(b.length == 4); }
out(v) { assert(b.length == 4); }
do { return (cast(uint)b[0] << 24) | (cast(uint)b[1] << 16) | (cast(uint)b[2] << 8) | b[3]; }

struct Decoded {
    @nogc nothrow:
    PacketKind kind;
    uint sequence;
    ubyte[MAX_DATA] payload;
    size_t length;
    bool verified;
    invariant { assert(length <= MAX_DATA); }
}
struct Wire {
    @nogc nothrow:
    ubyte[MAX_PACKET] data;
    size_t length;
    invariant { assert(length <= MAX_PACKET); }
    const(ubyte)[] bytes() const { return data[0 .. length]; }
}

bool encodePacket(PacketKind kind, ref const SessionId session, uint sequence, long now,
                  const(ubyte)[] data, ref const Key key, out Wire wire)
in { assert(data.length <= MAX_DATA && sequence < MAX_SEQUENCE && now >= 0 && now <= 9007199254740991L); }
out(ok) { assert(!ok || (wire.length >= HEADER + 17 && wire.length <= MAX_PACKET)); }
do {
    if (kind < PacketKind.data || kind >= PacketKind.hello || (kind == PacketKind.data) != (data.length > 0)) return false;
    ubyte[MAX_DATA + 1] compressed; size_t n;
    if (!rleEncode(data, compressed, n)) return false;
    wire.data[0 .. 8] = cast(const(ubyte)[])"S6DUDP02";
    wire.data[8] = kind; wire.data[9 .. 25] = session[];
    put32(wire.data[25 .. 29], sequence);
    foreach(i; 0 .. 8) wire.data[36 - i] = cast(ubyte)(cast(ulong)now >> (i * 8));
    uint cipherLength = cast(uint)n + 16;
    wire.data[37] = cast(ubyte)(cipherLength >> 8); wire.data[38] = cast(ubyte)cipherLength;
    ubyte[12] nonce; nonce[0] = kind; put32(nonce[4 .. 8], sequence); put32(nonce[8 .. 12], cast(uint)now);
    if (!encrypt(key, nonce, wire.data[0 .. HEADER], compressed[0 .. n], wire.data[HEADER .. HEADER + cipherLength])) return false;
    wire.length = HEADER + cipherLength;
    return true;
}

private bool decodeBounded(const(ubyte)[] frame, ref const SessionId session, long now,
                          ref const Key key, out Decoded outPacket)
in { assert(frame.length <= MAX_PACKET && now >= 0 && now <= 9007199254740991L); }
out(ok) { assert(!ok || (outPacket.verified && outPacket.length <= MAX_DATA && outPacket.sequence < MAX_SEQUENCE)); }
do {
    if (frame.length < HEADER + 17 || memcmp(frame.ptr, "S6DUDP02".ptr, 8) || memcmp(frame.ptr + 9, session.ptr, 16)) return false;
    if (frame[8] < PacketKind.data || frame[8] >= PacketKind.hello) return false;
    uint n = (cast(uint)frame[37] << 8) | frame[38];
    if (n < 17 || n > MAX_DATA + 17 || n != frame.length - HEADER) return false;
    ulong stamp;
    foreach(b; frame[29 .. 37]) stamp = (stamp << 8) | b;
    if (stamp > cast(ulong)now + 30 || (cast(ulong)now > stamp && cast(ulong)now - stamp > 30)) return false;
    uint sequence = get32(frame[25 .. 29]); if (sequence >= MAX_SEQUENCE) return false;
    ubyte[12] nonce; nonce[0] = frame[8]; put32(nonce[4 .. 8], sequence); put32(nonce[8 .. 12], cast(uint)stamp);
    ubyte[MAX_DATA + 1] plain;
    if (!decrypt(key, nonce, frame[0 .. HEADER], frame[HEADER .. $], plain)) return false;
    if (!rleDecode(plain[0 .. n - 16], outPacket.payload, outPacket.length)) return false;
    if ((frame[8] == PacketKind.data) != (outPacket.length > 0)) return false;
    outPacket.kind = cast(PacketKind)frame[8]; outPacket.sequence = sequence; outPacket.verified = true;
    return true;
}

bool decodePacket(const(ubyte)[] frame, ref const SessionId session, long now,
                  ref const Key key, out Decoded result) {
    // Treat socket lengths and clocks as untrusted before invoking contracts.
    if (frame.length > MAX_PACKET || now < 0 || now > 9007199254740991L) return false;
    return decodeBounded(frame, session, now, key, result);
}

enum Action { ignore, deliver, acknowledge, finished }
struct ReceiveState {
    @nogc nothrow:
    private uint nextSequence;
    private bool closed;
    invariant { assert(nextSequence <= MAX_SEQUENCE); }
    Action accept(ref const Decoded p)
    in { assert(p.verified && p.sequence < MAX_SEQUENCE && p.length <= MAX_DATA); }
    out(action) { assert(nextSequence <= MAX_SEQUENCE); }
    do {
        if (p.kind != PacketKind.data && p.kind != PacketKind.close) return Action.ignore;
        if (p.sequence < nextSequence) return Action.acknowledge;
        if (closed || p.sequence != nextSequence) return Action.ignore;
        ++nextSequence;
        if (p.kind == PacketKind.close) { closed = true; return Action.finished; }
        return Action.deliver;
    }
    bool done() const { return closed; }
}
