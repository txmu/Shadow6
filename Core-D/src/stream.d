module stream;
import native;
import core.stdc.string : memcmp;

@nogc nothrow:

enum MAX_CHUNK = 1024;
enum HEADER = 14;
enum MAX_FRAME = HEADER + MAX_CHUNK + 16;
enum DATA = 1;
enum CLOSE = 2;

private void put32(ubyte[] outBytes, uint value) {
    foreach (i; 0 .. 4) outBytes[3 - i] = cast(ubyte)(value >> (i * 8));
}
private uint get32(const(ubyte)[] bytes) {
    return (cast(uint)bytes[0] << 24) | (cast(uint)bytes[1] << 16) |
           (cast(uint)bytes[2] << 8) | bytes[3];
}
private void header(ref ubyte[HEADER] outBytes, ubyte kind, uint sequence, ushort length) {
    outBytes[0 .. 4] = cast(const(ubyte)[])"S6DS";
    outBytes[4] = 1; outBytes[5] = kind; outBytes[6] = 0; outBytes[7] = 0;
    put32(outBytes[8 .. 12], sequence);
    outBytes[12] = cast(ubyte)(length >> 8); outBytes[13] = cast(ubyte)length;
}
private void nonce(ref ubyte[12] outBytes, ubyte kind, uint sequence) {
    outBytes[] = 0; outBytes[0] = kind; put32(outBytes[4 .. 8], sequence);
}
private bool encodeFrame(ubyte[] frame, ubyte kind, uint sequence, const(ubyte)[] payload, ref const Key key) {
    if ((kind != DATA && kind != CLOSE) || payload.length > MAX_CHUNK ||
        (kind == DATA) != (payload.length > 0) || sequence == uint.max ||
        frame.length != HEADER + payload.length + 16) return false;
    ubyte[HEADER] head; ubyte[12] n;
    header(head, kind, sequence, cast(ushort)(payload.length + 16)); nonce(n, kind, sequence);
    frame[0 .. HEADER] = head[];
    return encrypt(key, n, head, payload, frame[HEADER .. $]);
}
private int receiveFrame(int socket, ref uint expected, ubyte[] payload, ref const Key key) {
    ubyte[HEADER] head; ubyte[MAX_CHUNK + 16] cipher; ubyte[12] n;
    if (d_read(socket, head.ptr, HEADER, 1) != HEADER || memcmp(head.ptr, "S6DS".ptr, 4) ||
        head[4] != 1 || head[6] || head[7]) return -1;
    ubyte kind = head[5]; uint sequence = get32(head[8 .. 12]);
    uint length = (cast(uint)head[12] << 8) | head[13];
    if ((kind != DATA && kind != CLOSE) || sequence != expected || sequence == uint.max || length < 16 ||
        length > MAX_CHUNK + 16 || d_read(socket, cipher.ptr, cast(int)length, 1) != length) return -1;
    nonce(n, kind, sequence);
    if (!decrypt(key, n, head, cipher[0 .. length], payload[0 .. length - 16])) return -1;
    ++expected;
    if (kind == CLOSE) return length == 16 ? 0 : -1;
    return length > 16 ? cast(int)length - 16 : -1;
}

private struct Direction {
    int local, remote;
    const(Key)* key;
    long deadline;
    bool sending;
}

private extern(C) int transfer(void* argument) {
    auto state = cast(Direction*)argument;
    uint sequence;
    // A worker owns its sequence, buffers and key direction for its lifetime.
    enum BATCH = 16;
    ubyte[MAX_CHUNK * BATCH] buffer;
    ubyte[MAX_FRAME * BATCH] wire;
    scope(exit) d_wipe(buffer.ptr, cast(int)buffer.length);
    while (d_clock() < state.deadline) {
        int input = state.sending ? state.local : state.remote;
        if (!d_ready(input)) {
            if (d_wait_pair(input, -1) < 0) return 0;
            continue;
        }
        if (state.sending) {
            int n = d_read(input, buffer.ptr, cast(int)buffer.length, 0);
            if (n < 0 || sequence == uint.max) return 0;
            size_t used, offset;
            do {
                size_t count = cast(size_t)n - offset;
                if (count > MAX_CHUNK) count = MAX_CHUNK;
                size_t length = HEADER + count + 16;
                if (!encodeFrame(wire[used .. used + length], n == 0 ? CLOSE : DATA,
                                 sequence, buffer[offset .. offset + count], *state.key)) return 0;
                ++sequence; used += length; offset += count;
            } while (offset < n);
            if (d_write(state.remote, wire.ptr, cast(int)used)) return 0;
            if (n == 0) return 1;
        } else {
            int n = receiveFrame(input, sequence, buffer, *state.key);
            if (n < 0 || (n > 0 && d_write(state.local, buffer.ptr, n))) return 0;
            if (n == 0) { d_half_close(state.local); return 1; }
        }
    }
    return 0;
}

bool relay(int local, int remote, ref const Key tx, ref const Key rx, uint lifetimeSeconds) {
    if (local < 0 || remote < 0 || !lifetimeSeconds || lifetimeSeconds > 86400) return false;
    long deadline = d_clock() + cast(long)lifetimeSeconds * 1000;
    Direction sender = Direction(local, remote, &tx, deadline, true);
    Direction receiver = Direction(local, remote, &rx, deadline, false);
    return d_run_pair(local, remote, &transfer, &sender, &receiver) != 0;
}
