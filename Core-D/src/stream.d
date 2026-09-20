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
private bool sendFrame(int socket, ubyte kind, uint sequence, const(ubyte)[] payload, ref const Key key) {
    if ((kind != DATA && kind != CLOSE) || payload.length > MAX_CHUNK ||
        (kind == DATA) != (payload.length > 0) || sequence == uint.max) return false;
    ubyte[HEADER] head; ubyte[12] n; ubyte[MAX_CHUNK + 16] cipher;
    header(head, kind, sequence, cast(ushort)(payload.length + 16)); nonce(n, kind, sequence);
    return encrypt(key, n, head, payload, cipher[0 .. payload.length + 16]) &&
           d_write(socket, head.ptr, HEADER) == 0 &&
           d_write(socket, cipher.ptr, cast(int)payload.length + 16) == 0;
}
private int receiveFrame(int socket, ref uint expected, ubyte[] payload, ref const Key key) {
    ubyte[HEADER] head; ubyte[MAX_CHUNK + 16] cipher; ubyte[12] n;
    if (d_read(socket, head.ptr, HEADER, 1) != HEADER || memcmp(head.ptr, "S6DS".ptr, 4) ||
        head[4] != 1 || head[6] || head[7]) return -1;
    ubyte kind = head[5]; uint sequence = get32(head[8 .. 12]);
    uint length = (cast(uint)head[12] << 8) | head[13];
    if ((kind != DATA && kind != CLOSE) || sequence != expected || length < 16 ||
        length > MAX_CHUNK + 16 || d_read(socket, cipher.ptr, cast(int)length, 1) != length) return -1;
    nonce(n, kind, sequence);
    if (!decrypt(key, n, head, cipher[0 .. length], payload[0 .. length - 16])) return -1;
    ++expected;
    if (kind == CLOSE) return length == 16 ? 0 : -1;
    return length > 16 ? cast(int)length - 16 : -1;
}

bool relay(int local, int remote, ref const Key tx, ref const Key rx, uint lifetimeSeconds) {
    if (local < 0 || remote < 0 || !lifetimeSeconds || lifetimeSeconds > 86400) return false;
    long deadline = d_clock() + cast(long)lifetimeSeconds * 1000;
    uint sendSequence, receiveSequence; bool localOpen = true, remoteOpen = true;
    ubyte[MAX_CHUNK] buffer;
    while ((localOpen || remoteOpen) && d_clock() < deadline) {
        bool progressed;
        if (localOpen && d_ready(local)) {
            int n = d_read(local, buffer.ptr, MAX_CHUNK, 0);
            if (n < 0 || (n > 0 && (sendSequence == uint.max || !sendFrame(remote, DATA, sendSequence, buffer[0 .. n], tx)))) return false;
            if (n > 0) ++sendSequence;
            if (n == 0) {
                if (sendSequence == uint.max || !sendFrame(remote, CLOSE, sendSequence, null, tx)) return false;
                ++sendSequence;
                localOpen = false; progressed = true;
            } else progressed = true;
        }
        if (remoteOpen && d_ready(remote)) {
            int n = receiveFrame(remote, receiveSequence, buffer, rx);
            if (n < 0 || (n > 0 && d_write(local, buffer.ptr, n))) return false;
            if (n == 0) { d_half_close(local); remoteOpen = false; }
            progressed = true;
        }
        if (!progressed) d_pause();
    }
    return !localOpen && !remoteOpen;
}
