module websocket;
import bounded, native;
import core.stdc.string : memcpy;
@nogc nothrow:
struct Channel {
    @nogc nothrow:
    int handle = -1;
    bool client;
    invariant { assert(handle >= -1 && handle < 40); }
    bool send(const(ubyte)[] data, ubyte opcode = 1)
    in { assert(data.length <= MAX_JSON); }
    out(ok) { assert(data.length <= MAX_JSON); }
    do {
        if (handle < 0 || (opcode != 1 && opcode != 2 && opcode != 8 && opcode != 9 && opcode != 10) || (opcode >= 8 && data.length > 125)) return false;
        ubyte[14] header; size_t hn = 2; header[0] = 128 | opcode;
        if (data.length < 126) header[1] = cast(ubyte)data.length;
        else if (data.length < 65536) { header[1] = 126; header[2] = cast(ubyte)(data.length >> 8); header[3] = cast(ubyte)data.length; hn = 4; }
        else { header[1] = 127; header[7] = 1; hn = 10; }
        ubyte[4] mask;
        if (client) { if (!random(mask)) return false; header[1] |= 128; header[hn .. hn + 4] = mask[]; hn += 4; }
        ubyte[MAX_JSON] payload;
        foreach(i, b; data) payload[i] = b ^ mask[i % 4];
        return d_write(handle,header.ptr,cast(int)hn) == 0 && d_write(handle,payload.ptr,cast(int)data.length) == 0;
    }
    bool text(const(char)[] data) { if (data.length > MAX_JSON) return false; return send(cast(const(ubyte)[])data); }
    bool receive(ref Text text, out ubyte opcode)
    in { assert(handle >= -1 && handle < 40); }
    out(ok) { assert(text.length <= MAX_JSON); }
    do {
        text.clear; ubyte first; bool fragmented; long deadline = d_clock() + 10000;
        ubyte[MAX_JSON] payload;
        foreach (_; 0 .. 128) {
            if (handle < 0 || d_clock() >= deadline) return false;
            ubyte[2] h;
            if (d_read(handle,h.ptr,2,1) != 2) return false;
            ubyte op = h[0] & 15; bool fin = (h[0] & 128) != 0;
            if ((h[0] & 112) || ((h[1] & 128) != 0) == client) return false;
            ulong n = h[1] & 127;
            if (n == 126) { if (d_read(handle,h.ptr,2,1) != 2) return false; n = (cast(uint)h[0] << 8) | h[1]; if (n < 126) return false; }
            else if (n == 127) { ubyte[8] ext; if (d_read(handle,ext.ptr,8,1) != 8) return false; n = 0; foreach(b; ext) n = (n << 8) | b; if (n < 65536) return false; }
            if (n > MAX_JSON || n > MAX_JSON - text.length) return false;
            ubyte[4] mask;
            if (!client && d_read(handle,mask.ptr,4,1) != 4) return false;
            if (d_read(handle,payload.ptr,cast(int)n,1) != n) return false;
            foreach(i; 0 .. cast(size_t)n) payload[i] ^= mask[i % 4];
            if (op >= 8) {
                if (!fin || n > 125 || (op != 8 && op != 9 && op != 10)) return false;
                if (op == 8) return false;
                if (op == 9 && !send(payload[0 .. cast(size_t)n],10)) return false;
                continue;
            }
            if ((!fragmented && op != 1 && op != 2) || (fragmented && op != 0)) return false;
            if (!fragmented) first = op;
            fragmented = true;
            if (!text.append(cast(const(char)[])payload[0 .. cast(size_t)n])) return false;
            if (fin) { opcode = first; return first == 2 || utf8(text.text); }
        }
        return false;
    }
}

private bool equalLower(const(char)[] a,const(char)[] b) {
    if (a.length != b.length) return false;
    foreach(i, raw; a) { char c = raw; char d = b[i]; if(c >= 'A' && c <= 'Z') c += 32; if(d >= 'A' && d <= 'Z') d += 32; if(c != d) return false; }
    return true;
}
private size_t lineEnd(const(char)[] s, size_t p) {
    while (p + 1 < s.length) { if(s[p] == '\r' && s[p + 1] == '\n') return p; ++p; } return s.length;
}
private bool header(const(char)[] http,const(char)[] name,out const(char)[] value)
in { assert(http.length <= 8192); }
out(ok) { assert(value.length <= http.length); }
do {
    size_t p = lineEnd(http,0); if (p == http.length) return false; p += 2; bool found;
    while (p + 1 < http.length) {
        size_t end = lineEnd(http,p); if (end == p) break;
        if (end == http.length || http[p] == ' ' || http[p] == '\t') return false;
        size_t colon = p; while (colon < end && http[colon] != ':') ++colon;
        if (colon == end || colon == p) return false;
        if (equalLower(http[p .. colon],name)) {
            if (found) return false; found = true;
            size_t start = colon + 1; while(start < end && (http[start] == ' ' || http[start] == '\t')) ++start;
            size_t tail = end; while(tail > start && (http[tail - 1] == ' ' || http[tail - 1] == '\t')) --tail;
            value = http[start .. tail];
        }
        p = end + 2;
    }
    return true;
}
private bool httpRead(ref Channel c, ref Buffer!8192 output) {
    output.clear; long deadline = d_clock() + 10000;
    while (output.length < 8192 && d_clock() < deadline) {
        char b; if(d_read(c.handle,&b,1,1) != 1 || !output.chr(b)) return false;
        if(output.length >= 4 && equal(output.text[$ - 4 .. $],"\r\n\r\n")) return true;
    }
    return false;
}
private bool acceptKey(const(char)[] key, ref Buffer!128 result) {
    Buffer!128 text; ubyte[20] sha;
    if (!text.append(key) || !text.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) return false;
    return d_hash(text.text.ptr,cast(int)text.length,sha.ptr,1) == 0 && base64Encode(sha,result);
}
bool upgrade(ref Channel c, const(char)[] host = "localhost")
in { assert(host.length <= 253); }
out(ok) { assert(c.handle >= -1 && c.handle < 40); }
do {
    Buffer!8192 request; Buffer!128 key, expected; const(char)[] value;
    if (c.client) {
        ubyte[16] nonce;
        if (!random(nonce) || !base64Encode(nonce,key) || !acceptKey(key.text,expected)) return false;
        request.append("GET /ws HTTP/1.1\r\nHost: "); request.append(host);
        request.append("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        request.append(key.text); request.append("\r\n\r\n");
        if (!request.good || d_write(c.handle,request.text.ptr,cast(int)request.length) != 0 || !httpRead(c,request) || !starts(request.text,"HTTP/1.1 101 ")) return false;
        if(!header(request.text,"Sec-WebSocket-Accept",value) || !equal(value,expected.text)) return false;
    } else {
        if (!httpRead(c,request) || (!starts(request.text,"GET /ws HTTP/1.1\r\n") && !starts(request.text,"GET /ws?control=rust HTTP/1.1\r\n"))) return false;
        if(!header(request.text,"Sec-WebSocket-Version",value) || !equal(value,"13")) return false;
        if(!header(request.text,"Sec-WebSocket-Key",value)) return false;
        ubyte[16] decoded;
        if (!base64Decode(value,decoded) || !acceptKey(value,expected)) return false;
        if(!header(request.text,"Origin",value) || value.length) return false;
    }
    if(!header(request.text,"Upgrade",value) || !equalLower(value,"websocket")) return false;
    if(!header(request.text,"Connection",value) || !equalLower(value,"upgrade")) return false;
    if(!header(request.text,"Sec-WebSocket-Extensions",value) || value.length) return false;
    if(!c.client) {
        request.clear;
        request.append("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
        request.append(expected.text); request.append("\r\n\r\n");
        if(!request.good || d_write(c.handle,request.text.ptr,cast(int)request.length)) return false;
    }
    return true;
}
