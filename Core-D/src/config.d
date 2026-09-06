module config;
import bounded, json, native;
import core.stdc.string : memcmp;
@nogc nothrow:
enum features = `{"core":"shadow6-d","version":"1.1.0","crosed_compiled":false,"crosed_max_level":0,"app_transport":false,"qubes_isolation":false,"gate_compiled":false,"gate_enabled_by_default":false,"utf8":true,"crosed_capabilities":[],"transport":"rle-udp","better_c":true}`;

bool loadKey(const(char)[] encoded, out Key pub, out Secret secret)
in { assert(encoded.length <= MAX_JSON); }
out(ok) { assert(pub.length == 32 && secret.length == 64); }
do {
    if (encoded.length != 64 && encoded.length != 128) return false;
    Key seed;
    if (!hexDecode(encoded[0 .. 64], seed)) return false;
    scope(exit) d_wipe(seed.ptr, 32);
    if (!keypair(seed, pub, secret)) return false;
    if (encoded.length == 128) { Key suffix; if (!hexDecode(encoded[64 .. $], suffix) || memcmp(suffix.ptr, pub.ptr, 32)) return false; }
    return true;
}
bool readConfig(const(char)[] path, ref Document doc)
in { assert(path.length <= MAX_JSON); }
out(ok) { assert(!ok || doc.kind(1) == Kind.object); }
do {
    if (!path.length || path.length > 4095 || !ascii(path)) return false;
    Buffer!4096 name; if (!name.append(path)) return false;
    char[MAX_JSON] data;
    int n = d_file(name.cstring, data.ptr, cast(int)data.length);
    if (n <= 0 || n > data.length) return false;
    bool ok = parseUntrusted(doc, data[0 .. n]);
    d_wipe(data.ptr, cast(int)data.length);
    return ok && doc.kind(1) == Kind.object && validateConfig(doc);
}
bool endpoint(const(char)[] text, ref Buffer!256 host, out ushort port)
in { assert(text.length <= MAX_JSON); }
out(ok) { assert(!ok || (host.good && host.length > 0 && port > 0)); }
do {
    host.clear; size_t colon = text.length;
    foreach(i, c; text) if (c == ':') colon = i;
    if (colon == text.length || !colon || colon + 1 == text.length) return false;
    auto raw = text[0 .. colon];
    if (raw.length > 2 && raw[0] == '[' && raw[$ - 1] == ']') raw = raw[1 .. $ - 1];
    if (!raw.length || raw.length > 253) return false;
    foreach(c; raw) if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '.' && c != '-' && c != ':') return false;
    uint n;
    foreach(c; text[colon + 1 .. $]) { if (c < '0' || c > '9' || n > (65535u - (c - '0')) / 10) return false; n = n * 10 + c - '0'; }
    if (!n) return false;
    port = cast(ushort)n; return host.append(raw);
}
bool url(const(char)[] text, ref Buffer!256 host, out ushort port, out bool tls)
in { assert(text.length <= MAX_JSON); }
out(ok) { assert(!ok || host.good); }
do {
    tls = starts(text, "wss://");
    if (!tls && !starts(text, "ws://")) return false;
    if (text.length < 10 || text.length > 2048 || !equal(text[$ - 3 .. $], "/ws")) return false;
    if (!endpoint(text[tls ? 6 : 5 .. $ - 3], host, port)) return false;
    return tls || equal(host.text, "127.0.0.1") || equal(host.text, "::1") || equal(host.text, "localhost");
}
ushort findPeer(ref const Document d, ushort broker, const(char)[] id, out bool agent) {
    foreach(k; 0 .. 2) {
        agent = k == 0;
        for(ushort p = d.child(d.get(broker, agent ? "agents" : "clients")); p; p = d.next(p))
            if (equal(d.field(p, "id"), id)) return p;
    }
    return 0;
}
bool optionalString(ref const Document d, ushort p, const(char)[] key, bool mustEmpty = false) {
    auto i = d.get(p, key); return !i || (d.kind(i) == Kind.str && (!mustEmpty || d.text(i).length == 0));
}
bool validateConfig(ref const Document d)
in { assert(d.kind(1) == Kind.object); }
out(ok) { assert(!ok || d.get(1, "role") != 0); }
do {
    if (!d.fields(1, "role|broker|agent|client")) return false;
    auto role = d.field(1, "role");
    if (!equal(role, "broker") && !equal(role, "agent") && !equal(role, "client")) return false;
    ushort p = d.get(1, role); if (d.kind(p) != Kind.object) return false;
    uint n; for(ushort i = d.child(1); i; i = d.next(i)) ++n; if (n != 2) return false;
    Key pub; Secret secret;
    if (!loadKey(d.field(p, "private_key"), pub, secret)) return false;
    d_wipe(secret.ptr, 64);
    if (equal(role, "broker")) {
        if (!d.fields(p, "listen_addr|private_key|agents|clients|webhook_url|stealth_mode|tls_cert|tls_key")) return false;
        Buffer!256 host; ushort port;
        if (!endpoint(d.field(p, "listen_addr"), host, port) || !optionalString(d, p, "webhook_url", true)) return false;
        if (d.get(p, "stealth_mode") && d.kind(d.get(p, "stealth_mode")) != Kind.boolean) return false;
        if (!optionalString(d,p,"tls_cert") || !optionalString(d,p,"tls_key") ||
            (d.field(p,"tls_cert").length == 0) != (d.field(p,"tls_key").length == 0)) return false;
        foreach(k; 0 .. 2) {
            auto a = d.get(p, k == 0 ? "agents" : "clients"); if (d.kind(a) != Kind.array) return false;
            n = 0;
            for(ushort i = d.child(a); i; i = d.next(i)) {
                if (++n > 16 || !d.fields(i, k == 0 ? "id|pubkey" : "id|pubkey|allowed_agents") ||
                    !identity(d.field(i,"id")) || !hexDecode(d.field(i,"pubkey"),pub)) return false;
                bool isAgent;
                if (findPeer(d,p,d.field(i,"id"),isAgent) != i) return false;
                if (k == 1) {
                    auto allowed = d.get(i,"allowed_agents"); if (d.kind(allowed) != Kind.array) return false;
                    for(ushort j = d.child(allowed); j; j = d.next(j))
                        if (!findPeer(d,p,d.text(j),isAgent) || !isAgent) return false;
                }
            }
        }
    } else {
        bool agent = equal(role, "agent");
        if (!d.fields(p, agent ? "id|broker_addrs|broker_pubkey|private_key|target_port|auto_close_after|allow_local_discovery|client_pubkeys|transport|sni|alpn" :
            "id|broker_addrs|broker_pubkey|private_key|target_agent|agent_pubkey|on_success|allow_local_discovery|transport|sni|alpn")) return false;
        if (!identity(d.field(p,"id")) || !equal(d.field(p,"transport"),"rle-udp") || !hexDecode(d.field(p,"broker_pubkey"),pub)) return false;
        auto discover = d.get(p,"allow_local_discovery");
        if (discover && (d.kind(discover) != Kind.boolean || d.boolean(discover))) return false;
        if (!optionalString(d,p,"sni",true) || !optionalString(d,p,"alpn",true)) return false;
        auto addrs = d.get(p,"broker_addrs"); if (d.kind(addrs) != Kind.array || !d.child(addrs)) return false;
        n = 0;
        for (ushort a = d.child(addrs); a; a = d.next(a)) {
            Buffer!256 host; ushort port; bool tls;
            if (++n > 8 || !url(d.text(a),host,port,tls)) return false;
        }
        if (agent) {
            auto target = d.number(d.get(p,"target_port")), lifetime = d.number(d.get(p,"auto_close_after"));
            if (target < 1 || target > 65535 || lifetime < 1 || lifetime > 86400) return false;
            auto clients = d.get(p,"client_pubkeys"); if (d.kind(clients) != Kind.object || !d.child(clients)) return false;
            n = 0;
            for (ushort c = d.child(clients); c; c = d.next(c))
                if (++n > 16 || !identity(d.key(c)) || !hexDecode(d.text(c),pub)) return false;
        } else if (!identity(d.field(p,"target_agent")) || !hexDecode(d.field(p,"agent_pubkey"),pub) || !optionalString(d,p,"on_success",true)) return false;
    }
    return true;
}
