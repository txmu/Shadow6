module main;
import benchmark, bounded, config, json, native, packet, runtime;
import core.stdc.stdio : printf, fgets, stdin;
import core.stdc.string : strlen, memcmp;

@nogc nothrow:

struct Driver {
    int socket = -1; Key key, txKey, identity, peer, ephemeral; Secret signer;
    Key[32] allowed; size_t allowedCount;
    SessionId session; ReceiveState receive; bool stopped, server, established;
    Hello request, response; ubyte[136] address;
    long expires, helloWindow, lastHello; uint helloCount;
    invariant { assert(socket >= -1 && socket < 40 && allowedCount <= 32); }
}
private bool arg(const(char)* v, const(char)[] e) { if (v is null) return false; auto n = strlen(v); return n == e.length && equal(v[0 .. n], e); }
private bool number(const(char)* value, out uint result) { result=0; if(value is null)return false; auto n=strlen(value); if(!n||n>5)return false; foreach(c;value[0..n]){if(c<'0'||c>'9')return false; result=result*10+c-'0';} return result>0; }
private bool initDriver(ref Driver d, ref const Document doc) {
    auto role = doc.field(1, "role"); auto section = doc.get(1, role); if (!section) return false;
    Key pub; if (!loadKey(doc.field(section, "private_key"), pub, d.signer)) return false;
    d.identity = pub;
    Buffer!256 host; ushort port;
    if (equal(role, "broker")) {
        d.server = true;
        foreach(group; ["agents", "clients"]) {
            for (auto i = doc.child(doc.get(section, group)); i; i = doc.next(i)) {
                if (d.allowedCount == d.allowed.length || !hexDecode(doc.field(i, "pubkey"), d.allowed[d.allowedCount])) return false;
                ++d.allowedCount;
            }
        }
        if (!endpoint(doc.field(section, "listen_addr"), host, port)) return false;
        d.socket = d_udp(host.cstring, port);
    } else {
        if (!hexDecode(doc.field(section, "broker_pubkey"), d.peer) || !random(d.ephemeral) || !random(d.session)) return false;
        Key publicEphemeral;
        if (!publicKey(d.ephemeral, publicEphemeral) || !makeHello(1, d.session, d_now(), d.identity, publicEphemeral, d.peer, d.signer, d.request)) return false;
        d.expires = d_clock() + 30000;
        auto addresses = doc.get(section, "broker_addrs"); auto first = doc.child(addresses); if (!first) return false;
        bool tls; if (!url(doc.text(first), host, port, tls)) return false;
        d.socket = d_udp("127.0.0.1", 0);
        if (d.socket >= 0 && d_udp_connect(d.socket, host.cstring, port) != 0) { d_close(d.socket); d.socket = -1; }
    }
    return d.socket >= 0;
}
extern(C) int shadow6_d_driver_init(const(char)* path, Driver* d) {
    if (d is null || path is null || d_init() != 0) return -1;
    Document doc; auto n = strlen(path); if (!readConfig(path[0 .. n], doc)) return -1;
    return initDriver(*d, doc) ? 0 : -1;
}
extern(C) int shadow6_d_driver_step(Driver* d) {
    if (d is null || d.socket < 0 || d.stopped) return -1;
    if (!d.server && !d.established && d_clock() >= d.expires) { d_wipe(d.ephemeral.ptr, 32); d.stopped = true; return -1; }
    if (d.established && d_clock() >= d.expires) {
        d_wipe(d.key.ptr, 32); d_wipe(d.txKey.ptr, 32); d.established = false;
        if (!d.server) { d.stopped = true; return -1; }
    }
    if (!d.server && !d.established && d_clock() - d.lastHello >= 1000) {
        d_udp_send(d.socket, d.request.ptr, HELLO_SIZE, null); d.lastHello = d_clock();
    }
    ubyte[MAX_PACKET] wire; ubyte[136] peer; int n = d_udp_receive(d.socket, wire.ptr, cast(int)wire.length, peer.ptr);
    if (n == -2 || n == 0) return 0;
    if (n < 0) { d.stopped = true; return -1; }
    Decoded p;
    if (n == HELLO_SIZE && !memcmp(wire.ptr, "S6DHEL02".ptr, 8)) {
        if (d_clock() - d.helloWindow >= 1000) { d.helloWindow = d_clock(); d.helloCount = 0; }
        if (d.helloCount >= 16) return 0;
        ++d.helloCount;
        if (d.server) {
            if (d.established) {
                if (!memcmp(peer.ptr, d.address.ptr, peer.length) && !memcmp(wire.ptr, d.request.ptr, HELLO_SIZE))
                    d_udp_send(d.socket, d.response.ptr, HELLO_SIZE, peer.ptr);
                return 0;
            }
            bool trusted;
            foreach(ref allowed; d.allowed[0 .. d.allowedCount]) {
                if (!memcmp(wire.ptr + 33, allowed.ptr, 32)) { d.peer = allowed; trusted = true; break; }
            }
            if (!trusted || !checkHello(wire[0 .. n], 1, d_now(), d.peer, d.identity)) return 0;
            Key publicEphemeral, remoteEphemeral, binding;
            d.request[] = wire[0 .. n]; d.session[] = wire[9 .. 25]; remoteEphemeral[] = wire[65 .. 97];
            if (!random(d.ephemeral) || !publicKey(d.ephemeral, publicEphemeral) || !hash(d.request, binding) ||
                !makeHello(2, d.session, d_now(), d.identity, publicEphemeral, binding, d.signer, d.response) ||
                !trafficKeys(d.ephemeral, remoteEphemeral, d.request, d.response, d.key, d.txKey)) {
                d_wipe(d.ephemeral.ptr, 32); d_wipe(d.key.ptr, 32); d_wipe(d.txKey.ptr, 32); return 0;
            }
            d_wipe(d.ephemeral.ptr, 32);
            d.address = peer; d.receive = ReceiveState.init; d.established = true; d.expires = d_clock() + 60000;
            d_udp_send(d.socket, d.response.ptr, HELLO_SIZE, peer.ptr);
        } else if (!d.established) {
            Key binding, remoteEphemeral;
            if (!hash(d.request, binding) || !checkHello(wire[0 .. n], 2, d_now(), d.peer, binding) || memcmp(wire.ptr + 9, d.session.ptr, 16)) return 0;
            d.response[] = wire[0 .. n]; remoteEphemeral[] = wire[65 .. 97];
            if (!trafficKeys(d.ephemeral, remoteEphemeral, d.request, d.response, d.txKey, d.key)) return 0;
            d_wipe(d.ephemeral.ptr, 32);
            d.address = peer; d.established = true; d.expires = d_clock() + 60000;
        }
        return 1;
    }
    if (!d.established || memcmp(peer.ptr, d.address.ptr, peer.length)) return 0;
    if (!decodePacket(wire[0 .. n], d.session, d_now(), d.key, p)) return 0;
    auto action = d.receive.accept(p);
    if (action == Action.finished) d.stopped = true;
    if (action == Action.deliver || action == Action.acknowledge) {
        Wire reply;
        if (encodePacket(PacketKind.ack, d.session, p.sequence, d_now(), null, d.txKey, reply))
            d_udp_send(d.socket, reply.data.ptr, cast(int)reply.length, peer.ptr);
    }
    return 1;
}

extern(C) int shadow6_d_entry(int argc, char** argv) {
    if (d_init() != 0) return 1;
    if (argc == 2 && arg(argv[1], "--feature-report")) {
        printf("%.*s\n", cast(int)features.length, features.ptr); return 0;
    }
    if (argc == 4 && arg(argv[1], "--benchmark-loopback")) {
        uint payload, requests; if(!number(argv[2],payload)||!number(argv[3],requests)) return 2;
        return runBenchmark(payload,requests);
    }
    if (argc == 2 && arg(argv[1], "--json-rpc")) {
        char[MAX_JSON] line; Document doc;
        while (fgets(line.ptr, cast(int)line.length, stdin) !is null) {
            size_t n = strlen(line.ptr); if (!n || !parseUntrusted(doc, line[0 .. n])) { printf("{\"error\":\"invalid_request\"}\n"); continue; }
            if (equal(doc.field(1, "method"), "feature_report")) printf("{\"result\":%.*s}\n", cast(int)features.length, features.ptr);
            else if (equal(doc.field(1, "method"), "stop")) { printf("{\"result\":true}\n"); break; }
            else printf("{\"error\":\"method_not_found\"}\n");
        }
        return 0;
    }
    if (argc == 3 && arg(argv[1], "--check-config")) {
        Document doc; if (!readConfig(argv[2][0 .. strlen(argv[2])], doc)) return 1;
        printf("Configuration valid for shadow6-d\n"); return 0;
    }
    if (argc == 4 && arg(argv[1], "--config") && arg(argv[3], "--check-config")) {
        Document doc; if (!readConfig(argv[2][0 .. strlen(argv[2])], doc)) return 1;
        printf("Configuration valid for shadow6-d\n"); return 0;
    }
    if (argc == 4 && arg(argv[1], "--config") && arg(argv[3], "--embedded")) {
        Document doc; if (!readConfig(argv[2][0 .. strlen(argv[2])], doc)) return 1;
        /* The host owns the event loop; validation is the only startup action. */
        return 0;
    }
    if (argc == 3 && arg(argv[1], "--config")) {
        Document doc; if (!readConfig(argv[2][0 .. strlen(argv[2])], doc)) return 1;
        return runRuntime(doc) ? 0 : 1;
    }
    printf("shadow6-d --config FILE [--embedded|--check-config] | --feature-report | --json-rpc | --benchmark-loopback BYTES REQUESTS\n"); return 2;
}
