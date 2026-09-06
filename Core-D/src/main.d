module main;
import bounded, config, json, native, packet;
import core.stdc.stdio : printf, fgets, stdin;
import core.stdc.string : strlen;

@nogc nothrow:

struct Driver { int socket = -1; Key key; Secret signer; Key peer; SessionId session; ReceiveState receive; bool stopped; invariant { assert(socket >= -1 && socket < 40); } }
private bool arg(const(char)* v, const(char)[] e) { if (v is null) return false; auto n = strlen(v); return n == e.length && equal(v[0 .. n], e); }
private bool initDriver(ref Driver d, ref const Document doc) {
    auto role = doc.field(1, "role"); auto section = doc.get(1, role); if (!section) return false;
    Key pub; if (!loadKey(doc.field(section, "private_key"), pub, d.signer)) return false;
    d.key = pub; d.peer = pub; Key digest; if (!hash(cast(const(ubyte)[])role, digest)) return false; d.session[] = digest[0 .. 16];
    Buffer!256 host; ushort port;
    if (equal(role, "broker")) {
        if (!endpoint(doc.field(section, "listen_addr"), host, port)) return false;
        d.socket = d_udp(host.cstring, port);
    } else {
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
    ubyte[MAX_PACKET] wire; ubyte[136] peer; int n = d_udp_receive(d.socket, wire.ptr, cast(int)wire.length, peer.ptr);
    if (n == -2) return 0; if (n < 1) return -1; Decoded p;
    if (!decodePacket(wire[0 .. n], d.session, d_now(), d.peer, d.key, p)) return 0;
    auto action = d.receive.accept(p); if (action == Action.finished) d.stopped = true; return 1;
}

extern(C) int shadow6_d_entry(int argc, char** argv) {
    if (d_init() != 0) return 1;
    if (argc == 2 && arg(argv[1], "--feature-report")) {
        printf("%.*s\n", cast(int)features.length, features.ptr); return 0;
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
    if (argc == 4 && arg(argv[1], "--config") && arg(argv[3], "--embedded")) {
        Document doc; if (!readConfig(argv[2][0 .. strlen(argv[2])], doc)) return 1;
        /* The host owns the event loop; validation is the only startup action. */
        return 0;
    }
    if (argc == 3 && arg(argv[1], "--config")) {
        Driver d; if (shadow6_d_driver_init(argv[2], &d) != 0) return 1;
        while (!d.stopped) { shadow6_d_driver_step(&d); d_pause(); }
        d_close(d.socket); return 0;
    }
    printf("shadow6-d --config FILE [--embedded|--check-config] | --feature-report | --json-rpc\n"); return 2;
}
