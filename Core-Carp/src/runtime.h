#ifndef SHADOW6_CARP_RUNTIME_H
#define SHADOW6_CARP_RUNTIME_H
#include <sodium.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>

/* Three fixed 40-byte headers: 24-byte nonce and 16-byte detached tag.
 * Each layer authenticates its layer index and the full inner envelope. */
enum { BODY = 1024, HEADER = 40, WIRE = BODY + 3 * HEADER, COMMAND = 28 };
struct packet { unsigned char bytes[WIRE], keys[96]; int valid; };
static int udp_fd = -1;
static unsigned char session_keys[96];
static uint64_t previous_sequence;
static unsigned long packets;
static time_t session_deadline;
static int endpoint_mode;
static int application_fd = -1, chain_role;
static struct sockaddr_in application_peer;
static unsigned char receive_keys[96];
static uint64_t send_sequence;
/* A=simplex, B=bidirectional, C=full duplex contract.  The mode is
 * authenticated as part of the session transcript and packet AD. */
static unsigned char link_mode = 'A';
static int parse_mode(const char *s) {
    if (!s || s[1] != '\0' || (s[0] != 'A' && s[0] != 'B' && s[0] != 'C')) return -1;
    return (unsigned char)s[0];
}
static time_t monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) exit(2);
    return now.tv_sec;
}
static const unsigned char operation[COMMAND] = "{\"op\":\"forward\",\"version\":1}";
static int secure_keys(const char *path, unsigned char *keys) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    struct stat before, after;
    if (fd < 0) return -1;
    int ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
        before.st_uid == geteuid() && (before.st_mode & 07777) == 0600 && before.st_size == 96;
    size_t done = 0;
    while (ok && done < 96) {
        ssize_t n = read(fd, keys + done, 96 - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = 0; break; }
        done += (size_t)n;
    }
    ok = ok && fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mode == after.st_mode && before.st_uid == after.st_uid;
    close(fd);
    if (!ok) sodium_memzero(keys, 96);
    return ok ? 0 : -1;
}
static int wrap(struct packet *p, size_t size) {
    unsigned char scratch[WIRE];
    for (int layer = 2; layer >= 0; --layer) {
        size_t start = (size_t)layer * HEADER, n = WIRE - start - HEADER;
        unsigned char ad[8] = {'S','6','C',1,(unsigned char)layer,link_mode,0,0};
        randombytes_buf(p->bytes + start, 24);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(scratch,
            p->bytes + start + 24, NULL, p->bytes + start + HEADER, n,
            ad, sizeof ad, NULL, p->bytes + start, p->keys + layer * 32)) {
            sodium_memzero(scratch, sizeof scratch); return -1;
        }
        memcpy(p->bytes + start + HEADER, scratch, n);
    }
    sodium_memzero(scratch, sizeof scratch);
    (void)size;
    return 0;
}
static int packet_peel(struct packet *p) {
    unsigned char scratch[WIRE];
    if (!p->valid) return -1;
    for (int layer = 0; layer < 3; ++layer) {
        size_t start = (size_t)layer * HEADER, n = WIRE - start - HEADER;
        unsigned char ad[8] = {'S','6','C',1,(unsigned char)layer,link_mode,0,0};
        if (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(scratch, NULL,
            p->bytes + start + HEADER, n, p->bytes + start + 24,
            ad, sizeof ad, p->bytes + start, p->keys + layer * 32)) {
            sodium_memzero(scratch, sizeof scratch);
            sodium_memzero(p, sizeof *p); return -1;
        }
        memcpy(p->bytes + start + HEADER, scratch, n);
    }
    sodium_memzero(scratch, sizeof scratch);
    sodium_memzero(p->keys, sizeof p->keys);
    return 0;
}
static char *packet_command(struct packet *p) { return (char *)p->bytes + 3 * HEADER; }
static int packet_finish(struct packet *p, bool accepted) {
    unsigned char *body = p->bytes + 3 * HEADER;
    size_t n = (size_t)body[COMMAND] * 256 + body[COMMAND + 1];
    int ok = accepted && n <= BODY - COMMAND - 2;
    for (size_t i = COMMAND + 2 + n; ok && i < BODY; ++i) if (body[i]) ok = 0;
    if (ok && endpoint_mode) {
        uint64_t sequence = 0;
        if (n < 8) ok = 0;
        else {
            for (int i = 0; i < 8; ++i) sequence = (sequence << 8) | body[COMMAND + 2 + i];
            if (sequence <= previous_sequence) ok = 0;
            else previous_sequence = sequence;
        }
        if (ok && chain_role) {
            if (chain_role == 2) ok = send(application_fd, body + COMMAND + 10, n - 8, 0) == (ssize_t)(n - 8);
            else ok = application_peer.sin_port && sendto(application_fd, body + COMMAND + 10, n - 8, 0,
                (struct sockaddr *)&application_peer, sizeof application_peer) == (ssize_t)(n - 8);
        } else if (ok) ok = write(STDOUT_FILENO, body + COMMAND + 10, n - 8) == (ssize_t)(n - 8);
    } else if (ok) ok = fwrite(body + COMMAND + 2, 1, n, stdout) == n && fflush(stdout) == 0;
    sodium_memzero(p, sizeof *p);
    return ok ? 0 : 2;
}
static int read_exact_fd(int fd, unsigned char *out, size_t size) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, out + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}
static int port_number(const char *s) {
    unsigned n = 0;
    if (!*s) return -1;
    for (size_t i = 0; s[i]; ++i) {
        if (i >= 5 || s[i] < '0' || s[i] > '9') return -1;
        n = n * 10 + (unsigned)(s[i] - '0');
    }
    return n >= 1024 && n <= 65535 ? (int)n : -1;
}
static int udp_open(int local, int peer) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)local);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr)) { close(fd); return -1; }
    addr.sin_port = htons((uint16_t)peer);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr)) { close(fd); return -1; }
    return fd;
}
static int receive_timeout(int fd, unsigned char *out, size_t max, int ms) {
    struct pollfd p = {.fd=fd,.events=POLLIN};
    if (poll(&p, 1, ms) != 1 || !(p.revents & POLLIN)) return -1;
    return (int)recv(fd, out, max, 0);
}
/* The 96-byte owned configuration stores our Ed25519 seed, peer Ed25519
 * public key, and a shared deployment binding. No network-selected identity. */
static int establish(int fd, unsigned char *config, int sender) {
    unsigned char pk[32], sk[64], eph[32], shared[32], request[128], reply[192], in[193];
    int ok = 0;
    crypto_sign_seed_keypair(pk, sk, config);
    randombytes_buf(eph, 32);
    if (sender) {
        randombytes_buf(request, 32);
        crypto_scalarmult_curve25519_base(request + 32, eph);
        crypto_sign_detached(request + 64, NULL, request, 64, sk);
        if (send(fd, request, 128, 0) != 128 || receive_timeout(fd, in, sizeof in, 5000) != 192) goto done;
        if (sodium_memcmp(request, in, 64) || crypto_sign_verify_detached(in + 128, in, 128, config + 32)) goto done;
        memcpy(reply, in, 192);
        if (crypto_scalarmult_curve25519(shared, eph, reply + 96)) goto done;
    } else {
        if (receive_timeout(fd, in, sizeof in, 30000) != 128 || crypto_sign_verify_detached(in + 64, in, 64, config + 32)) goto done;
        memcpy(reply, in, 64); randombytes_buf(reply + 64, 32);
        crypto_scalarmult_curve25519_base(reply + 96, eph);
        if (crypto_scalarmult_curve25519(shared, eph, reply + 32)) goto done;
        crypto_sign_detached(reply + 128, NULL, reply, 128, sk);
        if (send(fd, reply, 192, 0) != 192) goto done;
    }
    unsigned char material[162];
    memcpy(material, reply, 128); memcpy(material + 128, config + 64, 32);
    material[161] = link_mode;
    for (int layer = 0; layer < 3; ++layer) {
        material[160] = (unsigned char)layer;
        crypto_generichash(session_keys + layer * 32, 32, material, sizeof material, shared, 32);
    }
    sodium_memzero(material, sizeof material);
    session_deadline = monotonic_seconds() + 300; ok = 1;
done:
    sodium_memzero(sk, sizeof sk); sodium_memzero(eph, sizeof eph); sodium_memzero(shared, sizeof shared);
    sodium_memzero(config, 96);
    return ok ? 0 : -1;
}
static void sender_loop(int fd) {
    struct packet p = {0};
    for (uint64_t sequence = 1; sequence <= 1000000 && monotonic_seconds() < session_deadline; ++sequence) {
        struct pollfd f = {.fd=STDIN_FILENO,.events=POLLIN};
        if (poll(&f, 1, 1000) == 0) { --sequence; continue; }
        unsigned char *body = p.bytes + 3 * HEADER;
        ssize_t n = read(STDIN_FILENO, body + COMMAND + 10, BODY - COMMAND - 10);
        if (n <= 0) break;
        memcpy(body, operation, COMMAND);
        size_t total = (size_t)n + 8;
        body[COMMAND] = (unsigned char)(total >> 8); body[COMMAND + 1] = (unsigned char)total;
        for (int i = 0; i < 8; ++i) body[COMMAND + 2 + i] = (unsigned char)(sequence >> (56 - 8*i));
        memcpy(p.keys, session_keys, 96);
        if (wrap(&p, total) || send(fd, p.bytes, WIRE, 0) != WIRE) break;
        sodium_memzero(&p, sizeof p);
    }
    sodium_memzero(&p, sizeof p); sodium_memzero(session_keys, sizeof session_keys); close(fd);
}

static int chain_application(int port, int client) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a = {0}; a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons((uint16_t)port);
    int rc = client ? bind(fd, (struct sockaddr *)&a, sizeof a) : connect(fd, (struct sockaddr *)&a, sizeof a);
    if (rc) { close(fd); return -1; }
    return fd;
}

/* New full-duplex application roles retain the Carp schema check on every
 * received packet. Domain-separated keys prevent reflection between directions. */
static struct packet chain_receive(void) {
    struct packet p = {0};
    struct pollfd f[2] = {{.fd=udp_fd,.events=POLLIN}, {.fd=application_fd,.events=POLLIN}};
    if (poll(f, 2, 1000) <= 0) return p;
    if (f[1].revents & POLLIN) {
        unsigned char *body = p.bytes + 3 * HEADER;
        unsigned char input[BODY - COMMAND - 10 + 1];
        struct sockaddr_in source = {0}; socklen_t sl = sizeof source;
        ssize_t n = recvfrom(application_fd, input, sizeof input, 0, (struct sockaddr *)&source, &sl);
        if (n < 0 || n > BODY - COMMAND - 10) return p;
        if (chain_role == 1) {
            if (source.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
                (application_peer.sin_port && (application_peer.sin_port != source.sin_port ||
                 application_peer.sin_addr.s_addr != source.sin_addr.s_addr))) return p;
            application_peer = source;
        }
        if (++send_sequence > 1000000) exit(2);
        memcpy(body, operation, COMMAND);
        size_t total = (size_t)n + 8;
        body[COMMAND] = (unsigned char)(total >> 8); body[COMMAND + 1] = (unsigned char)total;
        for (int i = 0; i < 8; ++i) body[COMMAND + 2 + i] = (unsigned char)(send_sequence >> (56 - 8*i));
        memcpy(body + COMMAND + 10, input, (size_t)n);
        memcpy(p.keys, session_keys, 96);
        if (wrap(&p, total) || send(udp_fd, p.bytes, WIRE, 0) != WIRE) exit(2);
        sodium_memzero(input, sizeof input); sodium_memzero(&p, sizeof p);
    }
    if (f[0].revents & POLLIN) {
        unsigned char input[WIRE + 1];
        ssize_t n = recv(udp_fd, input, sizeof input, 0);
        if (n == WIRE) { memcpy(p.bytes, input, WIRE); memcpy(p.keys, receive_keys, 96); p.valid = 1; }
        sodium_memzero(input, sizeof input);
    }
    return p;
}

/* Fixed broker route. CONFIG is reserved-zero[32], client pin[32], agent
 * pin[32]. Only authenticated handshake admission; data stays encrypted. */
static int chain_broker(const char *path, int local, int client, int agent) {
    unsigned char pins[96], frame[WIRE + 1], challenge[64];
    if (secure_keys(path, pins) || sodium_is_zero(pins, 32) != 1) return 2;
    int fd = chain_application(local, 1);
    if (fd < 0) return 2;
    int phase = 0, rc = 0;
    time_t started = monotonic_seconds(), activity = started;
    puts("broker ready");
    for (unsigned count = 0; count < 1000000; ++count) {
        time_t now = monotonic_seconds();
        if (now - started >= 300 || now - activity >= (phase == 2 ? 60 : 5)) break;
        struct pollfd poller = {.fd=fd,.events=POLLIN};
        if (poll(&poller, 1, 1000) <= 0) continue;
        struct sockaddr_in source; socklen_t sl = sizeof source;
        ssize_t n = recvfrom(fd, frame, sizeof frame, 0, (struct sockaddr *)&source, &sl);
        if (n < 0 || source.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) continue;
        int port = ntohs(source.sin_port), destination = 0;
        if (phase == 0 && port == client && n == 128) {
            if (crypto_sign_verify_detached(frame + 64, frame, 64, pins + 32)) continue;
            memcpy(challenge, frame, 64); phase = 1; destination = agent;
        } else if (phase == 1 && port == agent && n == 192) {
            if (sodium_memcmp(challenge, frame, 64) || crypto_sign_verify_detached(frame + 128, frame, 128, pins + 64)) continue;
            phase = 2; destination = client;
        } else if (phase == 2 && n == WIRE) {
            if (port == client) destination = agent;
            else if (port == agent) destination = client;
        }
        if (!destination) continue;
        source.sin_port = htons((uint16_t)destination);
        if (sendto(fd, frame, (size_t)n, 0, (struct sockaddr *)&source, sizeof source) != n) { rc = 2; break; }
        activity = now;
    }
    close(fd); sodium_memzero(pins, sizeof pins); return rc;
}
/* Offline codec and bounded loopback UDP endpoint share the same checked path. */
static struct packet packet_receive(void) {
    struct packet p = {0};
    if (endpoint_mode) {
        if (++packets > 1000000 || monotonic_seconds() >= session_deadline) {
            sodium_memzero(session_keys, sizeof session_keys);
            sodium_memzero(receive_keys, sizeof receive_keys);
            if (application_fd >= 0) close(application_fd);
            close(udp_fd); exit(0);
        }
        if (chain_role) return chain_receive();
        unsigned char incoming[WIRE + 1];
        int n = receive_timeout(udp_fd, incoming, sizeof incoming, 1000);
        if (n == WIRE) { memcpy(p.bytes, incoming, WIRE); memcpy(p.keys, session_keys, 96); p.valid = 1; }
        sodium_memzero(incoming, sizeof incoming); return p;
    }
    char **argv = System_args.data;
    int argc = (int)System_args.len;
    if (sodium_init() < 0) exit(2);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(300);
    if (argc == 6 && (!strcmp(argv[1], "--broker") || !strcmp(argv[1], "--agent") || !strcmp(argv[1], "--client"))) {
        int local = port_number(argv[3]), peer = port_number(argv[4]), application = port_number(argv[5]);
        if (local < 0 || peer < 0 || application < 0 || local == peer || local == application || peer == application) exit(2);
        if (!strcmp(argv[1], "--broker")) exit(chain_broker(argv[2], local, peer, application));
        chain_role = !strcmp(argv[1], "--client") ? 1 : 2;
        link_mode = 'T'; /* Separate contract; legacy A/B/C remains unchanged. */
        if (secure_keys(argv[2], p.keys)) exit(2);
        udp_fd = udp_open(local, peer);
        application_fd = chain_application(application, chain_role == 1);
        if (udp_fd < 0 || application_fd < 0) exit(2);
        puts("control ready");
        if (establish(udp_fd, p.keys, chain_role == 1)) exit(2);
        unsigned char base[96]; memcpy(base, session_keys, 96);
        for (int i = 0; i < 3; ++i) {
            unsigned char tx[2] = {(unsigned char)i, (unsigned char)chain_role};
            unsigned char rx[2] = {(unsigned char)i, (unsigned char)(3-chain_role)};
            crypto_generichash(session_keys + i*32, 32, tx, 2, base + i*32, 32);
            crypto_generichash(receive_keys + i*32, 32, rx, 2, base + i*32, 32);
        }
        sodium_memzero(base, sizeof base); endpoint_mode = 1;
        puts("session ready"); return packet_receive();
    }
    if ((argc == 5 || argc == 6) && (!strcmp(argv[1], "--listen") || !strcmp(argv[1], "--send"))) {
        int local = port_number(argv[3]), peer = port_number(argv[4]);
        if (argc == 6 && parse_mode(argv[5]) < 0) exit(2);
        link_mode = argc == 6 ? (unsigned char)argv[5][0] : 'A';
        if (local < 0 || peer < 0 || local == peer || secure_keys(argv[2], p.keys)) exit(2);
        udp_fd = udp_open(local, peer);
        int sender = !strcmp(argv[1], "--send");
        if (udp_fd < 0 || establish(udp_fd, p.keys, sender)) exit(2);
        if (sender) { sender_loop(udp_fd); exit(0); }
        endpoint_mode = 1; return packet_receive();
    }
    if (argc == 2 && strcmp(argv[1], "--feature-report") == 0) {
        puts("{\"core\":\"shadow6-carp\",\"version\":\"0.1.0\",\"crosed_compiled\":false,\"crosed_max_level\":0,\"app_transport\":false,\"qubes_isolation\":false,\"gate_compiled\":false,\"gate_enabled_by_default\":false,\"utf8\":true,\"crosed_capabilities\":[]}"); exit(0);
    }
    if (argc == 3 && strcmp(argv[1], "--gen-key") == 0) {
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0) exit(2);
        randombytes_buf(p.keys, sizeof p.keys);
        int ok = write(fd, p.keys, sizeof p.keys) == sizeof p.keys && fsync(fd) == 0;
        close(fd); sodium_memzero(&p, sizeof p); exit(ok ? 0 : 2);
    }
    if (argc != 3 || (strcmp(argv[1], "--encode") && strcmp(argv[1], "--decode") && strcmp(argv[1], "--check-config"))) {
        fputs("shadow6-carp --gen-key FILE | --check-config FILE | --encode FILE | --decode FILE | --listen FILE LOCAL_PORT PEER_PORT [A|B|C] | --send FILE LOCAL_PORT PEER_PORT [A|B|C] | --feature-report\n", stderr); exit(2);
    }
    if (secure_keys(argv[2], p.keys)) return p;
    if (!strcmp(argv[1], "--check-config")) { sodium_memzero(&p, sizeof p); exit(0); }
    if (!strcmp(argv[1], "--encode")) {
        unsigned char *body = p.bytes + 3 * HEADER;
        size_t n = fread(body + COMMAND + 2, 1, BODY - COMMAND - 2, stdin);
        if (getchar() != EOF || ferror(stdin)) { sodium_memzero(&p, sizeof p); exit(2); }
        memcpy(body, operation, COMMAND); body[COMMAND] = (unsigned char)(n >> 8); body[COMMAND + 1] = (unsigned char)n;
        int ok = wrap(&p, n) == 0 && fwrite(p.bytes, 1, WIRE, stdout) == WIRE && fflush(stdout) == 0;
        sodium_memzero(&p, sizeof p); exit(ok ? 0 : 2);
    }
    size_t n = fread(p.bytes, 1, WIRE, stdin);
    if (n == WIRE && getchar() == EOF && !ferror(stdin)) p.valid = 1;
    return p;
}
static bool packet_continue(void) { return endpoint_mode != 0; }
#endif
