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
        unsigned char ad[8] = {'S','6','C',1,(unsigned char)layer,0,0,0};
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
        unsigned char ad[8] = {'S','6','C',1,(unsigned char)layer,0,0,0};
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
        if (ok) ok = write(STDOUT_FILENO, body + COMMAND + 10, n - 8) == (ssize_t)(n - 8);
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
    unsigned char material[161];
    memcpy(material, reply, 128); memcpy(material + 128, config + 64, 32);
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
/* Offline codec and bounded loopback UDP endpoint share the same checked path. */
static struct packet packet_receive(void) {
    struct packet p = {0};
    if (endpoint_mode) {
        if (++packets > 1000000 || monotonic_seconds() >= session_deadline) {
            sodium_memzero(session_keys, sizeof session_keys); close(udp_fd); exit(0);
        }
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
    if (argc == 5 && (!strcmp(argv[1], "--listen") || !strcmp(argv[1], "--send"))) {
        int local = port_number(argv[3]), peer = port_number(argv[4]);
        if (local < 0 || peer < 0 || local == peer || secure_keys(argv[2], p.keys)) exit(2);
        udp_fd = udp_open(local, peer);
        int sender = !strcmp(argv[1], "--send");
        if (udp_fd < 0 || establish(udp_fd, p.keys, sender)) exit(2);
        if (sender) { sender_loop(udp_fd); exit(0); }
        endpoint_mode = 1; return packet_receive();
    }
    if (argc == 2 && strcmp(argv[1], "--feature-report") == 0) {
        puts("{\"core\":\"shadow6-carp\",\"version\":\"0.1.0\",\"crosed_compiled\":false,\"crosed_max_level\":0,\"app_transport\":false,\"qubes_isolation\":false,\"utf8\":true,\"crosed_capabilities\":[]}"); exit(0);
    }
    if (argc == 3 && strcmp(argv[1], "--gen-key") == 0) {
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0) exit(2);
        randombytes_buf(p.keys, sizeof p.keys);
        int ok = write(fd, p.keys, sizeof p.keys) == sizeof p.keys && fsync(fd) == 0;
        close(fd); sodium_memzero(&p, sizeof p); exit(ok ? 0 : 2);
    }
    if (argc != 3 || (strcmp(argv[1], "--encode") && strcmp(argv[1], "--decode") && strcmp(argv[1], "--check-config"))) {
        fputs("shadow6-carp --gen-key FILE | --check-config FILE | --encode FILE | --decode FILE | --listen FILE LOCAL_PORT PEER_PORT | --send FILE LOCAL_PORT PEER_PORT | --feature-report\n", stderr); exit(2);
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
