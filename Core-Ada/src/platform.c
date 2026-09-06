#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

/* Stable libsodium ABI. The data loop calls only allocation-free primitives. */
extern int sodium_init(void);
extern int crypto_sign_seed_keypair(unsigned char *, unsigned char *, const unsigned char *);
extern int crypto_sign_detached(unsigned char *, unsigned long long *, const unsigned char *, unsigned long long, const unsigned char *);
extern int crypto_sign_verify_detached(const unsigned char *, const unsigned char *, unsigned long long, const unsigned char *);
extern int crypto_scalarmult_curve25519(unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_scalarmult_curve25519_base(unsigned char *, const unsigned char *);
extern int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *, unsigned long long *, const unsigned char *, unsigned long long, const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *, unsigned long long *, unsigned char *, const unsigned char *, unsigned long long, const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *);
extern const void *u8_check(const uint8_t *, size_t);
struct unicode_normalization_form;
extern const struct unicode_normalization_form uninorm_nfc;
extern uint8_t *u8_normalize(const struct unicode_normalization_form *, const uint8_t *, size_t, uint8_t *, size_t *);

int s6_nfc(const void *s, size_t n) {
    uint8_t buf[65536]; size_t out = sizeof buf;
    if (n > 16384 || u8_check(s, n) != NULL || memchr(s, 0, n)) return 0;
    uint8_t *p = u8_normalize(&uninorm_nfc, s, n, buf, &out);
    int ok = p && out == n && !memcmp(s, p, n);
    if (p && p != buf) free(p);
    return ok;
}
#if ADA_CROSED_LEVEL < 0 || ADA_CROSED_LEVEL > 5
#error Invalid Ada Crosed build level
#endif
int s6_init(void) {
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGPIPE, &action, NULL)) return -1;
    return sodium_init() < 0 ? -1 : 0;
}
int s6_level(void) { return ADA_CROSED_LEVEL; }
int s6_random(void *out, int n) {
    if (n < 0 || n > 65536) return -1;
    unsigned char *p = out;
    while (n) { ssize_t r = getrandom(p, (size_t)n, 0); if (r < 0 && errno == EINTR) continue; if (r <= 0) return -1; p += r; n -= (int)r; }
    return 0;
}
int s6_keypair(const void *seed, void *pub, void *secret) { return crypto_sign_seed_keypair(pub, secret, seed); }
int s6_sign(const void *secret, const void *data, int n, void *sig) {
    if (n < 0 || n > 65536) return -1;
    return crypto_sign_detached(sig, NULL, data, (unsigned)n, secret);
}
int s6_verify(const void *pub, const void *data, int n, const void *sig) {
    if (n < 0 || n > 65536) return -1;
    return crypto_sign_verify_detached(sig, data, (unsigned)n, pub);
}
int s6_xpublic(const void *secret, void *pub) { return crypto_scalarmult_curve25519_base(pub, secret); }
int s6_shared(const void *secret, const void *pub, void *shared) { return crypto_scalarmult_curve25519(shared, secret, pub); }
int s6_hash(const void *p, int n, void *out, int sha1) {
    if (n < 0 || n > 65536) return -1;
    unsigned len = 0;
    return EVP_Digest(p, (size_t)n, out, &len, sha1 ? EVP_sha1() : EVP_sha256(), NULL) == 1 ? 0 : -1;
}
void s6_wipe(void *p, int n) { if (n > 0) explicit_bzero(p, (size_t)n); }
int s6_seal(const void *key, int seq, const void *plain, unsigned char *wire) {
    unsigned char nonce[12] = {0}; unsigned long long n = 0;
    if (seq < 0 || seq >= 2147483646) return -1;
    memset(wire, 0, 8);
    for (int i = 0; i < 4; ++i) wire[7-i] = (unsigned)seq >> (8*i);
    memcpy(nonce + 4, wire, 8);
    return crypto_aead_chacha20poly1305_ietf_encrypt(wire + 8, &n, plain, 488, wire, 8, NULL, nonce, key) == 0 && n == 504 ? 0 : -1;
}
int s6_open(const void *key, int expected, const unsigned char *wire, void *plain) {
    unsigned char nonce[12] = {0}; unsigned long long n = 0;
    if (expected < 0 || expected >= 2147483646 || wire[0] || wire[1] || wire[2] || wire[3]) return -1;
    uint32_t seq = (uint32_t)wire[4]<<24 | (uint32_t)wire[5]<<16 | (uint32_t)wire[6]<<8 | wire[7];
    if (seq != (uint32_t)expected) return -1;
    memcpy(nonce + 4, wire, 8);
    return crypto_aead_chacha20poly1305_ietf_decrypt(plain, &n, NULL, wire + 8, 504, wire, 8, nonce, key) == 0 && n == 488 ? 0 : -1;
}
static int safe(const struct stat *s) { return S_ISREG(s->st_mode) && s->st_uid == geteuid() && (s->st_mode & 07777) == 0600 && s->st_nlink == 1; }
int s6_file(const char *path, void *buf, int cap) {
    struct stat before, after, end; int fd, n = -1;
    if (cap < 1 || cap > 65536 || lstat(path, &before) || !safe(&before)) return -1;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    if (fstat(fd, &after) || !safe(&after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino || after.st_size < 0 || after.st_size > cap) goto done;
    n = 0;
    while (n < after.st_size) { ssize_t r = read(fd, (char *)buf+n, (size_t)(after.st_size-n)); if (r <= 0) { n = -1; goto done; } n += (int)r; }
    char extra;
    if (read(fd, &extra, 1) != 0 || fstat(fd, &end) || !safe(&end) || end.st_size != after.st_size || end.st_mtim.tv_sec != after.st_mtim.tv_sec || end.st_mtim.tv_nsec != after.st_mtim.tv_nsec || end.st_ctim.tv_sec != after.st_ctim.tv_sec || end.st_ctim.tv_nsec != after.st_ctim.tv_nsec) n = -1;
done: close(fd); return n;
}
/* Fixed, locked replay store: 256 checksummed records, no live eviction.
 * Reject torn/corrupt records rather than interpreting them as an empty slot. */
int s6_replay(const char *path, const unsigned char *digest, int64_t now) {
    unsigned char records[256][72] = {{0}}; struct stat st; int slot = -1, ok = -1;
    char parent[4096]; size_t plen = strlen(path); if (!plen || plen >= sizeof parent) return -1;
    memcpy(parent, path, plen+1); char *slash = strrchr(parent, '/');
    if (slash) { if (slash == parent) slash[1] = 0; else *slash = 0; } else strcpy(parent, ".");
    int dir = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return -1;
    if (fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0022)) { close(dir); return -1; }
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) { close(dir); return -1; }
    if (flock(fd, LOCK_EX | LOCK_NB) || fstat(fd, &st) || !safe(&st) || (st.st_size != 0 && st.st_size != sizeof records)) goto end;
    if (st.st_size && pread(fd, records, sizeof records, 0) != sizeof records) goto end;
    if (!st.st_size && (pwrite(fd, records, sizeof records, 0) != sizeof records || fsync(fd))) goto end;
    for (int i = 0; i < 256; i++) {
        unsigned char checksum[32], zero[72] = {0};
        if (memcmp(records[i], zero, sizeof zero) &&
            (s6_hash(records[i], 40, checksum, 0) || memcmp(checksum, records[i]+40, 32))) goto end;
        uint64_t t = 0; for (int j = 0; j < 8; j++) t = (t<<8) | records[i][j];
        if (t && (t > (uint64_t)now || (uint64_t)now-t <= 600)) {
            if (!memcmp(records[i]+8, digest, 32)) goto end;
        } else if (slot < 0) slot = i;
    }
    if (slot < 0) goto end;
    for (int j = 0; j < 8; j++) records[slot][7-j] = (uint64_t)now >> (8*j);
    memcpy(records[slot]+8, digest, 32);
    if (s6_hash(records[slot], 40, records[slot]+40, 0)) goto end;
    if (pwrite(fd, records[slot], 72, (off_t)slot*72) == 72 && !fsync(fd) && !fsync(dir)) ok = 0;
end: close(fd); close(dir); return ok;
}
int64_t s6_now(void) { return (int64_t)time(NULL); }
int64_t s6_clock(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1; return t.tv_sec*1000 + t.tv_nsec/1000000; }

#define SLOTS 40
static struct { int used, fd; SSL *tls; SSL_CTX *ctx; } handles[SLOTS];
static int valid(int h) { return h >= 0 && h < SLOTS && handles[h].used; }
static int save(int fd) {
    for (int i = 0; i < SLOTS; i++) if (!handles[i].used) { handles[i].used = 1; handles[i].fd = fd; return i; }
    close(fd); return -1;
}
void s6_close(int h) {
    if (!valid(h)) return;
    SSL_free(handles[h].tls); SSL_CTX_free(handles[h].ctx); close(handles[h].fd); memset(&handles[h], 0, sizeof handles[h]);
}
static int waitfd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - s6_clock(); if (left <= 0) return -1;
        struct pollfd p = {fd, events, 0}; int r = poll(&p, 1, (int)(left > 10000 ? 10000 : left));
        if (r < 0 && errno == EINTR) continue;
        return r > 0 && (p.revents & (events | POLLHUP)) && !(p.revents & (POLLNVAL | POLLERR)) ? 0 : -1;
    }
}
int s6_listen(const char *host, int port) {
    struct addrinfo hints = {0}, *a = NULL; char service[8]; int out = -1;
    if (port < 0 || port > 65535) return -1;
    snprintf(service, sizeof service, "%d", port); hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(host, service, &hints, &a)) return -1;
    int fd = socket(a->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd >= 0) { int yes = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes); if (!bind(fd, a->ai_addr, a->ai_addrlen) && !listen(fd, 16)) out = save(fd); else close(fd); }
    freeaddrinfo(a); return out;
}
int s6_connect(const char *host, int port) {
    struct addrinfo hints = {0}, *a = NULL; char service[8]; int out = -1, count = 0;
    if (port < 1 || port > 65535) return -1;
    snprintf(service, sizeof service, "%d", port); hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICSERV;
    if (getaddrinfo(host, service, &hints, &a)) return -1;
    int64_t deadline = s6_clock() + 10000;
    for (struct addrinfo *p = a; p && count++ < 8; p = p->ai_next) {
        int fd = socket(p->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); if (fd < 0) continue;
        int e = 0; socklen_t len = sizeof e;
        if ((connect(fd, p->ai_addr, p->ai_addrlen) == 0 || (errno == EINPROGRESS && !waitfd(fd, POLLOUT, deadline))) && !getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &len) && !e) { out = save(fd); break; }
        close(fd);
    }
    freeaddrinfo(a); return out;
}
int s6_accept(int h) { return valid(h) ? ( { int fd = accept4(handles[h].fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC); fd < 0 ? -1 : save(fd); } ) : -1; }
int s6_port(int h) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    if (!valid(h) || getsockname(handles[h].fd, (struct sockaddr *)&a, &n)) return -1;
    return ntohs(a.ss_family == AF_INET ? ((struct sockaddr_in *)&a)->sin_port : ((struct sockaddr_in6 *)&a)->sin6_port);
}
int s6_ip(int h, char *out, int peer) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    if (!valid(h) || (peer ? getpeername(handles[h].fd, (struct sockaddr *)&a, &n) : getsockname(handles[h].fd, (struct sockaddr *)&a, &n))) return -1;
    void *p = a.ss_family == AF_INET ? (void *)&((struct sockaddr_in *)&a)->sin_addr : (void *)&((struct sockaddr_in6 *)&a)->sin6_addr;
    return inet_ntop(a.ss_family, p, out, 128) ? (int)strlen(out) : -1;
}
int s6_tls(int h, const char *host, const char *cert, const char *key) {
    if (!valid(h) || handles[h].tls) return -1;
    int server = cert[0] != 0; SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) return -1;
    handles[h].ctx = ctx;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) return -1;
    if (server) {
        char data[65536]; int n = s6_file(key, data, sizeof data); if (n < 0) return -1;
        BIO *bio = BIO_new_mem_buf(data, n); if (!bio) return -1;
        EVP_PKEY *priv = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL); BIO_free(bio); explicit_bzero(data, sizeof data);
        if (!priv) return -1;
        int ok = SSL_CTX_use_PrivateKey(ctx, priv); EVP_PKEY_free(priv);
        if (!ok || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 || SSL_CTX_check_private_key(ctx) != 1) return -1;
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) return -1;
    }
    SSL *ssl = SSL_new(ctx); if (!ssl) return -1; handles[h].tls = ssl;
    if (!SSL_set_fd(ssl, handles[h].fd)) return -1;
    if (!server) {
        unsigned char ip[16]; int numeric = inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1;
        if (numeric) { if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host)) return -1; }
        else if (!SSL_set1_host(ssl, host) || !SSL_set_tlsext_host_name(ssl, host)) return -1;
    }
    int64_t deadline = s6_clock() + 10000;
    for (;;) {
        int r = server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (r == 1) return server || SSL_get_verify_result(ssl) == X509_V_OK ? 0 : -1;
        int e = SSL_get_error(ssl, r); if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return -1;
        if (waitfd(handles[h].fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline)) return -1;
    }
}
int s6_read(int h, void *buf, int n, int exact) {
    if (!valid(h) || n < 0 || n > 65536) return -1;
    int used = 0; int64_t deadline = s6_clock() + 10000;
    while (used < n) {
        int r = handles[h].tls ? SSL_read(handles[h].tls, (char *)buf+used, n-used) : (int)recv(handles[h].fd, (char *)buf+used, (size_t)(n-used), 0);
        if (r > 0) { used += r; if (!exact) break; continue; }
        if (r == 0) return used ? -1 : 0;
        short events = POLLIN;
        if (handles[h].tls) { int e = SSL_get_error(handles[h].tls, r); if (e == SSL_ERROR_WANT_WRITE) events = POLLOUT; else if (e != SSL_ERROR_WANT_READ) return -1; }
        else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        if (waitfd(handles[h].fd, events, deadline)) return -1;
    }
    return used;
}
int s6_write(int h, const void *buf, int n) {
    if (!valid(h) || n < 0 || n > 65536) return -1;
    int used = 0; int64_t deadline = s6_clock() + 10000;
    while (used < n) {
        int r = handles[h].tls ? SSL_write(handles[h].tls, (const char *)buf+used, n-used) : (int)send(handles[h].fd, (const char *)buf+used, (size_t)(n-used), MSG_NOSIGNAL);
        if (r > 0) { used += r; continue; }
        short events = POLLOUT;
        if (handles[h].tls) { int e = SSL_get_error(handles[h].tls, r); if (e == SSL_ERROR_WANT_READ) events = POLLIN; else if (e != SSL_ERROR_WANT_WRITE) return -1; }
        else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        if (waitfd(handles[h].fd, events, deadline)) return -1;
    }
    return 0;
}
int s6_ready(int h) {
    if (!valid(h)) return 0;
    if (handles[h].tls && SSL_pending(handles[h].tls)) return 1;
    struct pollfd p = {handles[h].fd, POLLIN, 0};
    return poll(&p, 1, 0) > 0 && p.revents ? 1 : 0;
}
void s6_pause(void) { struct timespec t = {0, 10000000}; nanosleep(&t, NULL); }
void s6_half_close(int h) { if (valid(h)) shutdown(handles[h].fd, SHUT_WR); }
