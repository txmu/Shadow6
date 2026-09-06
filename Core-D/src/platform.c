/* POSIX/TLS/crypto boundary shared in design with Core-Ada. Protocol logic is D. */
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
extern void sodium_memzero(void *, size_t);
extern int crypto_sign_seed_keypair(unsigned char *, unsigned char *, const unsigned char *);
extern int crypto_sign_detached(unsigned char *, unsigned long long *, const unsigned char *, unsigned long long, const unsigned char *);
extern int crypto_sign_verify_detached(const unsigned char *, const unsigned char *, unsigned long long, const unsigned char *);
extern int crypto_scalarmult_curve25519(unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_scalarmult_curve25519_base(unsigned char *, const unsigned char *);
extern int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *, unsigned long long *, const unsigned char *, unsigned long long, const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *, const unsigned char *);
extern int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *, unsigned long long *, unsigned char *, const unsigned char *, unsigned long long, const unsigned char *, unsigned long long, const unsigned char *, const unsigned char *);
int d_init(void) {
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGPIPE, &action, NULL)) return -1;
    return sodium_init() < 0 ? -1 : 0;
}
int d_random(void *out, int n) {
    if (n < 0 || n > 65536) return -1;
    unsigned char *p = out;
    while (n) { ssize_t r = getrandom(p, (size_t)n, 0); if (r < 0 && errno == EINTR) continue; if (r <= 0) return -1; p += r; n -= (int)r; }
    return 0;
}
int d_keypair(const void *seed, void *pub, void *secret) { return crypto_sign_seed_keypair(pub, secret, seed); }
int d_sign(const void *secret, const void *data, int n, void *sig) {
    if (n < 0 || n > 65536) return -1;
    return crypto_sign_detached(sig, NULL, data, (unsigned)n, secret);
}
int d_verify(const void *pub, const void *data, int n, const void *sig) {
    if (n < 0 || n > 65536) return -1;
    return crypto_sign_verify_detached(sig, data, (unsigned)n, pub);
}
int d_xpublic(const void *secret, void *pub) { return crypto_scalarmult_curve25519_base(pub, secret); }
int d_shared(const void *secret, const void *pub, void *shared) { return crypto_scalarmult_curve25519(shared, secret, pub); }
int d_encrypt(const void *key, const void *nonce, const void *aad, int an, const void *plain, int n, void *out) {
    unsigned long long written = 0;
    if (an < 0 || an > 64 || n < 0 || n > 1025) return -1;
    return crypto_aead_chacha20poly1305_ietf_encrypt(out, &written, plain, (unsigned)n, aad, (unsigned)an, NULL, nonce, key) == 0 && written == (unsigned)n + 16 ? 0 : -1;
}
int d_decrypt(const void *key, const void *nonce, const void *aad, int an, const void *cipher, int n, void *out) {
    unsigned long long written = 0;
    if (an < 0 || an > 64 || n < 16 || n > 1041) return -1;
    return crypto_aead_chacha20poly1305_ietf_decrypt(out, &written, NULL, cipher, (unsigned)n, aad, (unsigned)an, nonce, key) == 0 && written == (unsigned)n - 16 ? 0 : -1;
}
int d_hash(const void *p, int n, void *out, int sha1) {
    if (n < 0 || n > 65536) return -1;
    unsigned len = 0;
    return EVP_Digest(p, (size_t)n, out, &len, sha1 ? EVP_sha1() : EVP_sha256(), NULL) == 1 ? 0 : -1;
}
void d_wipe(void *p, int n) { if (n > 0) sodium_memzero(p, (size_t)n); }
static int safe(const struct stat *s) { return S_ISREG(s->st_mode) && s->st_uid == geteuid() && (s->st_mode & 07777) == 0600 && s->st_nlink == 1; }
int d_file(const char *path, void *buf, int cap) {
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
int64_t d_now(void) { return (int64_t)time(NULL); }
int64_t d_clock(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1; return t.tv_sec*1000 + t.tv_nsec/1000000; }

#define SLOTS 40
static struct { int used, fd; SSL *tls; SSL_CTX *ctx; } handles[SLOTS];
static int valid(int h) { return h >= 0 && h < SLOTS && handles[h].used; }
static int save(int fd) {
    for (int i = 0; i < SLOTS; i++) if (!handles[i].used) { handles[i].used = 1; handles[i].fd = fd; return i; }
    close(fd); return -1;
}
struct d_address { struct sockaddr_storage address; socklen_t length; };
_Static_assert(sizeof(struct d_address) <= 136, "D peer buffer is too small");
int d_udp(const char *host, int port) {
    struct addrinfo hints = {0}, *a = NULL; char service[8]; int out = -1;
    if (port < 0 || port > 65535) return -1;
    snprintf(service, sizeof service, "%d", port); hints.ai_socktype = SOCK_DGRAM; hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(host, service, &hints, &a)) return -1;
    int fd = socket(a->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd >= 0) { if (!bind(fd, a->ai_addr, a->ai_addrlen)) out = save(fd); else close(fd); }
    freeaddrinfo(a); return out;
}
int d_udp_connect(int h, const char *host, int port) {
    struct addrinfo hints = {0}, *a = NULL; char service[8]; int out = -1;
    if (!valid(h) || port < 1 || port > 65535) return -1;
    snprintf(service, sizeof service, "%d", port); hints.ai_socktype = SOCK_DGRAM; hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(host, service, &hints, &a)) return -1;
    if (!connect(handles[h].fd, a->ai_addr, a->ai_addrlen)) out = 0;
    freeaddrinfo(a); return out;
}
int d_udp_receive(int h, void *data, int capacity, struct d_address *peer) {
    if (!valid(h) || capacity < 1 || capacity > 1232) return -1;
    struct d_address addr = {0}; addr.length = sizeof addr.address;
    ssize_t n = recvfrom(handles[h].fd, data, (size_t)capacity, MSG_TRUNC, (struct sockaddr *)&addr.address, &addr.length);
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? -2 : -1;
    if (n > capacity || addr.length > sizeof addr.address) return -2;
    if (peer) *peer = addr;
    return (int)n;
}
int d_udp_send(int h, const void *data, int n, const struct d_address *peer) {
    if (!valid(h) || n < 1 || n > 1232 || (peer && peer->length > sizeof peer->address)) return -1;
    ssize_t sent = peer ? sendto(handles[h].fd, data, (size_t)n, MSG_NOSIGNAL, (const struct sockaddr *)&peer->address, peer->length)
                        : send(handles[h].fd, data, (size_t)n, MSG_NOSIGNAL);
    return sent == n ? 0 : -1;
}
int d_udp_peer(int h, const struct d_address *peer) {
    if (!valid(h) || !peer || peer->length > sizeof peer->address) return -1;
    return connect(handles[h].fd, (const struct sockaddr *)&peer->address, peer->length);
}
void d_close(int h) {
    if (!valid(h)) return;
    SSL_free(handles[h].tls); SSL_CTX_free(handles[h].ctx); close(handles[h].fd); memset(&handles[h], 0, sizeof handles[h]);
}
static int waitfd(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - d_clock(); if (left <= 0) return -1;
        struct pollfd p = {fd, events, 0}; int r = poll(&p, 1, (int)(left > 10000 ? 10000 : left));
        if (r < 0 && errno == EINTR) continue;
        return r > 0 && (p.revents & (events | POLLHUP)) && !(p.revents & (POLLNVAL | POLLERR)) ? 0 : -1;
    }
}
int d_listen(const char *host, int port) {
    struct addrinfo hints = {0}, *a = NULL; char service[8]; int out = -1;
    if (port < 0 || port > 65535) return -1;
    snprintf(service, sizeof service, "%d", port); hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(host, service, &hints, &a)) return -1;
    int fd = socket(a->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd >= 0) { int yes = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes); if (!bind(fd, a->ai_addr, a->ai_addrlen) && !listen(fd, 16)) out = save(fd); else close(fd); }
    freeaddrinfo(a); return out;
}
int d_connect(const char *host, int port) {
    struct addrinfo hints = {0}, *a = NULL; char service[8]; int out = -1, count = 0;
    if (port < 1 || port > 65535) return -1;
    snprintf(service, sizeof service, "%d", port); hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICSERV;
    if (getaddrinfo(host, service, &hints, &a)) return -1;
    int64_t deadline = d_clock() + 10000;
    for (struct addrinfo *p = a; p && count++ < 8; p = p->ai_next) {
        int fd = socket(p->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); if (fd < 0) continue;
        int e = 0; socklen_t len = sizeof e;
        if ((connect(fd, p->ai_addr, p->ai_addrlen) == 0 || (errno == EINPROGRESS && !waitfd(fd, POLLOUT, deadline))) && !getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &len) && !e) { out = save(fd); break; }
        close(fd);
    }
    freeaddrinfo(a); return out;
}
int d_accept(int h) { return valid(h) ? ( { int fd = accept4(handles[h].fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC); fd < 0 ? -1 : save(fd); } ) : -1; }
int d_port(int h) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    if (!valid(h) || getsockname(handles[h].fd, (struct sockaddr *)&a, &n)) return -1;
    return ntohs(a.ss_family == AF_INET ? ((struct sockaddr_in *)&a)->sin_port : ((struct sockaddr_in6 *)&a)->sin6_port);
}
int d_ip(int h, char *out, int peer) {
    struct sockaddr_storage a; socklen_t n = sizeof a;
    if (!valid(h) || (peer ? getpeername(handles[h].fd, (struct sockaddr *)&a, &n) : getsockname(handles[h].fd, (struct sockaddr *)&a, &n))) return -1;
    void *p = a.ss_family == AF_INET ? (void *)&((struct sockaddr_in *)&a)->sin_addr : (void *)&((struct sockaddr_in6 *)&a)->sin6_addr;
    return inet_ntop(a.ss_family, p, out, 128) ? (int)strlen(out) : -1;
}
int d_tls(int h, const char *host, const char *cert, const char *key) {
    if (!valid(h) || handles[h].tls) return -1;
    int server = cert[0] != 0; SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) return -1;
    handles[h].ctx = ctx;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) return -1;
    if (server) {
        char data[65536]; int n = d_file(key, data, sizeof data); if (n < 0) return -1;
        BIO *bio = BIO_new_mem_buf(data, n); if (!bio) return -1;
        EVP_PKEY *priv = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL); BIO_free(bio); sodium_memzero(data, sizeof data);
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
    int64_t deadline = d_clock() + 10000;
    for (;;) {
        int r = server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (r == 1) return server || SSL_get_verify_result(ssl) == X509_V_OK ? 0 : -1;
        int e = SSL_get_error(ssl, r); if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return -1;
        if (waitfd(handles[h].fd, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline)) return -1;
    }
}
int d_read(int h, void *buf, int n, int exact) {
    if (!valid(h) || n < 0 || n > 65536) return -1;
    int used = 0; int64_t deadline = d_clock() + 10000;
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
int d_write(int h, const void *buf, int n) {
    if (!valid(h) || n < 0 || n > 65536) return -1;
    int used = 0; int64_t deadline = d_clock() + 10000;
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
int d_ready(int h) {
    if (!valid(h)) return 0;
    if (handles[h].tls && SSL_pending(handles[h].tls)) return 1;
    struct pollfd p = {handles[h].fd, POLLIN, 0};
    return poll(&p, 1, 0) > 0 && p.revents ? 1 : 0;
}
void d_pause(void) { struct timespec t = {0, 10000000}; nanosleep(&t, NULL); }
void d_half_close(int h) { if (valid(h)) shutdown(handles[h].fd, SHUT_WR); }
