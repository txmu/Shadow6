/* Included by sodium_ffi.c. All results are bounded; returned strings are copied
 * by the Idris C FFI before the next call. No Idris heap pointer casts. */
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pthread.h>
#include <limits.h>

#define IDRIS_LIMIT 1048576u
static _Thread_local char idris_result[2 * (IDRIS_LIMIT + 16) + 1];
static int decode_hex(const char *s, unsigned char *out, size_t cap, size_t *n) {
    size_t len = s ? strnlen(s, 2 * cap + 1) : 0;
    return !s || len > 2 * cap || (len & 1) ||
        sodium_hex2bin(out, cap, s, len, NULL, n, NULL) != 0 ? -1 : 0;
}
static const char *hex_result(const unsigned char *b, size_t n) {
    return sodium_bin2hex(idris_result, sizeof idris_result, b, n);
}
const char *idris_crypto_hex(int op, const char *key, const char *nonce,
                             const char *input, const char *signature) {
    unsigned char k[32] = {0}, iv[12] = {0}, sig[64] = {0};
    unsigned char *in = NULL, *out = NULL;
    size_t n = 0, kn = 0, ivn = 0, sn = 0; unsigned long long outn = 0;
    const char *result = "!crypto failure";
    if (sodium_init() < 0 || op < 0 || op > 3) goto done;
    in = malloc(IDRIS_LIMIT + 16); out = malloc(IDRIS_LIMIT + 16);
    if (!in || !out || decode_hex(input, in, IDRIS_LIMIT + 16, &n)) goto done;
    if (op == 0) {
        if (n > IDRIS_LIMIT || crypto_hash_sha256(out, in, n)) goto done;
        outn = 32;
    } else {
        if (decode_hex(key, k, sizeof k, &kn) || kn != sizeof k) goto done;
        if (op == 1) {
            if (n > IDRIS_LIMIT || decode_hex(signature, sig, sizeof sig, &sn) || sn != sizeof sig ||
                crypto_sign_verify_detached(sig, in, n, k)) goto done;
            result = "ok"; goto done;
        }
        if (!crypto_aead_aes256gcm_is_available() || decode_hex(nonce, iv, sizeof iv, &ivn) || ivn != sizeof iv) goto done;
        if (op == 2) {
            if (n > IDRIS_LIMIT || crypto_aead_aes256gcm_encrypt(out, &outn, in, n, NULL, 0, NULL, iv, k)) goto done;
        } else if (n < 16 || n > IDRIS_LIMIT + 16 ||
            crypto_aead_aes256gcm_decrypt(out, &outn, NULL, in, n, NULL, 0, iv, k)) goto done;
    }
    result = hex_result(out, (size_t)outn);
done:
    sodium_memzero(k, sizeof k); sodium_memzero(iv, sizeof iv); sodium_memzero(sig, sizeof sig);
    if (in) { sodium_memzero(in, IDRIS_LIMIT + 16); free(in); }
    if (out) { sodium_memzero(out, IDRIS_LIMIT + 16); free(out); }
    return result;
}
const char *idris_random_hex(unsigned int n) {
    if (n > IDRIS_LIMIT || sodium_init() < 0) return "!random failure";
    unsigned char *buf = malloc(n ? n : 1);
    if (!buf) return "!allocation failure";
    randombytes_buf(buf, n); hex_result(buf, n); sodium_memzero(buf, n); free(buf);
    return idris_result;
}
uint64_t idris_now(void) {
    time_t now = time(NULL);
    return now > 0 ? (uint64_t)now : 0;
}
static int private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
        (s->st_mode & 07777) == 0600 && s->st_nlink == 1;
}
const char *idris_read_secure_hex(const char *path) {
    int fd = -1; struct stat a, b; unsigned char *buf = NULL;
    const char *result = "!unsafe file";
    if (!path || !*path || strnlen(path, 4096) >= 4096) return result;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &a) || !private_file(&a) || a.st_size < 0 || a.st_size > IDRIS_LIMIT) goto done;
    buf = malloc((size_t)a.st_size + 1); if (!buf) goto done;
    size_t used = 0;
    while (used <= (size_t)a.st_size) {
        ssize_t n = read(fd, buf + used, (size_t)a.st_size + 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (!n) break;
        used += (size_t)n;
    }
    if (used != (size_t)a.st_size || fstat(fd, &b) || !private_file(&b) ||
        a.st_dev != b.st_dev || a.st_ino != b.st_ino || a.st_size != b.st_size ||
        a.st_mtime != b.st_mtime || a.st_ctime != b.st_ctime) goto done;
#if defined(__APPLE__)
    if (a.st_mtimespec.tv_nsec != b.st_mtimespec.tv_nsec || a.st_ctimespec.tv_nsec != b.st_ctimespec.tv_nsec) goto done;
#else
    if (a.st_mtim.tv_nsec != b.st_mtim.tv_nsec || a.st_ctim.tv_nsec != b.st_ctim.tv_nsec) goto done;
#endif
    result = hex_result(buf, used);
done:
    if (buf) { sodium_memzero(buf, (size_t)a.st_size + 1); free(buf); }
    if (fd >= 0) close(fd);
    return result;
}
/* Fixed ledger: expired entries only; a full/corrupt/locked ledger denies.
 * Durable before grant. Protect its directory from deletion/rollback by others. */
int idris_reserve_nonce(const char *path, const char *key, const char *nonce) {
    unsigned char records[256][72] = {{0}}, identity[48], digest[32], zero[72] = {0};
    char parent[4096]; size_t n; int dir = -1, fd = -1, slot = -1, rc = -1;
    struct stat st; uint64_t now = idris_now();
    if (!now || !path || !*path || strlen(path) >= sizeof parent ||
        decode_hex(key, identity, 32, &n) || n != 32 ||
        decode_hex(nonce, identity + 32, 16, &n) || n != 16) return -1;
    crypto_hash_sha256(digest, identity, sizeof identity);
    strcpy(parent, path); char *slash = strrchr(parent, '/');
    const char *base = slash ? slash + 1 : path;
    char name[256]; if (!*base || strlen(base) >= sizeof name || !strcmp(base, ".") || !strcmp(base, "..")) return -1;
    strcpy(name, base);
    if (slash) { if (slash == parent) slash[1] = 0; else *slash = 0; } else strcpy(parent, ".");
    dir = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0022)) goto done;
    fd = openat(dir, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) || fstat(fd, &st) || !private_file(&st) ||
        (st.st_size != 0 && st.st_size != sizeof records)) goto done;
    if (st.st_size && pread(fd, records, sizeof records, 0) != sizeof records) goto done;
    for (int i = 0; i < 256; ++i) {
        uint64_t stamp = 0; unsigned char sum[32];
        crypto_hash_sha256(sum, records[i], 40);
        if (memcmp(records[i], zero, 72) && sodium_memcmp(sum, records[i] + 40, 32)) goto done;
        for (int j = 0; j < 8; ++j) stamp = (stamp << 8) | records[i][j];
        if (stamp && (stamp > now || now - stamp <= 600)) {
            if (!sodium_memcmp(records[i] + 8, digest, 32)) goto done;
        } else if (slot < 0) slot = i;
    }
    if (slot < 0) goto done;
    for (int j = 0; j < 8; ++j) records[slot][7-j] = now >> (8*j);
    memcpy(records[slot] + 8, digest, 32); crypto_hash_sha256(records[slot] + 40, records[slot], 40);
    if (pwrite(fd, records, sizeof records, 0) == sizeof records && !fsync(fd) && !fsync(dir)) rc = 0;
done:
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    return rc;
}

/* Handles are generations, never raw descriptors: stale/copied Idris contexts
 * cannot close an unrelated descriptor or bypass the process-wide bound. */
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { int fd, handle, state; } owned[512];
static int next_handle = 1;
static int stopped;
int idris_socket_create(void) {
    pthread_mutex_lock(&socket_lock); int result = -1;
    if (stopped || next_handle == INT_MAX) goto done;
    for (int i = 0; i < 512; ++i) if (!owned[i].handle) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) break;
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK)) { close(fd); break; }
        owned[i].fd = fd; owned[i].handle = next_handle++; owned[i].state = 0;
        result = owned[i].handle; break;
    }
done:
    pthread_mutex_unlock(&socket_lock); return result;
}
int idris_socket_op(int handle, int op, const char *address, unsigned int value) {
    pthread_mutex_lock(&socket_lock); int rc = -1;
    for (int i = 0; i < 512; ++i) if (handle > 0 && owned[i].handle == handle) {
        if (op == 0 && value <= 65535 && address && !strcmp(address, "127.0.0.1") && owned[i].state == 0) {
            struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(value); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            rc = bind(owned[i].fd, (struct sockaddr *)&a, sizeof a);
            if (!rc) owned[i].state = 1;
        } else if (op == 1 && value > 0 && value <= 128 && owned[i].state == 1) {
            rc = listen(owned[i].fd, (int)value); if (!rc) owned[i].state = 2;
        } else if (op == 2) {
            close(owned[i].fd); memset(&owned[i], 0, sizeof owned[i]); rc = 0;
        }
        break;
    }
    pthread_mutex_unlock(&socket_lock); return rc;
}
void idris_shutdown(void) {
    pthread_mutex_lock(&socket_lock); stopped = 1;
    for (int i = 0; i < 512; ++i) if (owned[i].handle) {
        close(owned[i].fd); memset(&owned[i], 0, sizeof owned[i]);
    }
    pthread_mutex_unlock(&socket_lock);
}
