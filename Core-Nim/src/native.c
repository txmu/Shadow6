#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static int owned(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
           (s->st_mode & 07777) == 0600 && s->st_nlink == 1;
}
int nim_secure_read(const char *path, char *out, int cap) {
    struct stat before, opened, after;
    if (cap < 1 || cap > 65536 || lstat(path, &before) || !owned(&before)) return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    int n = -1;
    if (fstat(fd, &opened) || !owned(&opened) || before.st_dev != opened.st_dev ||
        before.st_ino != opened.st_ino || opened.st_size < 0 || opened.st_size > cap) goto end;
    n = 0;
    while (n < opened.st_size) {
        ssize_t count = read(fd, out+n, opened.st_size-n);
        if (count <= 0) { n = -1; goto end; }
        n += (int)count;
    }
    char extra;
    if (read(fd, &extra, 1) != 0 || fstat(fd, &after) || !owned(&after) ||
        opened.st_size != after.st_size ||
        opened.st_mtim.tv_sec != after.st_mtim.tv_sec || opened.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        opened.st_ctim.tv_sec != after.st_ctim.tv_sec || opened.st_ctim.tv_nsec != after.st_ctim.tv_nsec) n = -1;
end:
    close(fd);
    return n;
}
int nim_random(unsigned char *out, int n) { return n > 0 && n <= 65536 && RAND_bytes(out,n) == 1; }
int nim_hash(const void *data, size_t size, unsigned char *out) {
    unsigned n = 0;
    return size <= 65536 && EVP_Digest(data,size,out,&n,EVP_sha256(),NULL) == 1 && n == 32;
}
int nim_public(const unsigned char *seed, unsigned char *out) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,seed,32);
    size_t n = 32;
    int ok = key && EVP_PKEY_get_raw_public_key(key,out,&n) == 1 && n == 32;
    EVP_PKEY_free(key);
    return ok;
}
int nim_signature(int signing, const unsigned char *key, const void *data, size_t n, unsigned char *sig) {
    if (n > 65536) return 0;
    EVP_PKEY *p = signing ? EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,NULL,key,32)
                         : EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,key,32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t size = 64;
    int ok = p && ctx && (signing
        ? EVP_DigestSignInit(ctx,NULL,NULL,NULL,p) == 1 && EVP_DigestSign(ctx,sig,&size,data,n) == 1 && size == 64
        : EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,p) == 1 && EVP_DigestVerify(ctx,sig,64,data,n) == 1);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(p);
    return ok;
}

/* Store nonce digests under a locked, owner-only directory. No live eviction. */
int nim_replay(const char *path, const unsigned char *hash, int64_t now) {
    unsigned char records[256][72] = {{0}}, zero[72] = {0};
    char parent[4096]; struct stat st; int result = 0, slot = -1;
    if (now <= 0 || strlen(path) >= sizeof parent) return 0;
    strcpy(parent,path);
    char *last = strrchr(parent,'/');
    const char *name = last ? last+1 : path;
    if (!*name) return 0;
    if (last) { if (last == parent) return 0; *last = 0; }
    else strcpy(parent,".");
    int dir = open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (dir < 0) return 0;
    if (fstat(dir,&st) || st.st_uid != geteuid() || (st.st_mode & 0022)) goto directory_end;
    int fd = openat(dir,name,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
    if (fd < 0) goto directory_end;
    if (flock(fd,LOCK_EX|LOCK_NB) || fstat(fd,&st) || !owned(&st) ||
        (st.st_size != 0 && st.st_size != sizeof records)) goto file_end;
    if (st.st_size && pread(fd,records,sizeof records,0) != sizeof records) goto file_end;
    for (int i = 0; i < 256; ++i) {
        unsigned char checksum[32]; uint64_t stamp = 0;
        if (memcmp(records[i],zero,72) &&
            (!nim_hash(records[i],40,checksum) || memcmp(checksum,records[i]+40,32))) goto file_end;
        for (int j = 0; j < 8; ++j) stamp = (stamp<<8)|records[i][j];
        if (stamp && (stamp > (uint64_t)now || (uint64_t)now-stamp <= 600)) {
            if (!memcmp(records[i]+8,hash,32)) goto file_end;
        } else if (slot < 0) slot = i;
    }
    if (slot < 0) goto file_end;
    for (int j = 0; j < 8; ++j) records[slot][7-j] = (uint64_t)now >> (8*j);
    memcpy(records[slot]+8,hash,32);
    if (!nim_hash(records[slot],40,records[slot]+40)) goto file_end;
    result = pwrite(fd,records,sizeof records,0) == sizeof records && !fsync(fd) && !fsync(dir);
file_end: close(fd);
directory_end: close(dir);
    return result;
}
int nim_tcp_listen(void) {
    int fd = socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && !bind(fd,(void *)&a,sizeof a) && !listen(fd,1)) return fd;
    if (fd >= 0) close(fd);
    return -1;
}
int nim_tcp_port(int fd) {
    struct sockaddr_in a; socklen_t n = sizeof a;
    return getsockname(fd,(void *)&a,&n) ? -1 : ntohs(a.sin_port);
}
int nim_tcp_accept(int fd) { return accept4(fd,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC); }
int nim_tcp_connect(int port) {
    int fd = socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(port);
    if (fd >= 0 && (!connect(fd,(void *)&a,sizeof a) || errno == EINPROGRESS)) return fd;
    if (fd >= 0) close(fd);
    return -1;
}
int nim_tcp_read(int fd, void *data, int n) {
    int result = (int)recv(fd,data,n,0);
    return result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? -2 : result;
}
int nim_tcp_write(int fd, const void *data, int n) {
    int result = (int)send(fd,data,n,MSG_NOSIGNAL);
    return result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOTCONN) ? -2 : result;
}
void nim_tcp_close(int fd) { if (fd >= 0) close(fd); }
void nim_tcp_halfclose(int fd) { if (fd >= 0) shutdown(fd,SHUT_WR); }
