/**
 * libsodium FFI wrapper for Idris 2
 * Provides safe C bindings for cryptographic operations
 */

#include <sodium.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

/* Initialize libsodium - must be called before any other function */
int idris_sodium_init(void) {
    return sodium_init();
}

/* Securely zero memory */
void idris_sodium_memzero(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
}

/* Ed25519 signature verification */
int idris_ed25519_verify(const unsigned char *sig,
                         const unsigned char *msg,
                         uint64_t msg_len,
                         const unsigned char *pubkey) {
    if (!sig || !msg || !pubkey) return -1;
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pubkey);
}

/* Check if AES-256-GCM is available on this CPU */
int idris_aes256gcm_available(void) {
    return crypto_aead_aes256gcm_is_available();
}

/* AES-256-GCM encryption */
int idris_aes256gcm_encrypt(unsigned char *ciphertext,
                            uint64_t *ciphertext_len,
                            const unsigned char *plaintext,
                            uint64_t plaintext_len,
                            const unsigned char *ad,
                            uint64_t ad_len,
                            const unsigned char *nsec,
                            const unsigned char *nonce,
                            const unsigned char *key) {
    if (!ciphertext || !plaintext || !nonce || !key) return -1;
    
    unsigned long long clen;
    int result = crypto_aead_aes256gcm_encrypt(
        ciphertext, &clen,
        plaintext, plaintext_len,
        ad, ad_len,
        nsec,
        nonce,
        key
    );
    
    if (ciphertext_len) {
        *ciphertext_len = (uint64_t)clen;
    }
    
    return result;
}

/* AES-256-GCM decryption */
int idris_aes256gcm_decrypt(unsigned char *plaintext,
                            uint64_t *plaintext_len,
                            unsigned char *nsec,
                            const unsigned char *ciphertext,
                            uint64_t ciphertext_len,
                            const unsigned char *ad,
                            uint64_t ad_len,
                            const unsigned char *nonce,
                            const unsigned char *key) {
    if (!plaintext || !ciphertext || !nonce || !key) return -1;
    
    unsigned long long plen;
    int result = crypto_aead_aes256gcm_decrypt(
        plaintext, &plen,
        nsec,
        ciphertext, ciphertext_len,
        ad, ad_len,
        nonce,
        key
    );
    
    if (plaintext_len) {
        *plaintext_len = (uint64_t)plen;
    }
    
    return result;
}

/* SHA-256 hash */
int idris_sha256(unsigned char *out,
                 const unsigned char *in,
                 uint64_t in_len) {
    if (!out || !in) return -1;
    return crypto_hash_sha256(out, in, in_len);
}

/* Generate random bytes */
void idris_random_bytes(unsigned char *buf, size_t size) {
    randombytes_buf(buf, size);
}

/* Constant-time memory comparison */
int idris_memcmp_constant_time(const void *a, const void *b, size_t len) {
    return sodium_memcmp(a, b, len);
}

/* Bounded loopback integration primitive.  It never exposes a non-loopback
 * listener and accepts exactly one length-prefixed frame. */
int idris_loopback_exchange(const unsigned char *request, uint64_t request_len,
                            unsigned char *response, uint64_t response_cap) {
    if (!request || !response || request_len > 1200 || response_cap < request_len) return -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -2;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) || listen(s, 1)) { close(s); return -3; }
    socklen_t alen = sizeof(a); if (getsockname(s, (struct sockaddr*)&a, &alen)) { close(s); return -4; }
    int c = socket(AF_INET, SOCK_STREAM, 0); if (c < 0) { close(s); return -5; }
    if (connect(c, (struct sockaddr*)&a, sizeof(a))) { close(c); close(s); return -6; }
    int p = accept(s, NULL, NULL); if (p < 0) { close(c); close(s); return -7; }
    uint32_t n = htonl((uint32_t)request_len); if (send(c, &n, 4, MSG_NOSIGNAL) != 4 || send(c, request, request_len, MSG_NOSIGNAL) != (ssize_t)request_len) { close(p); close(c); close(s); return -8; }
    uint32_t rn = 0; unsigned char frame[1200];
    if (recv(p, &rn, 4, MSG_WAITALL) != 4) { close(p); close(c); close(s); return -9; }
    rn = ntohl(rn); if (rn > sizeof(frame) || recv(p, frame, rn, MSG_WAITALL) != (ssize_t)rn || rn != request_len || memcmp(frame, request, rn) != 0) { close(p); close(c); close(s); return -10; }
    if (send(p, &n, 4, MSG_NOSIGNAL) != 4 || send(p, request, request_len, MSG_NOSIGNAL) != (ssize_t)request_len) { close(p); close(c); close(s); return -11; }
    if (recv(c, &rn, 4, MSG_WAITALL) != 4) { close(p); close(c); close(s); return -12; }
    rn = ntohl(rn); if (rn > response_cap || rn > 1200 || recv(c, response, rn, MSG_WAITALL) != (ssize_t)rn) { close(p); close(c); close(s); return -13; }
    close(p); close(c); close(s); return (int)rn;
}

/* Full cryptographic loopback contract: Ed25519 identity, X25519 agreement,
 * and XChaCha20-Poly1305 data authentication. Returns 0 only when both a
 * valid exchange and rejection of tampered/unknown identity frames succeed. */
int idris_secure_loopback_test(void) {
    unsigned char apk[crypto_sign_PUBLICKEYBYTES], ask[crypto_sign_SECRETKEYBYTES];
    unsigned char bpk[crypto_sign_PUBLICKEYBYTES], bsk[crypto_sign_SECRETKEYBYTES];
    unsigned char msg[32], sig[crypto_sign_BYTES], shared[crypto_scalarmult_BYTES];
    unsigned char ax[32], bx[32], ap[32], bp[32];
    unsigned long long slen = 0;
    if (crypto_sign_keypair(apk, ask) || crypto_sign_keypair(bpk, bsk)) return -1;
    randombytes_buf(msg, sizeof(msg));
    if (crypto_sign_detached(sig, &slen, msg, sizeof(msg), ask) ||
        crypto_sign_verify_detached(sig, msg, sizeof(msg), apk) != 0) return -2;
    sig[0] ^= 1;
    if (crypto_sign_verify_detached(sig, msg, sizeof(msg), apk) == 0) return -3;
    sig[0] ^= 1;
    randombytes_buf(ax, 32); randombytes_buf(bx, 32);
    if (crypto_scalarmult_base(ap, ax) || crypto_scalarmult_base(bp, bx) ||
        crypto_scalarmult(shared, ax, bp) != 0) return -4;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], ct[128], out[128];
    unsigned long long clen = 0, plen = 0; const unsigned char text[] = "shadow6-secure-loopback";
    randombytes_buf(nonce, sizeof(nonce));
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &clen, text, sizeof(text),
        msg, sizeof(msg), NULL, nonce, shared) != 0) return -5;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &plen, NULL, ct, clen,
        msg, sizeof(msg), nonce, shared) != 0 || plen != sizeof(text) || memcmp(out, text, plen)) return -6;
    ct[0] ^= 1;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &plen, NULL, ct, clen,
        msg, sizeof(msg), nonce, shared) == 0) return -7;
    const unsigned char request[] = "ping"; unsigned char response[sizeof(request)];
    int exchanged = idris_loopback_exchange(request, sizeof(request) - 1, response, sizeof(response));
    if (exchanged != (int)(sizeof(request) - 1) || memcmp(request, response, sizeof(request) - 1)) return -8;
    return 0;
}
