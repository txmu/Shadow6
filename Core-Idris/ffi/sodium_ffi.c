/**
 * libsodium FFI wrapper for Idris 2
 * Provides safe C bindings for cryptographic operations
 */

#include <sodium.h>
#include <string.h>
#include <stdint.h>

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
