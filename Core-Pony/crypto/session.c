/* Bounded synchronous FFI: no retained pointers, allocation, I/O, callbacks or
 * Pony runtime calls. Outputs are initialized and cleared on authentication
 * failure. randombytes_buf uses the OS CSPRNG and belongs to the trusted FFI. */
#include <sodium.h>
#include <stdint.h>
#include <string.h>

enum { HELLO = 140, RESPONSE = 172, STATE = 236, KEYS = 96, MAX_FRAME = 1200 };

static uint64_t read64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; ++i) n = (n << 8) | p[i];
    return n;
}
static void write64(unsigned char *p, uint64_t n) {
    for (unsigned i = 8; i > 0; --i) { p[i - 1] = (unsigned char)n; n >>= 8; }
}
static int fresh(const unsigned char *p, uint64_t now) {
    uint64_t issued = read64(p);
    return issued <= now && now - issued <= 30;
}
static int identity(const unsigned char *seed, unsigned char *pk, unsigned char *sk) {
    return crypto_sign_seed_keypair(pk, sk, seed);
}

int s6p_public(const unsigned char *seed, size_t n, unsigned char *pk, size_t cap) {
    if (!seed || !pk || n != 32 || cap != 32 || sodium_init() < 0) return -1;
    unsigned char sk[64];
    int result = identity(seed, pk, sk);
    sodium_memzero(sk, sizeof sk);
    return result;
}

/* Signature inputs include both pinned identities, role/version and the full
 * prior transcript. This prevents reflection and unknown-key-share attacks. */
static size_t signed_input(unsigned char *out, const unsigned char *packet,
                          size_t n, const unsigned char *client,
                          const unsigned char *agent, const unsigned char *hello) {
    memcpy(out, packet, n);
    memcpy(out + n, client, 32);
    memcpy(out + n + 32, agent, 32);
    if (hello) { memcpy(out + n + 64, hello, HELLO); return n + 64 + HELLO; }
    return n + 64;
}

/* State is serialized bytes: ephemeral secret | own identity | peer identity |
 * exact client hello. Its sole owner must wipe it after completion/timeout. */
int s6p_start(const unsigned char *seed, size_t n, const unsigned char *peer,
              size_t pn, unsigned char *state, size_t sn,
              unsigned char *out, size_t cap, uint64_t now) {
    if (!seed || !peer || !state || !out || n != 32 || pn != 32 ||
        sn != STATE || cap != HELLO || sodium_init() < 0) return -1;
    unsigned char sk[64], input[140];
    memset(state, 0, STATE); memset(out, 0, HELLO);
    int rc = identity(seed, state + 32, sk);
    memcpy(state + 64, peer, 32);
    memcpy(out, "S6P1", 4); write64(out + 4, now);
    randombytes_buf(out + 12, 32);
    randombytes_buf(state, 32);
    rc |= crypto_scalarmult_curve25519_base(out + 44, state);
    size_t len = signed_input(input, out, 76, state + 32, peer, NULL);
    rc |= crypto_sign_detached(out + 76, NULL, input, len, sk);
    memcpy(state + 96, out, HELLO);
    sodium_memzero(sk, sizeof sk); sodium_memzero(input, sizeof input);
    if (rc) { sodium_memzero(state, STATE); sodium_memzero(out, HELLO); }
    return rc ? -1 : 0;
}

static int derive(unsigned char *keys, const unsigned char *secret,
                  const unsigned char *remote, const unsigned char *hello,
                  const unsigned char *response, int client) {
    unsigned char shared[32], material[320], root[32], first[32], second[32];
    int rc = crypto_scalarmult_curve25519(shared, secret, remote);
    if (rc) { sodium_memzero(shared, sizeof shared); return -1; }
    memcpy(material, "S6PKDF01", 8);
    memcpy(material + 8, hello, HELLO);
    memcpy(material + 8 + HELLO, response, RESPONSE);
    rc |= crypto_generichash(root, 32, material, sizeof material, shared, 32);
    rc |= crypto_generichash(first, 32, (const unsigned char *)"S6P-c2a", 7, root, 32);
    rc |= crypto_generichash(second, 32, (const unsigned char *)"S6P-a2c", 7, root, 32);
    rc |= crypto_generichash(keys + 64, 32, material, sizeof material, NULL, 0);
    memcpy(keys, client ? first : second, 32);
    memcpy(keys + 32, client ? second : first, 32);
    sodium_memzero(shared, sizeof shared); sodium_memzero(root, sizeof root);
    sodium_memzero(first, sizeof first); sodium_memzero(second, sizeof second);
    sodium_memzero(material, sizeof material);
    return rc ? -1 : 0;
}

int s6p_respond(const unsigned char *seed, size_t n, const unsigned char *peer,
                size_t pn, const unsigned char *hello, size_t hn,
                unsigned char *out, size_t cap, unsigned char *keys,
                size_t kn, uint64_t now) {
    if (!seed || !peer || !hello || !out || !keys || n != 32 || pn != 32 ||
        hn != HELLO || cap != RESPONSE || kn != KEYS || sodium_init() < 0) return -1;
    memset(out, 0, RESPONSE); memset(keys, 0, KEYS);
    if (memcmp(hello, "S6P1", 4) || !fresh(hello + 4, now)) return -1;
    unsigned char sk[64], pk[32], input[312], secret[32];
    int rc = identity(seed, pk, sk);
    size_t len = signed_input(input, hello, 76, peer, pk, NULL);
    rc |= crypto_sign_verify_detached(hello + 76, input, len, peer);
    if (rc == 0) {
        memcpy(out, "S6P2", 4); write64(out + 4, now);
        memcpy(out + 12, hello + 12, 32);
        randombytes_buf(out + 44, 32); randombytes_buf(secret, 32);
        rc |= crypto_scalarmult_curve25519_base(out + 76, secret);
        len = signed_input(input, out, 108, peer, pk, hello);
        rc |= crypto_sign_detached(out + 108, NULL, input, len, sk);
        rc |= derive(keys, secret, hello + 44, hello, out, 0);
    }
    sodium_memzero(sk, sizeof sk); sodium_memzero(secret, sizeof secret);
    sodium_memzero(input, sizeof input);
    if (rc) { sodium_memzero(out, RESPONSE); sodium_memzero(keys, KEYS); }
    return rc ? -1 : 0;
}

int s6p_finish(unsigned char *state, size_t sn, const unsigned char *response,
               size_t rn, unsigned char *keys, size_t kn, uint64_t now) {
    if (!state || !response || !keys || sn != STATE || rn != RESPONSE ||
        kn != KEYS || sodium_init() < 0) return -1;
    unsigned char input[312];
    memset(keys, 0, KEYS);
    const unsigned char *hello = state + 96;
    int rc = -1;
    if (!memcmp(response, "S6P2", 4) && fresh(response + 4, now) &&
        fresh(hello + 4, now) && !sodium_memcmp(response + 12, hello + 12, 32)) {
        size_t len = signed_input(input, response, 108, state + 32, state + 64, hello);
        rc = crypto_sign_verify_detached(response + 108, input, len, state + 64);
        if (rc == 0) rc = derive(keys, state, response + 76, hello, response, 1);
    }
    /* Any completion attempt consumes the pending handshake. Retry requires
     * fresh randomness, never reuse the ephemeral secret after an error. */
    sodium_memzero(state, STATE); sodium_memzero(input, sizeof input);
    if (rc) sodium_memzero(keys, KEYS);
    return rc ? -1 : 0;
}

/* AEAD is detached and in-place. Caller owns packet exclusively. Header (kind,
 * counter) and session transcript hash are authenticated. No pointer is kept.
 * Replay/lifetime state stays with the owning Pony actor, after tag success. */
int s6p_seal(unsigned char *packet, size_t cap, size_t size,
              const unsigned char *keys, size_t kn, uint64_t sequence, unsigned kind) {
    if (!packet || !keys || cap > MAX_FRAME || size < 12 || size + 16 > cap ||
        kn != KEYS || !sequence || sequence > 1000000 || kind > 3) return -1;
    unsigned char nonce[12] = {0}, ad[44];
    memcpy(packet, "S6D", 3); packet[3] = (unsigned char)kind;
    write64(packet + 4, sequence); write64(nonce + 4, sequence);
    memcpy(ad, packet, 12); memcpy(ad + 12, keys + 64, 32);
    return crypto_aead_chacha20poly1305_ietf_encrypt_detached(packet + 12,
        packet + size, NULL, packet + 12, size - 12, ad, sizeof ad, NULL, nonce, keys);
}
int s6p_open(unsigned char *packet, size_t size, const unsigned char *keys, size_t kn) {
    if (!packet || !keys || size < 28 || size > MAX_FRAME || kn != KEYS ||
        memcmp(packet, "S6D", 3) || packet[3] > 3) return -1;
    uint64_t sequence = read64(packet + 4);
    if (!sequence || sequence > 1000000) return -1;
    unsigned char nonce[12] = {0}, ad[44];
    write64(nonce + 4, sequence);
    memcpy(ad, packet, 12); memcpy(ad + 12, keys + 64, 32);
    /* libsodium permits zero-length plaintext, but some builds reject an
     * overlapping zero-length ciphertext/tag pointer. Give that case a
     * stable non-overlapping sentinel while preserving the wire format. */
    static const unsigned char empty_ciphertext = 0;
    const unsigned char *ciphertext = (size == 28) ? &empty_ciphertext : packet + 12;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached(packet + 12, NULL,
        ciphertext, size - 28, packet + size - 16, ad, sizeof ad, nonce, keys + 32);
    if (rc) sodium_memzero(packet, size);
    return rc;
}
