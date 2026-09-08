/* Toolchain link/runtime smoke test; never part of the production Core. */
#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    const unsigned char input[] = "Shadow6 toolchain smoke test";
    unsigned char encrypted[sizeof input + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned char output[sizeof input];
    unsigned long long encrypted_len = 0, output_len = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int result = 1;
    if (sodium_init() < 0) return 1;
    randombytes_buf(key, sizeof key);
    randombytes_buf(nonce, sizeof nonce);
    if (crypto_aead_chacha20poly1305_ietf_encrypt(encrypted, &encrypted_len,
            input, sizeof input, NULL, 0, NULL, nonce, key) != 0) goto done;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(output, &output_len, NULL,
            encrypted, encrypted_len, NULL, 0, nonce, key) != 0) goto done;
    if (output_len != sizeof input || sodium_memcmp(input, output, sizeof input)) goto done;
    encrypted[0] ^= 1;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(output, &output_len, NULL,
            encrypted, encrypted_len, NULL, 0, nonce, key) == 0) goto done;
    if (!EVP_Digest(input, sizeof input, digest, &digest_len, EVP_sha256(), NULL)
            || digest_len != 32) goto done;
    puts("musl static PIE: sodium AEAD round-trip/tamper rejection and OpenSSL SHA-256 OK");
    result = 0;
done:
    sodium_memzero(key, sizeof key);
    sodium_memzero(output, sizeof output);
    return result;
}
