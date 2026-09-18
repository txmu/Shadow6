#ifdef SHADOW6_STATIC_NIF
#define STATIC_ERLANG_NIF_LIBNAME shadow6_sodium
#endif
#include <erl_nif.h>
#include <sodium.h>
#include <openssl/sha.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

static ERL_NIF_TERM atom(ErlNifEnv *env, const char *name) { return enif_make_atom(env, name); }

static ERL_NIF_TERM verify_mac(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary mac, message, key;
    if (argc != 3 || !enif_inspect_binary(env, argv[0], &mac) ||
        !enif_inspect_binary(env, argv[1], &message) || !enif_inspect_binary(env, argv[2], &key) ||
        mac.size != crypto_onetimeauth_BYTES || key.size != crypto_onetimeauth_KEYBYTES)
        return enif_make_badarg(env);
    return atom(env, crypto_onetimeauth_verify(mac.data, message.data,
      (unsigned long long)message.size, key.data) == 0 ? "true" : "false");
}

static ERL_NIF_TERM verify_ed25519(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary sig, message, key;
    if (argc != 3 || !enif_inspect_binary(env, argv[0], &sig) ||
        !enif_inspect_binary(env, argv[1], &message) || !enif_inspect_binary(env, argv[2], &key) ||
        sig.size != crypto_sign_BYTES || key.size != crypto_sign_PUBLICKEYBYTES)
        return enif_make_badarg(env);
    return atom(env, crypto_sign_verify_detached(sig.data, message.data,
      (unsigned long long)message.size, key.data) == 0 ? "true" : "false");
}

static ERL_NIF_TERM decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary cipher, mac, aad, nonce, key, plain;
    if (argc != 5 || !enif_inspect_binary(env, argv[0], &cipher) ||
        !enif_inspect_binary(env, argv[1], &mac) || !enif_inspect_binary(env, argv[2], &aad) ||
        !enif_inspect_binary(env, argv[3], &nonce) || !enif_inspect_binary(env, argv[4], &key) ||
        mac.size != crypto_aead_chacha20poly1305_ietf_ABYTES ||
        nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES ||
        key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES || !enif_alloc_binary(cipher.size, &plain))
        return enif_make_badarg(env);
    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(plain.data, NULL,
          cipher.data, (unsigned long long)cipher.size, mac.data,
          aad.data, (unsigned long long)aad.size, nonce.data, key.data) != 0) {
        sodium_memzero(plain.data, plain.size); enif_release_binary(&plain);
        return atom(env, "error");
    }
    return enif_make_tuple2(env, atom(env, "ok"), enif_make_binary(env, &plain));
}

static ERL_NIF_TERM encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary plain, aad, nonce, key, cipher, mac;
    if (argc != 4 || !enif_inspect_binary(env, argv[0], &plain) ||
        !enif_inspect_binary(env, argv[1], &aad) || !enif_inspect_binary(env, argv[2], &nonce) ||
        !enif_inspect_binary(env, argv[3], &key) || plain.size > 65472 ||
        nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES ||
        key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES ||
        !enif_alloc_binary(plain.size, &cipher) ||
        !enif_alloc_binary(crypto_aead_chacha20poly1305_ietf_ABYTES, &mac)) return enif_make_badarg(env);
    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(cipher.data, mac.data, NULL,
          plain.data, (unsigned long long)plain.size, aad.data, (unsigned long long)aad.size,
          NULL, nonce.data, key.data) != 0) {
        sodium_memzero(cipher.data, cipher.size); enif_release_binary(&cipher); enif_release_binary(&mac);
        return atom(env, "error");
    }
    return enif_make_tuple3(env, atom(env, "ok"), enif_make_binary(env, &cipher), enif_make_binary(env, &mac));
}

static ERL_NIF_TERM x25519(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary secret, peer, shared;
    if (argc != 2 || !enif_inspect_binary(env, argv[0], &secret) ||
        !enif_inspect_binary(env, argv[1], &peer) || secret.size != crypto_scalarmult_SCALARBYTES ||
        peer.size != crypto_scalarmult_BYTES || !enif_alloc_binary(crypto_scalarmult_BYTES, &shared))
        return enif_make_badarg(env);
    int rc = crypto_scalarmult(shared.data, secret.data, peer.data);
    if (rc != 0) { sodium_memzero(shared.data, shared.size); enif_release_binary(&shared); return atom(env, "error"); }
    return enif_make_tuple2(env, atom(env, "ok"), enif_make_binary(env, &shared));
}

static ERL_NIF_TERM keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary public_key, private_key;
    unsigned char expanded[crypto_sign_SECRETKEYBYTES];
    (void)argv;
    if (argc != 0 || !enif_alloc_binary(crypto_sign_PUBLICKEYBYTES, &public_key) ||
        !enif_alloc_binary(crypto_sign_SEEDBYTES, &private_key))
        return enif_make_badarg(env);
    randombytes_buf(private_key.data, private_key.size);
    if (crypto_sign_ed25519_seed_keypair(public_key.data, expanded, private_key.data) != 0) {
        sodium_memzero(private_key.data, private_key.size);
        sodium_memzero(expanded, sizeof(expanded));
        enif_release_binary(&private_key); enif_release_binary(&public_key);
        return atom(env, "error");
    }
    sodium_memzero(expanded, sizeof(expanded));
    return enif_make_tuple2(env, enif_make_binary(env, &private_key),
                            enif_make_binary(env, &public_key));
}

static ERL_NIF_TERM sha256(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary input, output;
    if (argc != 1 || !enif_inspect_iolist_as_binary(env, argv[0], &input) ||
        !enif_alloc_binary(crypto_hash_sha256_BYTES, &output)) return enif_make_badarg(env);
    crypto_hash_sha256(output.data, input.data, (unsigned long long)input.size);
    return enif_make_binary(env, &output);
}

static ERL_NIF_TERM sha1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary input, output;
    if (argc != 1 || !enif_inspect_iolist_as_binary(env, argv[0], &input) ||
        !enif_alloc_binary(SHA_DIGEST_LENGTH, &output)) return enif_make_badarg(env);
    SHA1(input.data, input.size, output.data);
    return enif_make_binary(env, &output);
}

static ERL_NIF_TERM random_bytes(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    unsigned int size; ErlNifBinary output;
    if (argc != 1 || !enif_get_uint(env, argv[0], &size) || size == 0 || size > 65536 ||
        !enif_alloc_binary(size, &output)) return enif_make_badarg(env);
    randombytes_buf(output.data, output.size);
    return enif_make_binary(env, &output);
}

static ERL_NIF_TERM sign_ed25519(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary message, seed, signature; unsigned char secret[crypto_sign_SECRETKEYBYTES];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    if (argc != 2 || !enif_inspect_iolist_as_binary(env, argv[0], &message) ||
        !enif_inspect_binary(env, argv[1], &seed) || seed.size != crypto_sign_SEEDBYTES ||
        !enif_alloc_binary(crypto_sign_BYTES, &signature)) return enif_make_badarg(env);
    crypto_sign_seed_keypair(public_key, secret, seed.data);
    crypto_sign_detached(signature.data, NULL, message.data, message.size, secret);
    sodium_memzero(secret, sizeof(secret)); sodium_memzero(public_key, sizeof(public_key));
    return enif_make_binary(env, &signature);
}

static ERL_NIF_TERM read_secure(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    char path[4096]; struct stat before, after; int fd = -1; ErlNifBinary out, input;
    if (argc != 1 || !enif_inspect_iolist_as_binary(env, argv[0], &input) ||
        input.size == 0 || input.size >= sizeof(path) || memchr(input.data, 0, input.size) != NULL)
        return enif_make_badarg(env);
    memcpy(path, input.data, input.size); path[input.size] = 0;
    /* A FIFO must reach fstat instead of blocking a dirty IO scheduler. */
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || (before.st_mode & 07777) != 0600 ||
        before.st_size <= 0 || before.st_size > 1048576 ||
        !enif_alloc_binary((size_t)before.st_size, &out)) goto fail;
    size_t used = 0;
    while (used < out.size) {
        ssize_t got = read(fd, out.data + used, out.size - used);
        if (got <= 0) { enif_release_binary(&out); goto fail; }
        used += (size_t)got;
    }
    uint8_t extra; if (read(fd, &extra, 1) != 0 || fstat(fd, &after) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_size != after.st_size || before.st_mode != after.st_mode ||
        before.st_uid != after.st_uid) { enif_release_binary(&out); goto fail; }
    close(fd);
    return enif_make_tuple2(env, atom(env, "ok"), enif_make_binary(env, &out));
fail:
    if (fd >= 0) close(fd);
    return enif_make_tuple2(env, atom(env, "error"), atom(env, "unsafe_file"));
}

/* A bounded persistent nonce ledger, committed before a Crosed grant. */
static ERL_NIF_TERM reserve_nonce(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary path, digest;
    char parent[4096], name[256];
    unsigned char records[256][72] = {{0}}, zero[72] = {0};
    struct stat info;
    int directory = -1, fd = -1, slot = -1, ok = 0;
    time_t now = time(NULL);
    if (argc != 2 || !enif_inspect_iolist_as_binary(env, argv[0], &path) ||
        !enif_inspect_binary(env, argv[1], &digest) || digest.size != 32 ||
        path.size == 0 || path.size >= sizeof(parent) || memchr(path.data, 0, path.size) || now <= 0)
        return enif_make_badarg(env);
    memcpy(parent, path.data, path.size); parent[path.size] = 0;
    char *slash = strrchr(parent, '/');
    const char *base = slash ? slash + 1 : parent;
    size_t length = strlen(base);
    if (!length || length + sizeof(".replay") > sizeof(name)) goto done;
    memcpy(name, base, length); memcpy(name + length, ".replay", sizeof(".replay"));
    if (slash) { if (slash == parent) slash[1] = 0; else *slash = 0; }
    else strcpy(parent, ".");
    directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || fstat(directory, &info) || info.st_uid != geteuid() || (info.st_mode & 0022)) goto done;
    fd = openat(directory, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) || fstat(fd, &info) ||
        !S_ISREG(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 07777) != 0600 ||
        info.st_nlink != 1 || (info.st_size != 0 && info.st_size != sizeof(records))) goto done;
    if (info.st_size && pread(fd, records, sizeof(records), 0) != sizeof(records)) goto done;
    for (int i = 0; i < 256; ++i) {
        unsigned char checksum[32]; uint64_t stamp = 0;
        if (memcmp(records[i], zero, sizeof(zero)) &&
            (!SHA256(records[i], 40, checksum) || memcmp(checksum, records[i] + 40, 32))) goto done;
        for (int j = 0; j < 8; ++j) stamp = (stamp << 8) | records[i][j];
        if (stamp && (stamp > (uint64_t)now || (uint64_t)now - stamp <= 600)) {
            if (!sodium_memcmp(records[i] + 8, digest.data, 32)) goto done;
        } else if (slot < 0) slot = i;
    }
    if (slot < 0) goto done;
    for (int j = 0; j < 8; ++j) records[slot][7-j] = (uint64_t)now >> (8*j);
    memcpy(records[slot] + 8, digest.data, 32);
    if (!SHA256(records[slot], 40, records[slot] + 40)) goto done;
    ok = pwrite(fd, records, sizeof(records), 0) == sizeof(records) && !fsync(fd) && !fsync(directory);
done:
    if (fd >= 0) close(fd);
    if (directory >= 0) close(directory);
    return atom(env, ok ? "true" : "false");
}

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)env; (void)priv; (void)info;
    return sodium_init() < 0 ? -1 : 0;
}

static ErlNifFunc functions[] = {
  {"verify_mac", 3, verify_mac, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"verify_ed25519", 3, verify_ed25519, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"decrypt", 5, decrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"encrypt", 4, encrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"x25519", 2, x25519, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"keypair", 0, keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"sha256", 1, sha256, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"sha1", 1, sha1, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"random_bytes", 1, random_bytes, 0},
  {"sign_ed25519", 2, sign_ed25519, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"read_secure", 1, read_secure, ERL_NIF_DIRTY_JOB_IO_BOUND},
  {"reserve_nonce", 2, reserve_nonce, ERL_NIF_DIRTY_JOB_IO_BOUND}
};
ERL_NIF_INIT(shadow6_sodium, functions, load, NULL, NULL, NULL)
