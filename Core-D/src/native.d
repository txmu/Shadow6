module native;
@nogc nothrow:
extern(C) {
    int d_init();
    int d_random(void*, int);
    int d_keypair(const(void)*, void*, void*);
    int d_sign(const(void)*, const(void)*, int, void*);
    int d_verify(const(void)*, const(void)*, int, const(void)*);
    int d_xpublic(const(void)*, void*);
    int d_shared(const(void)*, const(void)*, void*);
    int d_hash(const(void)*, int, void*, int);
    void d_wipe(void*, int);
    int d_encrypt(const(void)*, const(void)*, const(void)*, int, const(void)*, int, void*);
    int d_decrypt(const(void)*, const(void)*, const(void)*, int, const(void)*, int, void*);
    int d_file(const(char)*, void*, int);
    long d_now();
    long d_clock();
    int d_listen(const(char)*, int);
    int d_connect(const(char)*, int);
    int d_accept(int);
    int d_port(int);
    int d_ip(int, void*, int);
    int d_tls(int, const(char)*, const(char)*, const(char)*);
    int d_read(int, void*, int, int);
    int d_write(int, const(void)*, int);
    int d_ready(int);
    void d_pause();
    void d_close(int);
    void d_half_close(int);
    int d_udp(const(char)*, int);
    int d_udp_connect(int, const(char)*, int);
    int d_udp_receive(int, void*, int, void*);
    int d_udp_send(int, const(void)*, int, const(void)*);
    int d_udp_peer(int, const(void)*);
}

alias Key = ubyte[32];
alias Secret = ubyte[64];
alias Signature = ubyte[64];

bool random(ubyte[] outBytes)
in { assert(outBytes.length <= 65536); }
out(ok) { assert(outBytes.length <= 65536); }
do { return d_random(outBytes.ptr, cast(int)outBytes.length) == 0; }

bool keypair(ref const Key seed, out Key pub, out Secret secret)
in { assert(seed.length == 32); }
out(ok) { assert(pub.length == 32 && secret.length == 64); }
do { return d_keypair(seed.ptr, pub.ptr, secret.ptr) == 0; }

bool sign(ref const Secret secret, const(ubyte)[] data, out Signature sig)
in { assert(data.length <= 65536); }
out(ok) { assert(sig.length == 64); }
do { return d_sign(secret.ptr, data.ptr, cast(int)data.length, sig.ptr) == 0; }

bool verify(ref const Key pub, const(ubyte)[] data, ref const Signature sig)
in { assert(data.length <= 65536 && sig.length == 64); }
out(ok) { assert(data.length <= 65536); }
do { return d_verify(pub.ptr, data.ptr, cast(int)data.length, sig.ptr) == 0; }

bool hash(const(ubyte)[] data, out Key digest)
in { assert(data.length <= 65536); }
out(ok) { assert(digest.length == 32); }
do { return d_hash(data.ptr, cast(int)data.length, digest.ptr, 0) == 0; }

bool deriveShared(ref const Key secret, ref const Key peer, out Key result)
in { assert(secret.length == 32 && peer.length == 32); }
out(ok) { assert(result.length == 32); }
do { return d_shared(secret.ptr, peer.ptr, result.ptr) == 0; }

bool publicKey(ref const Key secret, out Key pub)
in { assert(secret.length == 32); }
out(ok) { assert(pub.length == 32); }
do { return d_xpublic(secret.ptr, pub.ptr) == 0; }

bool encrypt(ref const Key key, ref const ubyte[12] nonce, const(ubyte)[] aad, const(ubyte)[] plain, ubyte[] output)
in { assert(plain.length <= 1025 && aad.length <= 64 && output.length >= plain.length + 16); }
out(ok) { assert(output.length >= plain.length + 16); }
do { return d_encrypt(key.ptr, nonce.ptr, aad.ptr, cast(int)aad.length, plain.ptr, cast(int)plain.length, output.ptr) == 0; }

bool decrypt(ref const Key key, ref const ubyte[12] nonce, const(ubyte)[] aad, const(ubyte)[] cipher, ubyte[] output)
in { assert(cipher.length >= 16 && cipher.length <= 1041 && aad.length <= 64 && output.length >= cipher.length - 16); }
out(ok) { assert(output.length >= cipher.length - 16); }
do { return d_decrypt(key.ptr, nonce.ptr, aad.ptr, cast(int)aad.length, cipher.ptr, cast(int)cipher.length, output.ptr) == 0; }
