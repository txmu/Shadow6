/* No crypto implementation here: bounded OCaml bindings to libsodium. */
#include <sodium.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#define LIMIT 131072
#define DATA(v) ((unsigned char *)Bytes_val(v))
static void size(value v, size_t n) {
    if (caml_string_length(v) != n) caml_invalid_argument("cryptographic material size");
}
static void bounded(value v) {
    if (caml_string_length(v) > LIMIT) caml_invalid_argument("cryptographic record bound");
}
static void init(void) {
    if (sodium_init() < 0) caml_failwith("libsodium initialization");
}
CAMLprim value s6epe_keypair(value unit) {
    CAMLparam1(unit); CAMLlocal3(pk, sk, pair);
    init(); pk = caml_alloc_string(32); sk = caml_alloc_string(32);
    crypto_kx_keypair(DATA(pk), DATA(sk));
    pair = caml_alloc_tuple(2); Store_field(pair,0,pk); Store_field(pair,1,sk);
    CAMLreturn(pair);
}
CAMLprim value s6epe_session_keys(value server, value pk, value sk, value peer) {
    CAMLparam4(server,pk,sk,peer); CAMLlocal3(rx,tx,pair);
    size(pk,32); size(sk,32); size(peer,32); init();
    rx = caml_alloc_string(32); tx = caml_alloc_string(32);
    int rc = Bool_val(server) ? crypto_kx_server_session_keys(DATA(rx),DATA(tx),DATA(pk),DATA(sk),DATA(peer))
                             : crypto_kx_client_session_keys(DATA(rx),DATA(tx),DATA(pk),DATA(sk),DATA(peer));
    if (rc != 0) { sodium_memzero(DATA(rx),32); sodium_memzero(DATA(tx),32); caml_failwith("invalid peer key"); }
    pair = caml_alloc_tuple(2); Store_field(pair,0,rx); Store_field(pair,1,tx);
    CAMLreturn(pair);
}
CAMLprim value s6epe_seal(value key, value nonce, value ad, value message) {
    CAMLparam4(key,nonce,ad,message); CAMLlocal1(out);
    size(key,32); size(nonce,24); bounded(ad); bounded(message); init();
    out = caml_alloc_string(caml_string_length(message)+16);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(DATA(out),NULL,DATA(message),caml_string_length(message),
            DATA(ad),caml_string_length(ad),NULL,DATA(nonce),DATA(key)) != 0) caml_failwith("encryption failed");
    CAMLreturn(out);
}
CAMLprim value s6epe_open(value key, value nonce, value ad, value cipher) {
    CAMLparam4(key,nonce,ad,cipher); CAMLlocal1(out);
    size(key,32); size(nonce,24); bounded(ad); bounded(cipher); init();
    if (caml_string_length(cipher)<16) caml_invalid_argument("truncated capsule");
    out = caml_alloc_string(caml_string_length(cipher)-16);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(DATA(out),NULL,NULL,DATA(cipher),caml_string_length(cipher),
            DATA(ad),caml_string_length(ad),DATA(nonce),DATA(key)) != 0) {
        sodium_memzero(DATA(out),caml_string_length(out)); caml_failwith("capsule authentication failed");
    }
    CAMLreturn(out);
}
typedef crypto_secretstream_xchacha20poly1305_state stream_state;
CAMLprim value s6epe_init_push(value key) {
    CAMLparam1(key); CAMLlocal3(state,header,pair);
    size(key,32); init();
    state = caml_alloc_string(sizeof(stream_state)); header = caml_alloc_string(24);
    stream_state local;
    if (crypto_secretstream_xchacha20poly1305_init_push(&local,DATA(header),DATA(key)) != 0) caml_failwith("stream initialization");
    memcpy(DATA(state),&local,sizeof(local)); sodium_memzero(&local,sizeof(local));
    pair = caml_alloc_tuple(2); Store_field(pair,0,state); Store_field(pair,1,header);
    CAMLreturn(pair);
}
CAMLprim value s6epe_init_pull(value key, value header) {
    CAMLparam2(key,header); CAMLlocal1(state);
    size(key,32); size(header,24); init();
    stream_state local;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&local,DATA(header),DATA(key)) != 0) caml_failwith("stream initialization");
    state = caml_alloc_string(sizeof(local)); memcpy(DATA(state),&local,sizeof(local)); sodium_memzero(&local,sizeof(local));
    CAMLreturn(state);
}
CAMLprim value s6epe_push(value state, value ad, value message, value tag) {
    CAMLparam4(state,ad,message,tag); CAMLlocal1(out);
    size(state,sizeof(stream_state)); bounded(ad); bounded(message); init();
    int t = Int_val(tag);
    if (t != 0 && t != 2 && t != 3) caml_invalid_argument("stream record tag");
    out = caml_alloc_string(caml_string_length(message)+17);
    stream_state local; memcpy(&local,DATA(state),sizeof(local));
    int rc = crypto_secretstream_xchacha20poly1305_push(&local,DATA(out),NULL,DATA(message),caml_string_length(message),DATA(ad),caml_string_length(ad),(unsigned char)t);
    if (t == 3 || rc != 0) sodium_memzero(&local,sizeof(local));
    memcpy(DATA(state),&local,sizeof(local)); sodium_memzero(&local,sizeof(local));
    if (rc != 0) caml_failwith("stream encryption failed");
    CAMLreturn(out);
}
CAMLprim value s6epe_pull(value state, value ad, value cipher) {
    CAMLparam3(state,ad,cipher); CAMLlocal2(out,pair);
    size(state,sizeof(stream_state)); bounded(ad); bounded(cipher); init();
    if (caml_string_length(cipher)<17) caml_invalid_argument("truncated record");
    out = caml_alloc_string(caml_string_length(cipher)-17);
    stream_state local; unsigned char tag;
    memcpy(&local,DATA(state),sizeof(local));
    int rc = crypto_secretstream_xchacha20poly1305_pull(&local,DATA(out),NULL,&tag,DATA(cipher),caml_string_length(cipher),DATA(ad),caml_string_length(ad));
    if (rc != 0 || tag == 3) sodium_memzero(&local,sizeof(local));
    memcpy(DATA(state),&local,sizeof(local)); sodium_memzero(&local,sizeof(local));
    if (rc != 0 || (tag != 0 && tag != 2 && tag != 3)) {
        sodium_memzero(DATA(out),caml_string_length(out)); caml_failwith("stream authentication failed");
    }
    pair = caml_alloc_tuple(2); Store_field(pair,0,out); Store_field(pair,1,Val_int(tag));
    CAMLreturn(pair);
}
