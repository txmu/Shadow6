#include "carrier_tls_native.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <string.h>

#define CONTEXT(v) (*((s6_tls_context **)Data_custom_val(v)))
#define SESSION(v) (*((s6_tls **)Data_custom_val(v)))
static void context_finalize(value v) { s6_tls_context_free(CONTEXT(v)); CONTEXT(v) = NULL; }
static void session_finalize(value v) { s6_tls_free(SESSION(v)); SESSION(v) = NULL; }
static struct custom_operations context_ops = {
    "shadow6.tls.context.v1", context_finalize, custom_compare_default,
    custom_hash_default, custom_serialize_default, custom_deserialize_default,
    custom_compare_ext_default, custom_fixed_length_default
};
static struct custom_operations session_ops = {
    "shadow6.tls.session.v1", session_finalize, custom_compare_default,
    custom_hash_default, custom_serialize_default, custom_deserialize_default,
    custom_compare_ext_default, custom_fixed_length_default
};
CAMLprim value s6epe_tls_context(value cert, value key, value ca) {
    CAMLparam3(cert,key,ca); CAMLlocal1(v);
    v = caml_alloc_custom(&context_ops, sizeof(s6_tls_context *), 0, 1);
    CONTEXT(v) = s6_tls_context_create(String_val(cert), caml_string_length(cert),
        String_val(key), caml_string_length(key), String_val(ca), caml_string_length(ca));
    if (!CONTEXT(v)) caml_failwith("TLS carrier material rejected");
    CAMLreturn(v);
}
CAMLprim value s6epe_tls_create(value context, value descriptor, value server, value peer) {
    CAMLparam4(context,descriptor,server,peer); CAMLlocal1(v);
    if (caml_string_length(peer) > 253 || caml_string_length(peer) != strlen(String_val(peer)))
        caml_invalid_argument("TLS peer name");
    v = caml_alloc_custom(&session_ops, sizeof(s6_tls *), 0, 1);
    SESSION(v) = s6_tls_create(CONTEXT(context), Int_val(descriptor), Bool_val(server), String_val(peer));
    if (!SESSION(v)) caml_failwith("TLS carrier creation failed");
    CAMLreturn(v);
}
CAMLprim value s6epe_tls_handshake(value v) { return Val_int(s6_tls_handshake(SESSION(v))); }
static void bounds(value data, value offset, value length) {
    intnat off = Long_val(offset), len = Long_val(length);
    if (off < 0 || len < 1 || len > 131072 || (uintnat)off > caml_string_length(data) ||
        (uintnat)len > caml_string_length(data) - (uintnat)off) caml_invalid_argument("TLS I/O bounds");
}
CAMLprim value s6epe_tls_read(value v, value data, value offset, value length) {
    bounds(data,offset,length);
    return Val_int(s6_tls_read(SESSION(v), Bytes_val(data) + Long_val(offset), Long_val(length)));
}
CAMLprim value s6epe_tls_write(value v, value data, value offset, value length) {
    bounds(data,offset,length);
    return Val_int(s6_tls_write(SESSION(v), Bytes_val(data) + Long_val(offset), Long_val(length)));
}
CAMLprim value s6epe_tls_pending(value v) { return Val_int(s6_tls_pending(SESSION(v))); }
CAMLprim value s6epe_tls_has_pending(value v) { return Val_bool(s6_tls_has_pending(SESSION(v))); }
CAMLprim value s6epe_tls_shutdown(value v) { return Val_int(s6_tls_shutdown_send(SESSION(v))); }
CAMLprim value s6epe_tls_close(value v) { session_finalize(v); return Val_unit; }
