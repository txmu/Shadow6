#include "carrier_sctp_native.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <string.h>
#define HANDLE(v) (*((s6_sctp **)Data_custom_val(v)))
static void finalize(value v) { s6_sctp_free(HANDLE(v));HANDLE(v)=NULL; }
static struct custom_operations ops={"shadow6.sctp.carrier.v1",finalize,custom_compare_default,
    custom_hash_default,custom_serialize_default,custom_deserialize_default,
    custom_compare_ext_default,custom_fixed_length_default};
CAMLprim value s6epe_sctp_available(value unit) { (void)unit;return Val_bool(s6_sctp_available()); }
CAMLprim value s6epe_sctp_prepare(value fd,value streams) {
    if (Long_val(streams)<1 || Long_val(streams)>64 || s6_sctp_prepare(Int_val(fd),(unsigned)Long_val(streams)))
        caml_failwith("SCTP carrier setup unavailable");
    return Val_unit;
}
CAMLprim value s6epe_sctp_attach(value fd,value maximum) {
    CAMLparam2(fd,maximum);CAMLlocal1(v);
    if (Long_val(maximum)<1 || Long_val(maximum)>131072) caml_invalid_argument("SCTP message budget");
    v=caml_alloc_custom(&ops,sizeof(s6_sctp *),(uintnat)Long_val(maximum)*2+512,8388608);
    HANDLE(v)=s6_sctp_attach(Int_val(fd),(size_t)Long_val(maximum));
    if (!HANDLE(v)) caml_failwith("SCTP established bounded association required");
    CAMLreturn(v);
}
CAMLprim value s6epe_sctp_stream_limit(value handle) {return Val_int(s6_sctp_stream_limit(HANDLE(handle)));}
CAMLprim value s6epe_sctp_pr(value handle) {return Val_bool(s6_sctp_partial_reliability(HANDLE(handle)));}
CAMLprim value s6epe_sctp_send(value handle,value data,value metadata) {
    intnat stream=Long_val(Field(metadata,0));int64_t ppid=Int64_val(Field(metadata,2));
    intnat policy=Long_val(Field(metadata,3)),budget=Long_val(Field(metadata,4));
    int64_t context=Int64_val(Field(metadata,5));
    if (stream<0 || stream>65535 || ppid<0 || (uint64_t)ppid>UINT32_MAX || policy<0 || policy>2 || budget<0 || budget>65535 || context<0 || (uint64_t)context>UINT32_MAX)
        caml_invalid_argument("SCTP send metadata");
    return Val_int(s6_sctp_send(HANDLE(handle),String_val(data),caml_string_length(data),
        (unsigned)stream,Bool_val(Field(metadata,1)),(uint32_t)ppid,(uint32_t)context,(int)policy,(unsigned)budget));
}
CAMLprim value s6epe_sctp_receive(value handle,value maximum) {
    CAMLparam2(handle,maximum);CAMLlocal5(option,event,payload,streams,ppid);CAMLlocal1(context);
    if (Long_val(maximum)<1 || Long_val(maximum)>131072) caml_invalid_argument("SCTP receive budget");
    payload=caml_alloc_string((mlsize_t)Long_val(maximum));s6_sctp_event native;
    int result=s6_sctp_receive(HANDLE(handle),Bytes_val(payload),(size_t)Long_val(maximum),&native);
    if (result<0) caml_failwith("SCTP carrier receive failed");
    if (!result) CAMLreturn(Val_int(0));
    /* Shrink by copying: no OCaml pointer survives an allocation/native call. */
    value exact=caml_alloc_string(native.size);
    if (native.size) memcpy(Bytes_val(exact),Bytes_val(payload),native.size);
    payload=exact;
    streams=caml_alloc(native.reset_count,0);
    for (unsigned i=0;i<native.reset_count;i++) Store_field(streams,i,Val_int(native.reset_streams[i]));
    ppid=caml_copy_int64(native.ppid);context=caml_copy_int64(native.context);
    event=caml_alloc_tuple(8);
    Store_field(event,0,Val_int(native.kind));Store_field(event,1,Val_int(native.stream));
    Store_field(event,2,Val_bool(native.ordered));
    Store_field(event,3,ppid);Store_field(event,4,context);Store_field(event,5,Val_int(native.reset_flags));
    Store_field(event,6,streams);Store_field(event,7,payload);
    option=caml_alloc(1,0);Store_field(option,0,event);CAMLreturn(option);
}
CAMLprim value s6epe_sctp_watch_sender(value handle) {
    if (s6_sctp_watch_sender(HANDLE(handle))) caml_failwith("SCTP sender completion unavailable");
    return Val_unit;
}
CAMLprim value s6epe_sctp_reset(value handle,value stream,value incoming,value outgoing) {
    if (Long_val(stream)<0 || Long_val(stream)>65535) caml_invalid_argument("SCTP reset stream");
    return Val_int(s6_sctp_reset(HANDLE(handle),(unsigned)Long_val(stream),Bool_val(incoming),Bool_val(outgoing)));
}
CAMLprim value s6epe_sctp_close(value v) {finalize(v);return Val_unit;}
