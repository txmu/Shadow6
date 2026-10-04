#include "carrier_webrtc_native.h"
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/threads.h>
#include <string.h>
#define HANDLE(v) (*((s6_rtc **)Data_custom_val(v)))
static void finalize(value v){s6_rtc_free(HANDLE(v));HANDLE(v)=NULL;}
static struct custom_operations ops={"shadow6.webrtc.carrier.v1",finalize,custom_compare_default,
 custom_hash_default,custom_serialize_default,custom_deserialize_default,
 custom_compare_ext_default,custom_fixed_length_default};
CAMLprim value s6epe_rtc_available(value unit){(void)unit;return Val_bool(s6_rtc_available());}
CAMLprim value s6epe_rtc_create(value bind,value channels,value limits){
 CAMLparam3(bind,channels,limits);CAMLlocal1(v);
 mlsize_t count=Wosize_val(channels);s6_rtc_channel native[64];
 intnat maximum=Long_val(Field(limits,0)),depth=Long_val(Field(limits,1)),budget=Long_val(Field(limits,2));
 if(count<1 || count>64 || maximum<1 || maximum>73728 || depth<1 || depth>128 || budget<maximum || budget>16777216)
  caml_invalid_argument("WebRTC admission budget");
 for(mlsize_t i=0;i<count;i++){
  value c=Field(channels,i);intnat id=Long_val(Field(c,0)),kind=Long_val(Field(c,2)),amount=Long_val(Field(c,3));
  if(id<0 || id>63 || kind<0 || kind>2 || amount<0 || amount>65535)caml_invalid_argument("WebRTC channel metadata");
  native[i]=(s6_rtc_channel){(unsigned)id,(unsigned)Bool_val(Field(c,1)),(unsigned)kind,(unsigned)amount};
 }
 if(caml_string_length(bind)>45 || memchr(String_val(bind),0,caml_string_length(bind)))caml_invalid_argument("WebRTC bind address");
 v=caml_alloc_custom(&ops,sizeof(s6_rtc *),(uintnat)budget+4096,8388608);
 HANDLE(v)=s6_rtc_create(String_val(bind),native,(unsigned)count,(size_t)maximum,(unsigned)depth,(size_t)budget);
 if(!HANDLE(v))caml_failwith("WebRTC bounded native backend unavailable");
 CAMLreturn(v);
}
CAMLprim value s6epe_rtc_local(value handle,value offer){
 CAMLparam2(handle,offer);CAMLlocal2(result,sdp);char buffer[32769];
 int size=s6_rtc_local(HANDLE(handle),Bool_val(offer),buffer,sizeof buffer);
 if(size<0)caml_failwith("WebRTC local SDP failed");
 if(!size)CAMLreturn(Val_int(0));
 sdp=caml_alloc_initialized_string((mlsize_t)size-1,buffer);
 result=caml_alloc(1,0);Store_field(result,0,sdp);CAMLreturn(result);
}
CAMLprim value s6epe_rtc_remote(value handle,value offer,value sdp){
 if(s6_rtc_remote(HANDLE(handle),Bool_val(offer),String_val(sdp),caml_string_length(sdp)))caml_failwith("WebRTC remote SDP rejected");
 return Val_unit;
}
CAMLprim value s6epe_rtc_open(value handle){return Val_int(s6_rtc_open(HANDLE(handle)));}
CAMLprim value s6epe_rtc_send(value handle,value channel,value text,value data){
 intnat id=Long_val(channel);if(id<0 || id>63)caml_invalid_argument("WebRTC channel ID");
 return Val_int(s6_rtc_send(HANDLE(handle),(unsigned)id,Bool_val(text),String_val(data),caml_string_length(data)));
}
CAMLprim value s6epe_rtc_receive(value handle,value maximum){
 CAMLparam2(handle,maximum);CAMLlocal4(payload,result,event,exact);
 intnat limit=Long_val(maximum);if(limit<1 || limit>73728)caml_invalid_argument("WebRTC receive budget");
 payload=caml_alloc_string((mlsize_t)limit);s6_rtc_event native;
 int status=s6_rtc_receive(HANDLE(handle),Bytes_val(payload),(size_t)limit,&native);
 if(status<0)caml_failwith("WebRTC callback queue/lifecycle failed");
 if(!status)CAMLreturn(Val_int(0));
 exact=caml_alloc_string(native.size);if(native.size)memcpy(Bytes_val(exact),Bytes_val(payload),native.size);
 event=caml_alloc_tuple(4);Store_field(event,0,Val_int(native.kind));Store_field(event,1,Val_int(native.channel));
 Store_field(event,2,Val_bool(native.text));Store_field(event,3,exact);
 result=caml_alloc(1,0);Store_field(result,0,event);CAMLreturn(result);
}
CAMLprim value s6epe_rtc_close_channel(value handle,value channel){
 intnat id=Long_val(channel);if(id<0 || id>63)caml_invalid_argument("WebRTC channel ID");
 return Val_int(s6_rtc_close_channel(HANDLE(handle),(unsigned)id));
}
CAMLprim value s6epe_rtc_buffered(value handle){return Val_int(s6_rtc_buffered(HANDLE(handle)));}
CAMLprim value s6epe_rtc_wait(value handle,value timeout){
 CAMLparam2(handle,timeout);intnat ms=Long_val(timeout);
 if(ms<0 || ms>1000)caml_invalid_argument("WebRTC wait budget");
 s6_rtc *native=HANDLE(handle);caml_enter_blocking_section();
 int result=s6_rtc_wait(native,(unsigned)ms);caml_leave_blocking_section();
 if(result)caml_failwith("WebRTC wait failed");
 CAMLreturn(Val_unit);
}
CAMLprim value s6epe_rtc_close(value handle){finalize(handle);return Val_unit;}
