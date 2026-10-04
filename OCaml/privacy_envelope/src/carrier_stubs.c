#define _GNU_SOURCE
/* Platform socket type inspection; no protocol parsing or cryptography. */
#include <sys/socket.h>
#include <caml/mlvalues.h>

CAMLprim value s6epe_is_stream(value descriptor) {
    int kind = 0;
    socklen_t length = sizeof kind;
    int result = getsockopt(Int_val(descriptor), SOL_SOCKET, SO_TYPE, &kind, &length);
    if (result || length != sizeof kind || kind != SOCK_STREAM) return Val_false;
#ifdef __linux__
    /* A one-to-one SCTP descriptor is SOCK_STREAM but retains message semantics. */
    int protocol=0;length=sizeof protocol;
    if (getsockopt(Int_val(descriptor),SOL_SOCKET,SO_PROTOCOL,&protocol,&length) || protocol==132) return Val_false;
#endif
    return Val_true;
}
