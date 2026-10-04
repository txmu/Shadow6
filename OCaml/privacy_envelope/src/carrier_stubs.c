/* Platform socket type inspection; no protocol parsing or cryptography. */
#include <sys/socket.h>
#include <caml/mlvalues.h>

CAMLprim value s6epe_is_stream(value descriptor) {
    int kind = 0;
    socklen_t length = sizeof kind;
    int result = getsockopt(Int_val(descriptor), SOL_SOCKET, SO_TYPE, &kind, &length);
    return Val_bool(result == 0 && length == sizeof kind && kind == SOCK_STREAM);
}
