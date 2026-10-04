#ifndef S6EPE_TLS_NATIVE_H
#define S6EPE_TLS_NATIVE_H
#include <stddef.h>
typedef struct s6_tls_context s6_tls_context;
typedef struct s6_tls s6_tls;
s6_tls_context *s6_tls_context_create(const char *, size_t, const char *, size_t, const char *, size_t);
void s6_tls_context_free(s6_tls_context *);
s6_tls *s6_tls_create(s6_tls_context *, int, int, const char *);
void s6_tls_free(s6_tls *);
/* 1 complete, -1 want-read, -2 want-write, -3 failure. */
int s6_tls_handshake(s6_tls *);
/* Positive byte count, 0 authenticated EOF, -1/-2 retry, -3 failure. */
int s6_tls_read(s6_tls *, void *, size_t);
int s6_tls_write(s6_tls *, const void *, size_t);
int s6_tls_pending(s6_tls *);
int s6_tls_has_pending(s6_tls *);
/* 1 own close_notify sent (receiving remains valid), -1/-2 retry, -3 failure. */
int s6_tls_shutdown_send(s6_tls *);
#endif
