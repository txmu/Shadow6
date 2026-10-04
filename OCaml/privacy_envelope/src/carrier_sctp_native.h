#ifndef SHADOW6_CARRIER_SCTP_NATIVE_H
#define SHADOW6_CARRIER_SCTP_NATIVE_H
#include <stddef.h>
#include <stdint.h>
typedef struct s6_sctp s6_sctp;
/* All descriptors remain caller-owned. Linux one-to-one SCTP only. */
int s6_sctp_available(void);
int s6_sctp_prepare(int fd, unsigned streams);
s6_sctp *s6_sctp_attach(int fd, size_t max_message);
unsigned s6_sctp_stream_limit(s6_sctp *);
int s6_sctp_partial_reliability(s6_sctp *);
void s6_sctp_free(s6_sctp *);
/* 1 accepted, 0 retry/backpressure, -1 failed. Zero-size SCTP sends are invalid. */
int s6_sctp_send(s6_sctp *, const void *, size_t, unsigned stream,
                 int ordered, uint32_t ppid, uint32_t context, int policy, unsigned budget);
/* 0 no event; 1 message; 2 reset; 3 shutdown; 4 closed; 5 restart; 6 abandoned.
   A reset is not a channel close. Failed reset flags are retained. */
typedef struct {
    unsigned kind, stream, ordered;
    uint32_t ppid, context;
    size_t size;
    unsigned reset_flags, reset_count;
    uint16_t reset_streams[64];
} s6_sctp_event;
int s6_sctp_receive(s6_sctp *, void *, size_t, s6_sctp_event *);
int s6_sctp_watch_sender(s6_sctp *);
int s6_sctp_reset(s6_sctp *, unsigned stream, int incoming, int outgoing);
#endif
