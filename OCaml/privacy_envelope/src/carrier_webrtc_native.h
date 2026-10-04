#ifndef SHADOW6_CARRIER_WEBRTC_NATIVE_H
#define SHADOW6_CARRIER_WEBRTC_NATIVE_H
#include <stddef.h>
#include <stdint.h>
typedef struct s6_rtc s6_rtc;
typedef struct { unsigned id, ordered, policy, budget; } s6_rtc_channel;
typedef struct { unsigned kind, channel, text; size_t size; } s6_rtc_event;
/* 0 unavailable, 1 pinned C API backend available. No library path input. */
int s6_rtc_available(void);
/* Owns a new ICE/DTLS/SCTP peer and negotiated channels. No STUN/TURN servers
   are implicitly enabled. All IDs/policies and byte/message budgets are fixed
   before SDP negotiation. Caller releases it with s6_rtc_free. */
s6_rtc *s6_rtc_create(const char *bind, const s6_rtc_channel *, unsigned count,
                    size_t maximum, unsigned depth, size_t queue_bytes);
/* Nontrickle standard SDP; 0 pending gathering, >0 bytes including NUL, -1
   terminal failure. SDP includes DTLS fingerprints; independent envelope PSK
   admission must still follow before any application forwarding. */
int s6_rtc_local(s6_rtc *, int offer, char *, size_t capacity);
int s6_rtc_remote(s6_rtc *, int offer, const char *, size_t size);
int s6_rtc_open(s6_rtc *);
/* 1 accepted, 0 whole-message backpressure, -1 terminal failure. */
int s6_rtc_send(s6_rtc *, unsigned channel, int text, const void *, size_t);
int s6_rtc_receive(s6_rtc *, void *, size_t capacity, s6_rtc_event *);
int s6_rtc_close_channel(s6_rtc *, unsigned channel);
int s6_rtc_buffered(s6_rtc *);
int s6_rtc_wait(s6_rtc *, unsigned timeout_ms);
void s6_rtc_free(s6_rtc *);
#endif
