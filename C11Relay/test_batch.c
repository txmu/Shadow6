/* Deterministic partial-send/backpressure checks for the actual batch helper. */
#define sendmmsg test_sendmmsg
#define main relay_program_main
#include "c11relay.c"
#undef main
#undef sendmmsg
#include <assert.h>

#ifdef __linux__
static int calls, mode;
int test_sendmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags) {
    (void)fd;
    assert(flags == (MSG_DONTWAIT | MSG_NOSIGNAL));
    ++calls;
    if (mode == 1) { errno = EINTR; return -1; }
    if (mode == 0 && calls == 2) {
        /* The first two datagrams already succeeded and must not be resent. */
        assert(count == 2U);
        assert(*(uint8_t *)messages[0].msg_hdr.msg_iov[0].iov_base == 2U);
        errno = EAGAIN;
        return -1;
    }
    unsigned int completed = mode == 0 ? 2U : count;
    for (unsigned int i = 0; i < completed; ++i) {
        messages[i].msg_len = (unsigned int)messages[i].msg_hdr.msg_iov[0].iov_len;
    }
    return (int)completed;
}
#endif

int main(void) {
#ifdef __linux__
    RelayBatch *batch = calloc(1, sizeof(*batch));
    assert(batch != NULL);
    RelayPeer peer = {.client_address.ss_family = AF_INET};
    RelayMetrics metrics = {0};
    for (unsigned int i = 0; i < 4U; ++i) {
        batch->messages[i].msg_len = 1U;
        batch->payloads[i][0] = (uint8_t)i;
    }
    send_reply_batch(-1, batch, 4, &peer, &metrics, 100U);
    assert(calls == 2 && metrics.packets_out == 2U && metrics.bytes_out == 2U && metrics.dropped == 2U);
    mode = 1; calls = 0; metrics = (RelayMetrics){0};
    send_reply_batch(-1, batch, 4, &peer, &metrics, 100U);
    assert(calls == HIGH_SPEED_BATCH && metrics.packets_out == 0U && metrics.dropped == 4U);
    mode = 2; calls = 0; metrics = (RelayMetrics){0};
    batch->messages[0].msg_len = MAX_DATAGRAM_BYTES + 1U;
    batch->messages[1].msg_len = 65508U; /* Exceeds IPv4 UDP limit. */
    batch->messages[2].msg_len = 0U;     /* Empty UDP datagram is valid. */
    send_reply_batch(-1, batch, 4, &peer, &metrics, 200U);
    assert(calls == 1 && metrics.packets_out == 2U && metrics.bytes_out == 1U && metrics.dropped == 2U);
    assert(peer.last_seen_ms == 200U);
    free(batch);
#endif
    puts("[PASS] bounded batch reply accounting");
    return 0;
}
