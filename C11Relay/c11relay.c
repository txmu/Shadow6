#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_DATAGRAM_BYTES 65535U
#define MAX_EVENTS 64
#define MAX_BATCH_DATAGRAMS 64
#define DEFAULT_MAX_PEERS 1024U
#define HARD_MAX_PEERS 4096U

typedef enum {
    MODE_NORMAL = 0,
    MODE_DATA_SAVING = 1,
    MODE_HIGH_SPEED = 2,
} RelayMode;

typedef enum {
    SCENARIO_BROKER = 0,
    SCENARIO_AGENT = 1,
} RelayScenario;

typedef struct {
    bool active;
    int upstream_fd;
    struct sockaddr_storage client_address;
    socklen_t client_length;
    uint64_t last_seen_ms;
    double tokens;
    uint64_t token_timestamp_ms;
    uint32_t generation;
} RelayPeer;

typedef struct {
    const char *bind_host;
    uint16_t listen_port;
    struct sockaddr_storage target_address;
    socklen_t target_length;
    RelayMode mode;
    RelayScenario scenario;
    size_t max_peers;
    uint64_t idle_timeout_ms;
    double rate_per_second;
    double burst;
    bool framing_back;
} RelayConfig;

typedef struct {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t dropped;
} RelayMetrics;

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void secure_zero(void *memory, size_t length) {
    volatile unsigned char *cursor = memory;
    while (length-- > 0U) {
        *cursor++ = 0;
    }
}

static bool parse_u16(const char *value, uint16_t *output) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 1L || parsed > 65535L) {
        return false;
    }
    *output = (uint16_t)parsed;
    return true;
}

static bool parse_size(const char *value, size_t minimum, size_t maximum, size_t *output) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < minimum || parsed > maximum) {
        return false;
    }
    *output = (size_t)parsed;
    return true;
}

static bool parse_positive_double(const char *value, double maximum, double *output) {
    char *end = NULL;
    errno = 0;
    double parsed = strtod(value, &end);
    if (errno != 0 || end == value || *end != '\0' || !(parsed > 0.0) || parsed > maximum) {
        return false;
    }
    *output = parsed;
    return true;
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    int descriptor_flags = fcntl(descriptor, F_GETFD, 0);
    if (descriptor_flags < 0 || fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
        return -1;
    }
    return 0;
}

static bool sockaddr_equal(
    const struct sockaddr_storage *left,
    socklen_t left_length,
    const struct sockaddr_storage *right,
    socklen_t right_length
) {
    if (left_length < sizeof(sa_family_t) || right_length < sizeof(sa_family_t)) {
        return false;
    }
    if (left->ss_family != right->ss_family) {
        return false;
    }
    if (left->ss_family == AF_INET) {
        if (left_length < sizeof(struct sockaddr_in) || right_length < sizeof(struct sockaddr_in)) { return false; }
        const struct sockaddr_in *first = (const struct sockaddr_in *)left;
        const struct sockaddr_in *second = (const struct sockaddr_in *)right;
        return first->sin_port == second->sin_port && first->sin_addr.s_addr == second->sin_addr.s_addr;
    }
    if (left->ss_family == AF_INET6) {
        if (left_length < sizeof(struct sockaddr_in6) || right_length < sizeof(struct sockaddr_in6)) { return false; }
        const struct sockaddr_in6 *first = (const struct sockaddr_in6 *)left;
        const struct sockaddr_in6 *second = (const struct sockaddr_in6 *)right;
        return first->sin6_port == second->sin6_port && first->sin6_scope_id == second->sin6_scope_id &&
               memcmp(&first->sin6_addr, &second->sin6_addr, sizeof(first->sin6_addr)) == 0;
    }
    return false;
}

/* Data-saving mode uses a one-byte frame marker: 0 for raw and 1 for RLE. */
static bool rle_encode(const uint8_t *input, size_t input_length, uint8_t *output, size_t capacity, size_t *output_length) {
    if (input_length >= capacity) {
        return false;
    }
    size_t cursor = 1U;
    if (input_length == 0U) { output[0] = 0U; *output_length = 1U; return true; }
    output[0] = 1U;
    for (size_t index = 0U; index < input_length; ++index) {
        uint8_t count = 1U;
        while (index + 1U < input_length && input[index] == input[index + 1U] && count < UINT8_MAX) {
            ++count;
            ++index;
        }
        if (cursor + 2U > input_length + 1U || cursor + 2U > capacity) {
            output[0] = 0U;
            memcpy(output + 1U, input, input_length);
            *output_length = input_length + 1U;
            return true;
        }
        output[cursor++] = count;
        output[cursor++] = input[index];
    }
    *output_length = cursor;
    return true;
}

static bool rle_decode(const uint8_t *input, size_t input_length, uint8_t *output, size_t capacity, size_t *output_length) {
    if (input_length < 1U) {
        return false;
    }
    if (input[0] == 0U) {
        if (input_length - 1U > capacity) {
            return false;
        }
        memcpy(output, input + 1U, input_length - 1U);
        *output_length = input_length - 1U;
        return true;
    }
    if (input[0] != 1U || (input_length - 1U) % 2U != 0U) {
        return false;
    }
    size_t cursor = 0U;
    for (size_t index = 1U; index < input_length; index += 2U) {
        size_t count = input[index];
        if (count == 0U || count > capacity - cursor) {
            return false;
        }
        memset(output + cursor, input[index + 1U], count);
        cursor += count;
    }
    *output_length = cursor;
    return cursor > 0U;
}

static bool rate_allow(RelayPeer *peer, uint64_t now, const RelayConfig *config) {
    if (config->rate_per_second <= 0.0) {
        return true;
    }
    if (peer->token_timestamp_ms == 0U) {
        peer->token_timestamp_ms = now;
        peer->tokens = config->burst;
    }
    uint64_t elapsed = now >= peer->token_timestamp_ms ? now - peer->token_timestamp_ms : 0U;
    peer->tokens += ((double)elapsed / 1000.0) * config->rate_per_second;
    if (peer->tokens > config->burst) {
        peer->tokens = config->burst;
    }
    peer->token_timestamp_ms = now;
    if (peer->tokens < 1.0) {
        return false;
    }
    peer->tokens -= 1.0;
    return true;
}

static void close_peer(int epoll_fd, RelayPeer *peer) {
    if (!peer->active) {
        return;
    }
    (void)epoll_ctl(epoll_fd, EPOLL_CTL_DEL, peer->upstream_fd, NULL);
    (void)close(peer->upstream_fd);
    uint32_t generation = peer->generation;
    secure_zero(peer, sizeof(*peer));
    peer->generation = generation;
    peer->upstream_fd = -1;
}

static ssize_t find_peer(
    RelayPeer *peers,
    size_t peer_count,
    const struct sockaddr_storage *client,
    socklen_t client_length
) {
    for (size_t index = 0U; index < peer_count; ++index) {
        if (peers[index].active && sockaddr_equal(&peers[index].client_address, peers[index].client_length, client, client_length)) {
            return (ssize_t)index;
        }
    }
    return -1;
}

static ssize_t create_peer(
    int epoll_fd,
    RelayPeer *peers,
    size_t peer_count,
    const RelayConfig *config,
    const struct sockaddr_storage *client,
    socklen_t client_length,
    uint64_t now
) {
    size_t index = peer_count;
    for (size_t candidate = 0U; candidate < peer_count; ++candidate) {
        if (!peers[candidate].active) {
            index = candidate;
            break;
        }
    }
    if (index == peer_count) {
        return -1;
    }
    int descriptor = socket(config->target_address.ss_family, SOCK_DGRAM, 0);
    if (descriptor < 0 || set_nonblocking(descriptor) != 0 ||
        connect(descriptor, (const struct sockaddr *)&config->target_address, config->target_length) != 0) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
    uint32_t generation = peers[index].generation + 1U;
    if (generation == 0U) { generation = 1U; }
    struct epoll_event event = {.events = EPOLLIN};
    event.data.u64 = ((uint64_t)generation << 32U) | ((uint32_t)index + 1U);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, descriptor, &event) != 0) {
        (void)close(descriptor);
        return -1;
    }
    peers[index].active = true;
    peers[index].generation = generation;
    peers[index].upstream_fd = descriptor;
    peers[index].client_address = *client;
    peers[index].client_length = client_length;
    peers[index].last_seen_ms = now;
    peers[index].tokens = config->burst;
    peers[index].token_timestamp_ms = now;
    return (ssize_t)index;
}

static int resolve_address(
    const char *host,
    const char *service,
    bool passive,
    struct sockaddr_storage *result,
    socklen_t *result_length
) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = passive ? AI_PASSIVE : 0;
    struct addrinfo *addresses = NULL;
    int status = getaddrinfo(host, service, &hints, &addresses);
    if (status != 0 || addresses == NULL || addresses->ai_addrlen > sizeof(*result)) {
        if (addresses != NULL) {
            freeaddrinfo(addresses);
        }
        return -1;
    }
    memcpy(result, addresses->ai_addr, addresses->ai_addrlen);
    *result_length = (socklen_t)addresses->ai_addrlen;
    freeaddrinfo(addresses);
    return 0;
}

static int create_listener(const RelayConfig *config) {
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", config->listen_port);
    struct sockaddr_storage address;
    socklen_t address_length = 0;
    if (resolve_address(config->bind_host, service, true, &address, &address_length) != 0) {
        return -1;
    }
    int descriptor = socket(address.ss_family, SOCK_DGRAM, 0);
    if (descriptor < 0) {
        return -1;
    }
    /* A relay listener must have an exclusive bind. Make IPv6-only behavior
       explicit instead of inheriting the host's dual-stack socket default. */
    if (address.ss_family == AF_INET6) {
        int only = 1;
        if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only)) != 0) {
            (void)close(descriptor);
            return -1;
        }
    }
    if (set_nonblocking(descriptor) != 0 || bind(descriptor, (struct sockaddr *)&address, address_length) != 0) {
        (void)close(descriptor);
        return -1;
    }
    return descriptor;
}

static void cleanup_idle_peers(int epoll_fd, RelayPeer *peers, size_t count, uint64_t now, uint64_t timeout) {
    for (size_t index = 0U; index < count; ++index) {
        if (peers[index].active && now >= peers[index].last_seen_ms && now - peers[index].last_seen_ms >= timeout) {
            close_peer(epoll_fd, &peers[index]);
        }
    }
}

static size_t datagram_limit(sa_family_t family) {
    return family == AF_INET6 ? 65527U : 65507U;
}

static bool transform_packet(const RelayConfig *config, bool from_client,
    const uint8_t *input, size_t input_length, uint8_t *output,
    size_t capacity, const uint8_t **payload, size_t *payload_length) {
    *payload = input;
    *payload_length = input_length;
    if (config->mode != MODE_DATA_SAVING) { return input_length <= capacity; }
    bool encode = from_client != config->framing_back;
    bool valid = encode ? rle_encode(input, input_length, output, capacity, payload_length)
                        : rle_decode(input, input_length, output, capacity, payload_length);
    if (valid) { *payload = output; }
    return valid;
}

static int run_relay(const RelayConfig *config, RelayMetrics *metrics) {
    int listener = create_listener(config);
    if (listener < 0) {
        perror("failed to create UDP listener");
        return -1;
    }
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        (void)close(listener);
        return -1;
    }
    RelayPeer *peers = calloc(config->max_peers, sizeof(*peers));
    if (peers == NULL) {
        (void)close(epoll_fd);
        (void)close(listener);
        return -1;
    }
    for (size_t index = 0U; index < config->max_peers; ++index) {
        peers[index].upstream_fd = -1;
    }
    /* Level-triggered readiness permits a finite per-socket batch without
       losing pending packets, so a busy sender cannot starve replies/cleanup. */
    struct epoll_event listener_event = {.events = EPOLLIN};
    listener_event.data.u64 = 0U;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &listener_event) != 0) {
        perror("epoll_ctl");
        free(peers);
        (void)close(epoll_fd);
        (void)close(listener);
        return -1;
    }

    uint8_t input[MAX_DATAGRAM_BYTES];
    uint8_t transformed[MAX_DATAGRAM_BYTES];
    struct epoll_event events[MAX_EVENTS];
    uint64_t last_cleanup = monotonic_milliseconds();
    int result = 0;
    while (!stop_requested) {
        int ready = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            result = -1;
            break;
        }
        uint64_t now = monotonic_milliseconds();
        if (now - last_cleanup >= 1000U) {
            cleanup_idle_peers(epoll_fd, peers, config->max_peers, now, config->idle_timeout_ms);
            last_cleanup = now;
        }
        for (int event_index = 0; event_index < ready; ++event_index) {
            uint32_t identifier = (uint32_t)events[event_index].data.u64;
            if (identifier == 0U) {
                for (size_t batch = 0U; batch < MAX_BATCH_DATAGRAMS && !stop_requested; ++batch) {
                    struct sockaddr_storage client;
                    socklen_t client_length = sizeof(client);
                    ssize_t received = recvfrom(listener, input, sizeof(input), MSG_TRUNC, (struct sockaddr *)&client, &client_length);
                    if (received < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        ++metrics->dropped;
                        break;
                    }
                    if ((size_t)received > sizeof(input) || client_length > sizeof(client)) {
                        ++metrics->dropped;
                        continue;
                    }
                    ++metrics->packets_in;
                    metrics->bytes_in += (uint64_t)received;
                    const uint8_t *payload;
                    size_t payload_length;
                    if (!transform_packet(config, true, input, (size_t)received, transformed,
                        datagram_limit(config->target_address.ss_family), &payload, &payload_length)) {
                        ++metrics->dropped;
                        continue;
                    }
                    ssize_t peer_index = find_peer(peers, config->max_peers, &client, client_length);
                    if (peer_index < 0) {
                        peer_index = create_peer(epoll_fd, peers, config->max_peers, config, &client, client_length, now);
                    }
                    if (peer_index < 0) {
                        ++metrics->dropped;
                        continue;
                    }
                    RelayPeer *peer = &peers[peer_index];
                    peer->last_seen_ms = now;
                    if (!rate_allow(peer, now, config)) {
                        ++metrics->dropped;
                        continue;
                    }
                    ssize_t sent = send(peer->upstream_fd, payload, payload_length, MSG_NOSIGNAL);
                    if (sent < 0 || (size_t)sent != payload_length) {
                        ++metrics->dropped;
                    }
                }
            } else {
                size_t peer_index = (size_t)(identifier - 1U);
                if (peer_index >= config->max_peers || !peers[peer_index].active ||
                    peers[peer_index].generation != (uint32_t)(events[event_index].data.u64 >> 32U)) {
                    continue;
                }
                RelayPeer *peer = &peers[peer_index];
                for (size_t batch = 0U; batch < MAX_BATCH_DATAGRAMS && !stop_requested; ++batch) {
                    ssize_t received = recv(peer->upstream_fd, input, sizeof(input), MSG_TRUNC);
                    if (received < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        close_peer(epoll_fd, peer);
                        break;
                    }
                    if ((size_t)received > sizeof(input)) {
                        ++metrics->dropped;
                        continue;
                    }
                    peer->last_seen_ms = now;
                    const uint8_t *payload;
                    size_t payload_length;
                    if (!transform_packet(config, false, input, (size_t)received, transformed,
                        datagram_limit(peer->client_address.ss_family), &payload, &payload_length)) {
                        ++metrics->dropped;
                        continue;
                    }
                    ssize_t sent = sendto(
                        listener,
                        payload,
                        payload_length,
                        MSG_NOSIGNAL,
                        (const struct sockaddr *)&peer->client_address,
                        peer->client_length
                    );
                    if (sent < 0 || (size_t)sent != payload_length) {
                        ++metrics->dropped;
                    } else {
                        ++metrics->packets_out;
                        metrics->bytes_out += (uint64_t)sent;
                    }
                }
            }
        }
    }

    for (size_t index = 0U; index < config->max_peers; ++index) {
        close_peer(epoll_fd, &peers[index]);
    }
    secure_zero(input, sizeof(input));
    secure_zero(transformed, sizeof(transformed));
    free(peers);
    (void)close(epoll_fd);
    (void)close(listener);
    return result;
}

static bool split_destination(const char *value, char *host, size_t host_capacity, char *service, size_t service_capacity) {
    const char *host_start = value;
    const char *host_end = NULL;
    const char *port_start = NULL;
    if (value[0] == '[') {
        host_start = value + 1;
        host_end = strchr(host_start, ']');
        if (host_end == NULL || host_end[1] != ':') {
            return false;
        }
        port_start = host_end + 2;
    } else {
        const char *colon = strrchr(value, ':');
        if (colon == NULL || strchr(value, ':') != colon) {
            return false;
        }
        host_end = colon;
        port_start = colon + 1;
    }
    size_t host_length = (size_t)(host_end - host_start);
    size_t port_length = strlen(port_start);
    if (host_length == 0U || host_length >= host_capacity || port_length == 0U || port_length >= service_capacity) {
        return false;
    }
    memcpy(host, host_start, host_length);
    host[host_length] = '\0';
    memcpy(service, port_start, port_length + 1U);
    uint16_t ignored;
    return parse_u16(service, &ignored);
}

static void print_usage(const char *program) {
    printf("Usage: %s [OPTIONS]\n", program);
    puts("Options:");
    puts("  -b, --bind <host>       Bind host (default: 127.0.0.1)");
    puts("  -p, --port <port>       UDP listen port (default: 4433)");
    puts("  -d, --dest <host:port>  UDP destination (default: 127.0.0.1:4434)");
    puts("  -m, --mode <mode>       normal, data-saving, or high-speed");
    puts("  -s, --scenario <name>   broker or agent (metrics label only)");
    puts("      --max-peers <count> Maximum active client mappings (default: 1024)");
    puts("      --idle <seconds>    Mapping idle timeout (default: 60)");
    puts("      --rate <pps>        Per-client packet rate (default: 1000)");
    puts("      --burst <packets>   Per-client burst allowance (default: 2000)");
    puts("      --framing-side <front|back> Data-saving pair side (default: front)");
    puts("  -t, --run-tests         Run deterministic self-tests");
    puts("  -h, --help              Show this help");
    puts("Data-saving mode is a framed relay-to-relay protocol and requires a paired peer.");
}

static int run_tests(void) {
    uint8_t encoded[512];
    uint8_t decoded[512];
    size_t encoded_length = 0U;
    size_t decoded_length = 0U;
    const uint8_t repetitive[] = "aaaaaaaaaabbbbbbbbbbbbcccccccc";
    if (!rle_encode(repetitive, sizeof(repetitive) - 1U, encoded, sizeof(encoded), &encoded_length) ||
        !rle_decode(encoded, encoded_length, decoded, sizeof(decoded), &decoded_length) ||
        decoded_length != sizeof(repetitive) - 1U || memcmp(decoded, repetitive, decoded_length) != 0) {
        fputs("[FAIL] RLE round trip\n", stderr);
        return 1;
    }
    uint8_t raw[64];
    for (size_t index = 0U; index < sizeof(raw); ++index) {
        raw[index] = (uint8_t)index;
    }
    if (!rle_encode(raw, sizeof(raw), encoded, sizeof(encoded), &encoded_length) || encoded[0] != 0U ||
        !rle_decode(encoded, encoded_length, decoded, sizeof(decoded), &decoded_length) ||
        decoded_length != sizeof(raw) || memcmp(decoded, raw, sizeof(raw)) != 0) {
        fputs("[FAIL] raw frame fallback\n", stderr);
        return 1;
    }
    const uint8_t malformed[] = {1U, 0U, 42U};
    if (rle_decode(malformed, sizeof(malformed), decoded, sizeof(decoded), &decoded_length)) {
        fputs("[FAIL] malformed frame accepted\n", stderr);
        return 1;
    }
    RelayConfig config = {.rate_per_second = 1.0, .burst = 1.0};
    RelayPeer peer = {0};
    if (!rate_allow(&peer, 1000U, &config) || rate_allow(&peer, 1000U, &config) || !rate_allow(&peer, 2000U, &config)) {
        fputs("[FAIL] rate limiter\n", stderr);
        return 1;
    }
    char host[128];
    char service[6];
    if (!split_destination("[::1]:4434", host, sizeof(host), service, sizeof(service)) ||
        strcmp(host, "::1") != 0 || strcmp(service, "4434") != 0 ||
        split_destination("::1:4434", host, sizeof(host), service, sizeof(service))) {
        fputs("[FAIL] destination parser\n", stderr);
        return 1;
    }
    /* A front/back pair must recover plain requests at an ordinary backend,
       then recover the backend's response at the original client. */
    RelayConfig front = {.mode = MODE_DATA_SAVING};
    RelayConfig back = {.mode = MODE_DATA_SAVING, .framing_back = true};
    const uint8_t *payload = NULL;
    size_t payload_length = 0U;
    if (!transform_packet(&front, true, repetitive, sizeof(repetitive)-1U, encoded,
            sizeof(encoded), &payload, &payload_length) ||
        !transform_packet(&back, true, payload, payload_length, decoded,
            sizeof(decoded), &payload, &payload_length) ||
        payload_length != sizeof(repetitive)-1U || memcmp(payload, repetitive, payload_length) != 0) {
        fputs("[FAIL] paired request framing\n", stderr);
        return 1;
    }
    if (!transform_packet(&back, false, raw, sizeof(raw), encoded, sizeof(encoded), &payload, &payload_length) ||
        !transform_packet(&front, false, payload, payload_length, decoded, sizeof(decoded), &payload, &payload_length) ||
        payload_length != sizeof(raw) || memcmp(payload, raw, payload_length) != 0) {
        fputs("[FAIL] paired response framing\n", stderr);
        return 1;
    }
    if (!rle_encode(raw, 0U, encoded, sizeof(encoded), &encoded_length) ||
        !rle_decode(encoded, encoded_length, decoded, sizeof(decoded), &decoded_length) || decoded_length != 0U ||
        rle_encode(raw, SIZE_MAX, encoded, sizeof(encoded), &encoded_length)) {
        fputs("[FAIL] empty datagram or encoding length overflow\n", stderr);
        return 1;
    }
    const uint8_t bomb[] = {1U, 255U, 42U, 255U, 43U, 255U, 44U};
    if (rle_decode(bomb, sizeof(bomb), decoded, sizeof(decoded), &decoded_length) ||
        rle_decode((const uint8_t[]){1U}, 1U, decoded, sizeof(decoded), &decoded_length)) {
        fputs("[FAIL] oversized or empty RLE expansion\n", stderr);
        return 1;
    }
    struct sockaddr_storage first = {0}, second = {0};
    struct sockaddr_in6 *first6 = (struct sockaddr_in6 *)&first;
    struct sockaddr_in6 *second6 = (struct sockaddr_in6 *)&second;
    first6->sin6_family = second6->sin6_family = AF_INET6;
    first6->sin6_port = second6->sin6_port = htons(4433);
    first6->sin6_addr = second6->sin6_addr = in6addr_loopback;
    first6->sin6_scope_id = 1U;
    second6->sin6_scope_id = 2U;
    if (sockaddr_equal(&first, sizeof(*first6), &second, sizeof(*second6)) ||
        sockaddr_equal(&first, 1U, &first, sizeof(*first6))) {
        fputs("[FAIL] IPv6 scope or address length validation\n", stderr);
        return 1;
    }
    second6->sin6_scope_id = first6->sin6_scope_id;
    if (!sockaddr_equal(&first, sizeof(*first6), &second, sizeof(*second6))) {
        fputs("[FAIL] equal IPv6 peers\n", stderr);
        return 1;
    }
    puts("[PASS] C11 relay framing, validation, and rate-limit self-tests");
    return 0;
}

int main(int argc, char **argv) {
    RelayConfig config = {
        .bind_host = "127.0.0.1",
        .listen_port = 4433U,
        .mode = MODE_NORMAL,
        .scenario = SCENARIO_BROKER,
        .max_peers = DEFAULT_MAX_PEERS,
        .idle_timeout_ms = 60000U,
        .rate_per_second = 1000.0,
        .burst = 2000.0,
    };
    char destination_host[256] = "127.0.0.1";
    char destination_service[6] = "4434";
    bool tests = false;
    enum { OPTION_MAX_PEERS = 1000, OPTION_IDLE, OPTION_RATE, OPTION_BURST, OPTION_FRAMING_SIDE };
    static const struct option options[] = {
        {"bind", required_argument, NULL, 'b'},
        {"port", required_argument, NULL, 'p'},
        {"dest", required_argument, NULL, 'd'},
        {"mode", required_argument, NULL, 'm'},
        {"scenario", required_argument, NULL, 's'},
        {"run-tests", no_argument, NULL, 't'},
        {"max-peers", required_argument, NULL, OPTION_MAX_PEERS},
        {"idle", required_argument, NULL, OPTION_IDLE},
        {"rate", required_argument, NULL, OPTION_RATE},
        {"burst", required_argument, NULL, OPTION_BURST},
        {"framing-side", required_argument, NULL, OPTION_FRAMING_SIDE},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;
    while ((option = getopt_long(argc, argv, "b:p:d:m:s:th", options, NULL)) != -1) {
        switch (option) {
            case 'b':
                if (optarg[0] == '\0' || strlen(optarg) > 255U) {
                    fputs("invalid bind host\n", stderr);
                    return 2;
                }
                config.bind_host = optarg;
                break;
            case 'p':
                if (!parse_u16(optarg, &config.listen_port)) {
                    fputs("invalid listen port\n", stderr);
                    return 2;
                }
                break;
            case 'd':
                if (!split_destination(optarg, destination_host, sizeof(destination_host), destination_service, sizeof(destination_service))) {
                    fputs("destination must be host:port (bracket IPv6 literals)\n", stderr);
                    return 2;
                }
                break;
            case 'm':
                if (strcmp(optarg, "normal") == 0) {
                    config.mode = MODE_NORMAL;
                } else if (strcmp(optarg, "data-saving") == 0) {
                    config.mode = MODE_DATA_SAVING;
                } else if (strcmp(optarg, "high-speed") == 0) {
                    config.mode = MODE_HIGH_SPEED;
                } else {
                    fputs("invalid relay mode\n", stderr);
                    return 2;
                }
                break;
            case 's':
                if (strcmp(optarg, "broker") == 0) {
                    config.scenario = SCENARIO_BROKER;
                } else if (strcmp(optarg, "agent") == 0) {
                    config.scenario = SCENARIO_AGENT;
                } else {
                    fputs("invalid scenario\n", stderr);
                    return 2;
                }
                break;
            case 't':
                tests = true;
                break;
            case OPTION_MAX_PEERS:
                if (!parse_size(optarg, 1U, HARD_MAX_PEERS, &config.max_peers)) {
                    fputs("invalid max-peers\n", stderr);
                    return 2;
                }
                break;
            case OPTION_IDLE: {
                size_t seconds = 0U;
                if (!parse_size(optarg, 1U, 86400U, &seconds)) {
                    fputs("invalid idle timeout\n", stderr);
                    return 2;
                }
                config.idle_timeout_ms = (uint64_t)seconds * 1000U;
                break;
            }
            case OPTION_RATE:
                if (!parse_positive_double(optarg, 1000000.0, &config.rate_per_second)) {
                    fputs("invalid rate\n", stderr);
                    return 2;
                }
                break;
            case OPTION_BURST:
                if (!parse_positive_double(optarg, 1000000.0, &config.burst)) {
                    fputs("invalid burst\n", stderr);
                    return 2;
                }
                break;
            case OPTION_FRAMING_SIDE:
                if (strcmp(optarg, "front") == 0) { config.framing_back = false; }
                else if (strcmp(optarg, "back") == 0) { config.framing_back = true; }
                else { fputs("invalid framing side\n", stderr); return 2; }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 2;
        }
    }
    if (optind != argc) {
        fputs("unexpected positional arguments\n", stderr);
        return 2;
    }
    if (tests) {
        return run_tests();
    }
    if (resolve_address(destination_host, destination_service, false, &config.target_address, &config.target_length) != 0) {
        fputs("cannot resolve destination\n", stderr);
        return 2;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    printf(
        "Shadow6 C11 UDP Relay: %s:%u -> %s:%s | peers=%zu mode=%s scenario=%s\n",
        config.bind_host,
        config.listen_port,
        destination_host,
        destination_service,
        config.max_peers,
        config.mode == MODE_DATA_SAVING ? "data-saving" : (config.mode == MODE_HIGH_SPEED ? "high-speed" : "normal"),
        config.scenario == SCENARIO_BROKER ? "broker" : "agent"
    );
    RelayMetrics metrics = {0};
    int status = run_relay(&config, &metrics);
    printf(
        "Relay stopped: in=%llu/%lluB out=%llu/%lluB dropped=%llu\n",
        (unsigned long long)metrics.packets_in,
        (unsigned long long)metrics.bytes_in,
        (unsigned long long)metrics.packets_out,
        (unsigned long long)metrics.bytes_out,
        (unsigned long long)metrics.dropped
    );
    return status == 0 ? 0 : 1;
}
