/* Native three-role transport, compiled into the existing Idris FFI boundary.
 * S6I3 signed ephemeral exchange is distinct from legacy pre-shared-key mode;
 * its S6I2 data frames use a bounded 256-packet selective-repeat window.
 * Every route is operator-pinned; the broker has public identity pins only. */
static time_t idris_chain_now(void) {
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC, &t) ? 0 : t.tv_sec;
}

static int idris_chain_receive(int fd, unsigned char *out, size_t cap,
                               const struct sockaddr_in *peer, int timeout) {
    struct pollfd p = {.fd=fd,.events=POLLIN};
    if (poll(&p, 1, timeout) != 1 || !(p.revents & POLLIN)) return -1;
    struct sockaddr_in source; socklen_t sl = sizeof source;
    ssize_t n = recvfrom(fd, out, cap, 0, (struct sockaddr *)&source, &sl);
    return n >= 0 && same_addr(&source, peer) ? (int)n : -1;
}

static int idris_chain_exchange(int fd, const struct sockaddr_in *peer, int role,
                                 unsigned char config[96], unsigned char key[32]) {
    unsigned char pk[32], sk[64], ephemeral[32], shared[32];
    unsigned char hello[132]={0}, reply[196]={0}, incoming[197], material[164];
    int rc = -1;
    if (crypto_sign_seed_keypair(pk, sk, config)) goto done;
    randombytes_buf(ephemeral, 32);
    if (role == 1) {
        memcpy(hello, "S6I3", 4); randombytes_buf(hello + 4, 32);
        if (crypto_scalarmult_base(hello + 36, ephemeral) ||
            crypto_sign_detached(hello + 68, NULL, hello, 68, sk)) goto done;
        if (sendto(fd, hello, sizeof hello, 0, (const struct sockaddr *)peer, sizeof *peer) != sizeof hello ||
            idris_chain_receive(fd, incoming, sizeof incoming, peer, 5000) != sizeof reply ||
            sodium_memcmp(incoming, hello, 68) ||
            memcmp(incoming + 68, "S6I3", 4) ||
            crypto_sign_verify_detached(incoming + 132, incoming, 132, config + 32)) goto done;
        memcpy(reply, incoming, sizeof reply);
        if (crypto_scalarmult(shared, ephemeral, reply + 100)) goto done;
    } else {
        if (idris_chain_receive(fd, incoming, sizeof incoming, peer, 30000) != sizeof hello ||
            memcmp(incoming, "S6I3", 4) ||
            crypto_sign_verify_detached(incoming + 68, incoming, 68, config + 32)) goto done;
        memcpy(reply, incoming, 68); randombytes_buf(reply + 68, 32);
        memcpy(reply + 68, "S6I3", 4);
        if (crypto_scalarmult_base(reply + 100, ephemeral) ||
            crypto_scalarmult(shared, ephemeral, reply + 36) ||
            crypto_sign_detached(reply + 132, NULL, reply, 132, sk)) goto done;
        if (sendto(fd, reply, sizeof reply, 0, (const struct sockaddr *)peer, sizeof *peer) != sizeof reply) goto done;
    }
    memcpy(material, reply, 132); memcpy(material + 132, config + 64, 32);
    rc = crypto_generichash(key, 32, material, sizeof material, shared, 32);
done:
    sodium_memzero(sk, sizeof sk); sodium_memzero(ephemeral, sizeof ephemeral);
    sodium_memzero(shared, sizeof shared); sodium_memzero(material, sizeof material);
    sodium_memzero(config, 96);
    return rc;
}

static int idris_chain_broker(const struct sockaddr_in *bind_sa,
                              const struct sockaddr_in *client,
                              const struct sockaddr_in *agent,
                              const char *path, unsigned int limit) {
    struct idris_broker_slot { uint64_t sequence; int pending; };
    unsigned char pins[96], frame[IDRIS_NATIVE_FRAME+1], challenge[68];
    struct idris_broker_slot window[2][IDRIS_CHAIN_WINDOW] = {{{0}}};
    if (same_addr(bind_sa,client) || same_addr(bind_sa,agent) || same_addr(client,agent) ||
        load_native_keys(path, pins, sizeof pins) || sodium_is_zero(pins, 32) != 1) return -1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0), rc = -1, phase = 0;
    unsigned int forwarded = 0;time_t final_until=0;
    if (fd < 0) return -1;
    if (bind(fd, (const struct sockaddr *)bind_sa, sizeof *bind_sa)) goto done;
    time_t started = idris_chain_now(), activity = started;
    if (!started) goto done;
    puts("broker ready"); fflush(stdout);
    for (unsigned int count=0; count<1000000; ++count) {
        time_t now = idris_chain_now();
        if (!now || now-started>=300 || now-activity>=(phase==2?60:5) || (final_until&&now>=final_until)) break;
        struct pollfd p = {.fd=fd,.events=POLLIN};
        if (poll(&p, 1, 1000)<=0) continue;
        struct sockaddr_in source; socklen_t sl=sizeof source;
        ssize_t n=recvfrom(fd,frame,sizeof frame,0,(struct sockaddr *)&source,&sl);
        const struct sockaddr_in *destination=NULL;
        int admission_frame=0;
        if (phase==0 && same_addr(&source,client) && n==132) {
            if (memcmp(frame,"S6I3",4) || crypto_sign_verify_detached(frame+68,frame,68,pins+32)) continue;
            memcpy(challenge,frame,68);phase=1;destination=agent;admission_frame=1;
        } else if (phase==1 && same_addr(&source,agent) && n==196) {
            if (sodium_memcmp(challenge,frame,68) || memcmp(frame+68,"S6I3",4) ||
                crypto_sign_verify_detached(frame+132,frame,132,pins+64)) continue;
            phase=2;destination=client;admission_frame=1;
        } else if (phase==2 && n>50 && n<=IDRIS_NATIVE_FRAME && !memcmp(frame,"S6I2",4) &&
                   frame[4]==2 && frame[6]<=1 && !frame[7] &&
                   n==50+(ssize_t)(((unsigned)frame[32]<<8)|frame[33])) {
            int side = same_addr(&source,client) ? 0 : same_addr(&source,agent) ? 1 : -1;
            uint64_t sequence = get64(frame+8);
            if (side < 0 || !sequence) continue;
            unsigned slot = (unsigned)(sequence & (IDRIS_CHAIN_WINDOW-1));
            if (frame[6] == 0 && frame[5] == (side == 0 ? 1 : 2)) {
                struct idris_broker_slot *entry = &window[side][slot];
                if (entry->sequence == sequence) {
                    /* Exact retransmission: the endpoint may have lost its ACK. */
                    entry->pending = 1;
                } else if (forwarded < limit && !entry->pending) {
                    entry->sequence = sequence; entry->pending = 1; ++forwarded;
                } else continue;
                destination = side == 0 ? agent : client;
                if (forwarded >= limit && final_until) final_until = now + 3;
            } else if (frame[6] == 1 && frame[33] == 1 && frame[5] == (side == 0 ? 1 : 2)) {
                struct idris_broker_slot *entry = &window[1-side][slot];
                if (entry->sequence != sequence || !entry->pending) continue;
                entry->pending = 0;
                destination = side == 0 ? agent : client;
                if (forwarded >= limit) {
                    int outstanding = 0;
                    for (unsigned d=0; d<2; ++d)
                        for (unsigned i=0; i<IDRIS_CHAIN_WINDOW; ++i) outstanding |= window[d][i].pending;
                    if (!outstanding) final_until = now + 3;
                }
            }
        }
        if (!destination) continue;
        if (sendto(fd,frame,(size_t)n,0,(const struct sockaddr *)destination,sizeof *destination)!=n) goto done;
        activity=now;
        /* Preserve the broker's established limit accounting: both signed
         * admission frames consume the same forwarding budget as data. */
        if (admission_frame && forwarded<limit) ++forwarded;
    }
    rc=(int)forwarded;
done:
    close(fd); sodium_memzero(pins,sizeof pins); return rc;
}
