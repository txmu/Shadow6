/* libdatachannel owns its threads. Nim ARC objects never cross callbacks. */
#ifndef SHADOW6_QUEUE_TEST
#include <rtc/rtc.h>
#else
/* The queue regression harness needs no external RTC runtime. */
#define RTC_ERR_NOT_AVAIL (-3)
static int rtcSetMessageCallback(int id, void (*callback)(int, const char *, int, void *)) {
    (void)callback; return id == 999 ? -1 : 0;
}
#endif
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t space = PTHREAD_COND_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
#ifndef SHADOW6_QUEUE_TEST
static int accepted[16], count;
static atomic_int gathered;
#endif
/* All Nim consumers run on one thread. One process-wide nonblocking pipe
 * wakes that thread for any RTC queue; data remains in the bounded queues. */
static pthread_once_t wake_once = PTHREAD_ONCE_INIT;
static int wake_pipe[2] = {-1,-1};
static void init_wake(void) {
    int fd[2];
    if (pipe(fd)) return;
    for (int i=0;i<2;i++) {
        int flags=fcntl(fd[i],F_GETFL);
        if (flags<0 || fcntl(fd[i],F_SETFL,flags|O_NONBLOCK)<0 ||
            fcntl(fd[i],F_SETFD,FD_CLOEXEC)<0) {
            close(fd[0]); close(fd[1]); return;
        }
    }
    wake_pipe[0]=fd[0]; wake_pipe[1]=fd[1];
}
static void wake_consumer(void) {
    if (wake_pipe[1]>=0) {
        char token=1;
        /* EAGAIN means a wake is already pending; never block a callback. */
        ssize_t result;
        do { result=write(wake_pipe[1],&token,1); } while(result<0 && errno==EINTR);
    }
}
static uint64_t next_generation;
/* 128 x 64 KiB per channel, 20 channels: a fixed 160 MiB static bound. */
#define RTC_QUEUE_DEPTH 128
/* Fixed receive queues impose a bound even when an authenticated peer floods
 * while the Nim event loop is busy. These are reliable ordered streams:
 * dropping an already-delivered SCTP/WebSocket message would corrupt them.
 * Apply bounded callback backpressure until the consumer drains a slot. */
static struct { int used, id, head, count, failed; uint64_t generation; int size[RTC_QUEUE_DEPTH]; char data[RTC_QUEUE_DEPTH][65536]; } queues[20];
static void message(int id, const char *data, int size, void *unused) {
    (void)unused;
    int n = size < 0 ? (int)strnlen(data,65536)+1 : size;
    pthread_mutex_lock(&lock);
    for (int i=0;i<20;i++) if (queues[i].used && queues[i].id==id) {
        uint64_t generation = queues[i].generation;
        if (n>65536 || n<1) queues[i].failed=1;
        struct timespec until;
        if (clock_gettime(CLOCK_REALTIME, &until)) queues[i].failed=1;
        else until.tv_sec += 5;
        while (!queues[i].failed && queues[i].used && queues[i].generation==generation && queues[i].count==RTC_QUEUE_DEPTH) {
            int result = pthread_cond_timedwait(&space, &lock, &until);
            if (result && queues[i].used && queues[i].generation==generation) queues[i].failed=1;
        }
        if (!queues[i].failed && queues[i].used && queues[i].generation==generation) {
            int slot=(queues[i].head+queues[i].count)%RTC_QUEUE_DEPTH;
            memcpy(queues[i].data[slot],data,n);
            queues[i].size[slot]=size<0 ? -n : n;
            queues[i].count++;
        }
        if (queues[i].count==1 || queues[i].failed) wake_consumer();
        pthread_cond_broadcast(&ready);
        break;
    }
    pthread_mutex_unlock(&lock);
}
static int watch(int id) {
    if (id<0) return id;
    pthread_once(&wake_once,init_wake);
    if (wake_pipe[0]<0) return -1;
    int slot=-1;
    pthread_mutex_lock(&lock);
    for (int i=0;i<20;i++) if (!queues[i].used) {
        if (next_generation == UINT64_MAX) break;
        memset(&queues[i],0,sizeof queues[i]); queues[i].used=1; queues[i].id=id;
        queues[i].generation=++next_generation; slot=i; break;
    }
    pthread_mutex_unlock(&lock);
    if (slot<0) return -1;
    if (rtcSetMessageCallback(id,message)) {
        pthread_mutex_lock(&lock);
        queues[slot].used=0;
        pthread_cond_broadcast(&space);
        pthread_mutex_unlock(&lock);
        return -1;
    }
    return id;
}
int nim_rtc_receive(int id, char *data, int *size) {
    int result=-1;
    pthread_mutex_lock(&lock);
    for (int i=0;i<20;i++) if (queues[i].used && queues[i].id==id) {
        if (queues[i].failed) break;
        if (!queues[i].count) { result=RTC_ERR_NOT_AVAIL; break; }
        int slot=queues[i].head, n=queues[i].size[slot];
        if ((n<0 ? -n : n)>*size) break;
        memcpy(data,queues[i].data[slot],n<0 ? -n : n); *size=n;
        queues[i].head=(slot+1)%RTC_QUEUE_DEPTH; queues[i].count--; result=0;
        pthread_cond_broadcast(&space); break;
    }
    pthread_mutex_unlock(&lock);
    return result;
}
/* Wake on arrival instead of sleeping through a full four-message queue.
 * One millisecond still bounds the wait for unrelated local TCP activity.
 * A generation check prevents a deleted/reused ID satisfying an old wait. */
int nim_rtc_wait(int id) {
    struct timespec until;
    if (clock_gettime(CLOCK_REALTIME, &until)) return -1;
    until.tv_nsec += 1000000;
    if (until.tv_nsec >= 1000000000) { until.tv_nsec -= 1000000000; until.tv_sec++; }
    int result = -1;
    pthread_mutex_lock(&lock);
    for (int i=0;i<20;i++) if (queues[i].used && queues[i].id==id) {
        uint64_t generation = queues[i].generation;
        while (queues[i].used && queues[i].generation==generation &&
               !queues[i].failed && !queues[i].count) {
            int status = pthread_cond_timedwait(&ready, &lock, &until);
            if (status == ETIMEDOUT) break;
            if (status) { pthread_mutex_unlock(&lock); return -1; }
        }
        if (queues[i].used && queues[i].generation==generation && !queues[i].failed)
            result = queues[i].count ? 1 : 0;
        break;
    }
    pthread_mutex_unlock(&lock);
    return result;
}
/* Wake on either local TCP readiness or RTC arrival. The caller chooses
 * POLLOUT only for a pending TCP write, and POLLIN only below its send bound.
 * A 1 ms timeout still services RTC buffered-amount changes without callbacks. */
int nim_rtc_wait_io(int id, int fd, int events) {
    int slot=-1; uint64_t generation=0;
    char tokens[64];
    /* Drain a bounded number of notifications BEFORE checking queue state. */
    if (wake_pipe[0]<0) return -1;
    (void)read(wake_pipe[0],tokens,sizeof tokens);
    pthread_mutex_lock(&lock);
    for(int i=0;i<20;i++) if(queues[i].used && queues[i].id==id) {
        if(!queues[i].failed) { slot=i; generation=queues[i].generation; }
        break;
    }
    int queued=slot>=0 && queues[slot].count;
    pthread_mutex_unlock(&lock);
    if(slot<0) return -1;
    if(queued && !(events&POLLOUT)) return 1;
    struct pollfd fds[2]={{wake_pipe[0],POLLIN,0},{fd,(short)events,0}};
    int status=poll(fds,2,1);
    if(status<0 && errno!=EINTR) return -1;
    pthread_mutex_lock(&lock);
    int valid=queues[slot].used && queues[slot].generation==generation && !queues[slot].failed;
    pthread_mutex_unlock(&lock);
    return valid ? (status>0) : -1;
}
void nim_rtc_forget(int id) {
    pthread_mutex_lock(&lock);
    for (int i=0;i<20;i++) if (queues[i].used && queues[i].id==id) queues[i].used=0;
    pthread_cond_broadcast(&space);
    wake_consumer();
    pthread_cond_broadcast(&ready);
    pthread_mutex_unlock(&lock);
}
#ifndef SHADOW6_QUEUE_TEST
static void on_client(int server, int ws, void *unused) {
    (void)server; (void)unused;
    pthread_mutex_lock(&lock);
    int allowed=count<16;
    if (allowed) accepted[count++] = ws;
    pthread_mutex_unlock(&lock);
    if (!allowed) rtcDeleteWebSocket(ws);
}
int nim_rtc_accept(void) {
    pthread_mutex_lock(&lock);
    int result = count ? accepted[--count] : -1;
    pthread_mutex_unlock(&lock);
    if (result>=0 && watch(result)<0) { rtcDeleteWebSocket(result); return -1; }
    return result;
}
int nim_rtc_server(const char *host, int port, const char *cert, const char *key) {
    rtcWsServerConfiguration config = {0};
    config.port = (uint16_t)port; config.bindAddress = host;
    config.enableTls = cert && *cert;
    config.certificatePemFile = cert && *cert ? cert : NULL;
    config.keyPemFile = key && *key ? key : NULL;
    config.maxMessageSize = 65536; config.connectionTimeoutMs = 10000;
    return rtcCreateWebSocketServer(&config,on_client);
}
int nim_rtc_websocket(const char *url) {
    rtcWsConfiguration config = {0};
    config.connectionTimeoutMs = 10000; config.maxMessageSize = 65536;
    int ws=rtcCreateWebSocketEx(url,&config);
    if (ws>=0 && watch(ws)<0) { rtcDeleteWebSocket(ws); return -1; }
    return ws;
}
static void gathering(int pc, rtcGatheringState state, void *unused) {
    (void)pc; (void)unused;
    if (state == RTC_GATHERING_COMPLETE) atomic_store(&gathered,1);
}
int nim_rtc_peer(const char *bind) {
    rtcSctpSettings settings = {0};
    settings.recvBufferSize = 262144; settings.sendBufferSize = 262144;
    settings.maxChunksOnQueue = 128; settings.maxRetransmitAttempts = 5;
    if (rtcSetSctpSettings(&settings)) return -1;
    rtcConfiguration config = {0};
    config.disableAutoNegotiation = true; config.maxMessageSize = 16392;
    config.bindAddress = bind && *bind ? bind : NULL;
    atomic_store(&gathered,0);
    int pc = rtcCreatePeerConnection(&config);
    if (pc >= 0 && rtcSetGatheringStateChangeCallback(pc,gathering)) {
        rtcDeletePeerConnection(pc); return -1;
    }
    return pc;
}
int nim_rtc_channel(int pc) {
    rtcDataChannelInit init = {0};
    init.negotiated = true; init.manualStream = true; init.stream = 0;
    init.protocol = "shadow6/1";
    int dc=rtcCreateDataChannelEx(pc,"shadow6",&init);
    if (dc>=0 && watch(dc)<0) { rtcDeleteDataChannel(dc); return -1; }
    return dc;
}
int nim_rtc_gathered(void) { return atomic_load(&gathered); }
#endif
