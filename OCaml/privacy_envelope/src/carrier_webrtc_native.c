#define _GNU_SOURCE
/* No OCaml objects or Native Core protocol bytes are interpreted in callbacks. */
#include "carrier_webrtc_native.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#if defined(__linux__) && defined(__has_include) && !defined(S6EPE_DISABLE_WEBRTC)
#if __has_include(<rtc/rtc.h>)
#define S6_RTC_HEADERS 1
#endif
#endif
#ifdef S6_RTC_HEADERS
#include <rtc/rtc.h>
#if RTC_VERSION_MAJOR != 0 || RTC_VERSION_MINOR != 23
#error "S6EPE WebRTC provider requires libdatachannel 0.23 C API"
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Resolve only the fixed backend SONAME; operator configuration never supplies
   a shared-library path. Headers and runtime are from the pinned CI dependency. */
#define RTC_FUNCTIONS(X) \
 X(rtcSetSctpSettings) X(rtcCreatePeerConnection) X(rtcDeletePeerConnection) \
 X(rtcSetUserPointer) X(rtcSetGatheringStateChangeCallback) X(rtcSetStateChangeCallback) \
 X(rtcSetIceStateChangeCallback) X(rtcSetLocalDescription) X(rtcSetRemoteDescription) \
 X(rtcGetLocalDescription) X(rtcCreateDataChannelEx) X(rtcDeleteDataChannel) \
 X(rtcSetMessageCallback) X(rtcSetClosedCallback) X(rtcSetErrorCallback) \
 X(rtcSendMessage) X(rtcClose) X(rtcIsOpen) X(rtcIsClosed) X(rtcGetBufferedAmount) \
 X(rtcSetBufferedAmountLowThreshold) X(rtcSetBufferedAmountLowCallback) X(rtcMaxMessageSize)
static struct {
#define DECLARE(name) __typeof__(&name) name;
 RTC_FUNCTIONS(DECLARE)
#undef DECLARE
} api;
static pthread_once_t load_once=PTHREAD_ONCE_INIT;
static int loaded;
static void *library;
static void load_api(void) {
    /* The pinned backend sizes its fixed global worker pool to the host's
       online CPUs (minimum four). Refuse a host beyond this explicit bound
       before backend initialization; no unbounded worker pool is admitted. */
    long processors=sysconf(_SC_NPROCESSORS_ONLN);
    if(processors<1 || processors>256)return;
    library=dlopen("libdatachannel.so.0.23",RTLD_NOW|RTLD_LOCAL);
    if (!library) return;
#define RESOLVE(name) do { void *symbol=dlsym(library,#name); if (!symbol) goto failed; memcpy(&api.name,&symbol,sizeof symbol); } while(0);
    RTC_FUNCTIONS(RESOLVE)
#undef RESOLVE
    rtcSctpSettings settings={0};
    settings.recvBufferSize=262144;settings.sendBufferSize=262144;
    settings.maxChunksOnQueue=128;settings.maxRetransmitAttempts=5;
    if (api.rtcSetSctpSettings(&settings)) goto failed;
    loaded=1;return;
failed:
    memset(&api,0,sizeof api);dlclose(library);library=NULL;
}
int s6_rtc_available(void) { pthread_once(&load_once,load_api);return loaded; }
#define MAX_PEERS 256
#define MAX_CHANNELS 64
#define SDP_MAX 32768
#define SEND_BYTES 262144
typedef struct record { struct record *next;unsigned kind,channel,text;size_t size;unsigned char data[]; } record;
struct s6_rtc {
    int pc,failed,started,local_offer,remote_seen,gathered,connected,ice,dead;
    unsigned count,depth,queued,slot,cursor;
    size_t maximum,budget,bytes;
    int dc[MAX_CHANNELS],closing[MAX_CHANNELS];
    s6_rtc_channel channels[MAX_CHANNELS];
    record *head,*tail;
};
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed=PTHREAD_COND_INITIALIZER;
static s6_rtc *peers[MAX_PEERS];
static size_t reserved_bytes;
#define TOTAL_QUEUE_BYTES (64U*1024U*1024U)
/* Callbacks use ID lookup while holding this lock, never a caller-owned or
   freed userdata pointer. Delete removes the peer before waiting on library
   cleanup. Channel/peer deletion stays outside the lock to avoid deadlocks. */
static s6_rtc *lookup(int id,unsigned *channel) {
    for (unsigned n=0;n<MAX_PEERS;n++) if (peers[n]) {
        s6_rtc *t=peers[n];
        if (id==t->pc) { *channel=MAX_CHANNELS;return t; }
        for (unsigned i=0;i<t->count;i++) if (t->dc[i]==id) { *channel=i;return t; }
    }
    return NULL;
}
static void wake(void) { pthread_cond_broadcast(&changed); }
static int utf8(const unsigned char *data,size_t size) {
    for(size_t i=0;i<size;) {
        unsigned char first=data[i++];unsigned remaining;uint32_t value,minimum;
        if(first<0x80)continue;
        if(first>=0xc2 && first<=0xdf){remaining=1;value=first&0x1f;minimum=0x80;}
        else if(first>=0xe0 && first<=0xef){remaining=2;value=first&0x0f;minimum=0x800;}
        else if(first>=0xf0 && first<=0xf4){remaining=3;value=first&7;minimum=0x10000;}
        else return 0;
        if(remaining>size-i)return 0;
        for(unsigned n=0;n<remaining;n++){unsigned char next=data[i++];if((next&0xc0)!=0x80)return 0;value=(value<<6)|(next&0x3f);}
        if(value<minimum || value>0x10ffff || (value>=0xd800 && value<=0xdfff))return 0;
    }
    return 1;
}
static void enqueue(s6_rtc *t,unsigned kind,unsigned channel,int text,const void *data,size_t size) {
    if (t->failed) return;
    if (size>t->maximum || t->queued>=t->depth || size>t->budget-t->bytes) { t->failed=1;wake();return; }
    record *r=malloc(sizeof *r+size);
    if (!r) {t->failed=1;wake();return;}
    r->next=NULL;r->kind=kind;r->channel=channel;r->text=(unsigned)text;r->size=size;
    if (size) memcpy(r->data,data,size);
    if (t->tail) t->tail->next=r;else t->head=r;
    t->tail=r;t->queued++;t->bytes+=size;wake();
}
static void message(int id,const char *data,int size,void *unused) {
    (void)unused;unsigned i;
    pthread_mutex_lock(&lock);s6_rtc *t=lookup(id,&i);
    if (t && i<t->count) {
        /* C API text size is -(UTF-8 byte length + terminator), not -1.
           Binary zero-length callbacks may legitimately have NULL data. */
        size_t n=size<0?(size_t)(-(int64_t)size-1):(size_t)size;
        if ((!data && (n || size<0)) || n>t->maximum ||
            (size<0 && (data[n] || !utf8((const unsigned char *)data,n))) || t->closing[i]==2) {t->failed=1;wake();}
        else enqueue(t,1,t->channels[i].id,size<0,data,n);
    }
    pthread_mutex_unlock(&lock);
}
static void closed(int id,void *unused) {
    (void)unused;unsigned i;
    pthread_mutex_lock(&lock);s6_rtc *t=lookup(id,&i);
    if (t && i<t->count) {t->closing[i]=2;enqueue(t,2,t->channels[i].id,0,NULL,0);}
    pthread_mutex_unlock(&lock);
}
static void error(int id,const char *detail,void *unused) {
    (void)unused;unsigned i;
    (void)detail;
    pthread_mutex_lock(&lock);s6_rtc *t=lookup(id,&i);if(t){t->failed=1;wake();}pthread_mutex_unlock(&lock);
}
static void low(int id,void *unused) {
    (void)id;(void)unused;pthread_mutex_lock(&lock);wake();pthread_mutex_unlock(&lock);
}
static void gathering(int id,rtcGatheringState state,void *unused) {
    (void)unused;unsigned i;
    pthread_mutex_lock(&lock);s6_rtc *t=lookup(id,&i);
    if(t){t->gathered=state==RTC_GATHERING_COMPLETE;wake();}pthread_mutex_unlock(&lock);
}
static void state(int id,rtcState value,void *unused) {
    (void)unused;unsigned i;
    pthread_mutex_lock(&lock);s6_rtc *t=lookup(id,&i);
    if(t){t->connected=value==RTC_CONNECTED;
        /* DISCONNECTED is a recoverable ICE transition. Handshake/session
           deadlines bound recovery; only FAILED terminates immediately. */
        if(value==RTC_FAILED){t->failed=1;wake();}
        else if(value==RTC_CLOSED){t->dead=1;enqueue(t,3,0,0,NULL,0);}
        wake();}
    pthread_mutex_unlock(&lock);
}
static void ice(int id,rtcIceState value,void *unused) {
    (void)unused;unsigned i;
    pthread_mutex_lock(&lock);s6_rtc *t=lookup(id,&i);
    if(t){t->ice=value==RTC_ICE_CONNECTED || value==RTC_ICE_COMPLETED;
        if(value==RTC_ICE_FAILED){t->failed=1;wake();}}
    pthread_mutex_unlock(&lock);
}
void s6_rtc_free(s6_rtc *t) {
    if (!t) return;
    pthread_mutex_lock(&lock);peers[t->slot]=NULL;reserved_bytes-=t->budget;wake();pthread_mutex_unlock(&lock);
    for(unsigned i=0;i<t->count;i++) if(t->dc[i]>=0) api.rtcDeleteDataChannel(t->dc[i]);
    if(t->pc>=0) api.rtcDeletePeerConnection(t->pc);
    while(t->head){record *r=t->head;t->head=r->next;memset(r->data,0,r->size);free(r);}
    memset(t,0,sizeof *t);free(t);
}
s6_rtc *s6_rtc_create(const char *bind,const s6_rtc_channel *channels,unsigned count,
                     size_t maximum,unsigned depth,size_t queue_bytes) {
    unsigned char address[16];
    if(!s6_rtc_available() || !bind ||
       (inet_pton(AF_INET,bind,address)!=1 && inet_pton(AF_INET6,bind,address)!=1) ||
       !channels || count<1 || count>MAX_CHANNELS || maximum<1 || maximum>73728 ||
       depth<1 || depth>128 || queue_bytes<maximum || queue_bytes>16777216) return NULL;
    for(unsigned i=0;i<count;i++) {
        const s6_rtc_channel *c=&channels[i];
        if(c->id>63 || c->ordered>1 || c->policy>2 ||
           (!c->policy && c->budget) || (c->policy==1 && c->budget>65535) ||
           (c->policy==2 && (c->budget<1 || c->budget>60000))) return NULL;
        for(unsigned j=0;j<i;j++) if(channels[j].id==c->id) return NULL;
    }
    s6_rtc *t=calloc(1,sizeof *t);if(!t)return NULL;
    t->pc=-1;t->count=count;t->maximum=maximum;t->depth=depth;t->budget=queue_bytes;
    memcpy(t->channels,channels,count*sizeof *channels);
    for(unsigned i=0;i<count;i++)t->dc[i]=-1;
    pthread_mutex_lock(&lock);
    for(t->slot=0;t->slot<MAX_PEERS && peers[t->slot];t->slot++);
    if(t->slot==MAX_PEERS || queue_bytes>TOTAL_QUEUE_BYTES-reserved_bytes){pthread_mutex_unlock(&lock);free(t);return NULL;}
    reserved_bytes+=queue_bytes;peers[t->slot]=t;pthread_mutex_unlock(&lock);
    rtcConfiguration config={0};config.bindAddress=bind;config.disableAutoNegotiation=true;
    config.maxMessageSize=(int)maximum;config.iceServersCount=0;
    int pc=api.rtcCreatePeerConnection(&config);
    pthread_mutex_lock(&lock);t->pc=pc;pthread_mutex_unlock(&lock);
    if(pc<0 || api.rtcSetStateChangeCallback(pc,state) || api.rtcSetIceStateChangeCallback(pc,ice) ||
       api.rtcSetGatheringStateChangeCallback(pc,gathering)) goto failed;
    for(unsigned i=0;i<count;i++) {
        rtcDataChannelInit init={0};init.negotiated=true;init.manualStream=true;
        init.stream=(uint16_t)channels[i].id;init.protocol="s6epe/3";
        init.reliability.unordered=!channels[i].ordered;init.reliability.unreliable=channels[i].policy!=0;
        if(channels[i].policy==1)init.reliability.maxRetransmits=channels[i].budget;
        if(channels[i].policy==2)init.reliability.maxPacketLifeTime=channels[i].budget;
        int dc=api.rtcCreateDataChannelEx(pc,"s6epe",&init);
        pthread_mutex_lock(&lock);t->dc[i]=dc;pthread_mutex_unlock(&lock);
        if(dc<0 || api.rtcSetMessageCallback(dc,message) || api.rtcSetClosedCallback(dc,closed) ||
           api.rtcSetErrorCallback(dc,error) || api.rtcSetBufferedAmountLowThreshold(dc,SEND_BYTES/2) ||
           api.rtcSetBufferedAmountLowCallback(dc,low)) goto failed;
    }
    return t;
failed:s6_rtc_free(t);return NULL;
}
int s6_rtc_local(s6_rtc *t,int offer,char *buffer,size_t capacity) {
    if(!t || !buffer || capacity<1 || capacity>SDP_MAX+1 || (offer!=0 && offer!=1))return -1;
    pthread_mutex_lock(&lock);int failed=t->failed,started=t->started,gathered=t->gathered;
    if(started && t->local_offer!=offer)failed=1;
    if(!started){t->started=1;t->local_offer=offer;}
    pthread_mutex_unlock(&lock);
    if(failed)return -1;
    if(!started && api.rtcSetLocalDescription(t->pc,offer?"offer":"answer"))return -1;
    if(!gathered)return 0;
    int size=api.rtcGetLocalDescription(t->pc,buffer,(int)capacity);
    if(size<=0 || (size_t)size>capacity || buffer[size-1])return -1;
    return size;
}
int s6_rtc_remote(s6_rtc *t,int offer,const char *sdp,size_t size) {
    if(!t || !sdp || size<1 || size>SDP_MAX || memchr(sdp,0,size) || (offer!=0 && offer!=1))return -1;
    pthread_mutex_lock(&lock);
    int allowed=!t->remote_seen && !t->failed && !t->connected;
    if(allowed)t->remote_seen=1;
    pthread_mutex_unlock(&lock);
    if(!allowed)return -1;
    char *copy=malloc(size+1);if(!copy)return -1;memcpy(copy,sdp,size);copy[size]=0;
    int result=api.rtcSetRemoteDescription(t->pc,copy,offer?"offer":"answer");free(copy);
    return result? -1:0;
}
int s6_rtc_open(s6_rtc *t) {
    if(!t)return -1;
    pthread_mutex_lock(&lock);int fail=t->failed || t->dead,ready=t->connected && t->ice;pthread_mutex_unlock(&lock);
    if(fail)return -1;
    if(!ready)return 0;
    for(unsigned i=0;i<t->count;i++)if(!api.rtcIsOpen(t->dc[i]))return 0;
    return 1;
}
static int index_of(s6_rtc *t,unsigned channel) {
    for(unsigned i=0;i<t->count;i++)if(t->channels[i].id==channel)return (int)i;
    return -1;
}
int s6_rtc_send(s6_rtc *t,unsigned channel,int text,const void *data,size_t size) {
    if(!t || !data || size>t->maximum || (text!=0 && text!=1))return -1;
    int i=index_of(t,channel);if(i<0)return -1;
    pthread_mutex_lock(&lock);int failed=t->failed || t->dead || t->closing[i];pthread_mutex_unlock(&lock);
    if(failed || !api.rtcIsOpen(t->dc[i]))return -1;
    int amount=api.rtcGetBufferedAmount(t->dc[i]);int maximum=api.rtcMaxMessageSize(t->dc[i]);
    if(amount<0 || maximum<0 || size>(size_t)maximum)return -1;
    if(size>SEND_BYTES || (size_t)amount>SEND_BYTES-size)return 0;
    const char *message_data=data;char *copy=NULL;
    if(text){if(memchr(data,0,size) || !utf8(data,size))return -1;copy=malloc(size+1);if(!copy)return -1;memcpy(copy,data,size);copy[size]=0;message_data=copy;}
    int result=api.rtcSendMessage(t->dc[i],message_data,text?-1:(int)size);free(copy);
    return result<0?-1:1;
}
int s6_rtc_receive(s6_rtc *t,void *data,size_t capacity,s6_rtc_event *event) {
    if(!t || !data || !event || capacity<t->maximum)return -1;
    memset(event,0,sizeof *event);pthread_mutex_lock(&lock);
    if(t->failed){pthread_mutex_unlock(&lock);return -1;}
    record *r=t->head;if(!r){pthread_mutex_unlock(&lock);return 0;}
    t->head=r->next;if(!t->head)t->tail=NULL;t->queued--;t->bytes-=r->size;
    event->kind=r->kind;event->channel=r->channel;event->text=r->text;event->size=r->size;
    if(r->size)memcpy(data,r->data,r->size);
    memset(r->data,0,r->size);free(r);
    pthread_mutex_unlock(&lock);return 1;
}
int s6_rtc_close_channel(s6_rtc *t,unsigned channel) {
    if(!t)return -1;
    int i=index_of(t,channel);if(i<0)return -1;
    pthread_mutex_lock(&lock);int failed=t->failed,closing=t->closing[i];pthread_mutex_unlock(&lock);
    if(failed)return -1;
    /* Peer reset may complete before its queued callback is consumed by the
       envelope. Repeating a close request is accepted, never completion proof;
       only the actual callback advances the authenticated session lifecycle. */
    if(closing)return 1;
    int buffered=api.rtcGetBufferedAmount(t->dc[i]);if(buffered<0)return -1;if(buffered)return 0;
    /* Calling rtcClose starts the native reset handshake. Only its closed
       callback proves completion. Neither reset nor zero buffered amount is
       evidence of an authenticated envelope close. */
    pthread_mutex_lock(&lock);t->closing[i]=1;pthread_mutex_unlock(&lock);
    return api.rtcClose(t->dc[i])? -1:1;
}
int s6_rtc_buffered(s6_rtc *t) {
    if(!t)return -1;
    int total=0;
    pthread_mutex_lock(&lock);int failed=t->failed;pthread_mutex_unlock(&lock);if(failed)return -1;
    for(unsigned i=0;i<t->count;i++){int amount=api.rtcGetBufferedAmount(t->dc[i]);if(amount<0 || amount>INT_MAX-total)return -1;total+=amount;}return total;
}
int s6_rtc_wait(s6_rtc *t,unsigned timeout_ms) {
    if(!t || timeout_ms>1000)return -1;
    struct timespec until;if(clock_gettime(CLOCK_REALTIME,&until))return -1;
    until.tv_nsec+=(long)timeout_ms*1000000;until.tv_sec+=until.tv_nsec/1000000000;until.tv_nsec%=1000000000;
    pthread_mutex_lock(&lock);int result=0;
    if(!t->failed && !t->head)result=pthread_cond_timedwait(&changed,&lock,&until);
    int failed=t->failed;pthread_mutex_unlock(&lock);return failed || (result && result!=ETIMEDOUT)?-1:0;
}
#else
/* Optional native backend is absent. No RTC capability or successful operation
   is reported; default raw/TLS/SCTP compilation does not require this library. */
int s6_rtc_available(void){return 0;}
s6_rtc *s6_rtc_create(const char *b,const s6_rtc_channel *c,unsigned n,size_t m,unsigned d,size_t q){(void)b;(void)c;(void)n;(void)m;(void)d;(void)q;return NULL;}
int s6_rtc_local(s6_rtc *t,int o,char *b,size_t c){(void)t;(void)o;(void)b;(void)c;return -1;}
int s6_rtc_remote(s6_rtc *t,int o,const char *s,size_t n){(void)t;(void)o;(void)s;(void)n;return -1;}
int s6_rtc_open(s6_rtc *t){(void)t;return -1;}
int s6_rtc_send(s6_rtc *t,unsigned c,int x,const void *d,size_t n){(void)t;(void)c;(void)x;(void)d;(void)n;return -1;}
int s6_rtc_receive(s6_rtc *t,void *d,size_t n,s6_rtc_event *e){(void)t;(void)d;(void)n;(void)e;return -1;}
int s6_rtc_close_channel(s6_rtc *t,unsigned c){(void)t;(void)c;return -1;}
int s6_rtc_buffered(s6_rtc *t){(void)t;return -1;}
int s6_rtc_wait(s6_rtc *t,unsigned m){(void)t;(void)m;return -1;}
void s6_rtc_free(s6_rtc *t){(void)t;}
#endif
