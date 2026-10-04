#define _GNU_SOURCE
/* Native SCTP records, never TCP flattening or Native Core protocol parsing. */
#include "carrier_sctp_native.h"
#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sctp.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <linux/sock_diag.h>

int s6_sctp_available(void) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,IPPROTO_SCTP);
    if (fd<0) return 0;
    close(fd);return 1;
}
struct s6_sctp {
    int fd, failed, ended, pending_dry;
    unsigned incoming, outgoing;
    int partial_reliability;
    size_t maximum, used;
    unsigned char *assembly, *scratch;
    struct sctp_rcvinfo info;
};
static int socket_type(int fd) {
    int type=0, protocol=0; socklen_t n=sizeof type;
    if (getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n) || type!=SOCK_STREAM) return 0;
    n=sizeof protocol;
    return !getsockopt(fd,SOL_SOCKET,SO_PROTOCOL,&protocol,&n) && protocol==IPPROTO_SCTP;
}
int s6_sctp_prepare(int fd, unsigned streams) {
    if (!socket_type(fd) || streams<1 || streams>64) return -1;
    int one=1, zero=0, buffer=524288;
    struct sctp_initmsg init={0};
    init.sinit_num_ostreams=(uint16_t)streams; init.sinit_max_instreams=(uint16_t)streams;
    init.sinit_max_attempts=3; init.sinit_max_init_timeo=3000;
    struct sctp_assoc_value reset={0}; reset.assoc_value=SCTP_ENABLE_RESET_STREAM_REQ;
    struct sctp_assoc_value reconfig={0}; reconfig.assoc_value=1;
    struct sctp_event_subscribe events={0};
    events.sctp_association_event=1; events.sctp_shutdown_event=1;
    events.sctp_partial_delivery_event=1; events.sctp_stream_reset_event=1;
    events.sctp_send_failure_event_event=1;
    if (setsockopt(fd,IPPROTO_SCTP,SCTP_INITMSG,&init,sizeof init) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_RECVRCVINFO,&one,sizeof one) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_FRAGMENT_INTERLEAVE,&zero,sizeof zero) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_NODELAY,&one,sizeof one) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_PR_SUPPORTED,&reconfig,sizeof reconfig) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_RECONFIG_SUPPORTED,&reconfig,sizeof reconfig) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_ENABLE_STREAM_RESET,&reset,sizeof reset) ||
        setsockopt(fd,IPPROTO_SCTP,SCTP_EVENTS,&events,sizeof events) ||
        setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&buffer,sizeof buffer) ||
        setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof buffer)) return -1;
    return 0;
}
s6_sctp *s6_sctp_attach(int fd, size_t maximum) {
    if (!socket_type(fd) || maximum<1 || maximum>131072) return NULL;
    int flags=fcntl(fd,F_GETFL); if (flags<0 || !(flags&O_NONBLOCK)) return NULL;
    struct sctp_status status={0}; socklen_t size=sizeof status;
    if (getsockopt(fd,IPPROTO_SCTP,SCTP_STATUS,&status,&size) || size!=sizeof status ||
        status.sstat_state!=SCTP_ESTABLISHED || !status.sstat_instrms || !status.sstat_outstrms ||
        status.sstat_instrms>64 || status.sstat_outstrms>64) return NULL;
    int enabled=0;size=sizeof enabled;
    if (getsockopt(fd,IPPROTO_SCTP,SCTP_RECVRCVINFO,&enabled,&size) || !enabled) return NULL;
    enabled=0;size=sizeof enabled;
    if (getsockopt(fd,IPPROTO_SCTP,SCTP_FRAGMENT_INTERLEAVE,&enabled,&size) || enabled) return NULL;
    struct sctp_assoc_value pr={0};size=sizeof pr;
    if (getsockopt(fd,IPPROTO_SCTP,SCTP_PR_SUPPORTED,&pr,&size) || size!=sizeof pr) return NULL;
    s6_sctp *t=calloc(1,sizeof *t); if (!t) return NULL;
    t->partial_reliability=pr.assoc_value!=0;
    t->fd=fd;t->maximum=maximum;t->incoming=status.sstat_instrms;t->outgoing=status.sstat_outstrms;
    t->assembly=malloc(maximum);t->scratch=malloc(maximum+256);
    if (!t->assembly || !t->scratch) { s6_sctp_free(t);return NULL; }
    return t;
}
unsigned s6_sctp_stream_limit(s6_sctp *t) { return t?(t->incoming<t->outgoing?t->incoming:t->outgoing):0; }
int s6_sctp_partial_reliability(s6_sctp *t) { return t && t->partial_reliability; }
void s6_sctp_free(s6_sctp *t) {
    if (t) { free(t->assembly);free(t->scratch);free(t); }
}
static int fail(s6_sctp *t) { t->failed=1;return -1; }
int s6_sctp_send(s6_sctp *t, const void *data, size_t size, unsigned stream,
                 int ordered, uint32_t ppid, uint32_t context, int policy, unsigned budget) {
    if (!t || t->failed || t->ended || !data || !size || size>t->maximum || stream>=t->outgoing ||
        (ordered!=0 && ordered!=1) || policy<0 || policy>2 || (policy && !t->partial_reliability) ||
        (policy==0 && budget!=0) || (policy==1 && budget>65535) ||
        (policy==2 && (budget<1 || budget>60000))) return -1;
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct sctp_sndinfo))+CMSG_SPACE(sizeof(struct sctp_prinfo))]; } control={0};
    struct iovec iov={(void *)data,size};
    struct msghdr msg={0};msg.msg_iov=&iov;msg.msg_iovlen=1;
    msg.msg_control=control.bytes;msg.msg_controllen=sizeof control.bytes;
    struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=IPPROTO_SCTP;c->cmsg_type=SCTP_SNDINFO;
    c->cmsg_len=CMSG_LEN(sizeof(struct sctp_sndinfo));
    struct sctp_sndinfo snd={0};snd.snd_sid=(uint16_t)stream;
    snd.snd_context=context;
    snd.snd_flags=ordered?0:SCTP_UNORDERED;snd.snd_ppid=htonl(ppid);memcpy(CMSG_DATA(c),&snd,sizeof snd);
    c=CMSG_NXTHDR(&msg,c);if (!c) return fail(t);
    c->cmsg_level=IPPROTO_SCTP;c->cmsg_type=SCTP_PRINFO;c->cmsg_len=CMSG_LEN(sizeof(struct sctp_prinfo));
    struct sctp_prinfo pr={0};pr.pr_policy=policy==1?SCTP_PR_SCTP_RTX:policy==2?SCTP_PR_SCTP_TTL:SCTP_PR_SCTP_NONE;
    pr.pr_value=budget;memcpy(CMSG_DATA(c),&pr,sizeof pr);
    ssize_t result=sendmsg(t->fd,&msg,MSG_DONTWAIT|MSG_NOSIGNAL);
    if (result<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return 0;
    if (result<0 || (size_t)result!=size) return fail(t);
    t->pending_dry=0;return 1;
}
static int notification(s6_sctp *t, size_t size, s6_sctp_event *event) {
    union sctp_notification *n=(union sctp_notification *)t->scratch;
    if (size<sizeof n->sn_header || n->sn_header.sn_length!=size) return fail(t);
    switch (n->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:
        if (size<sizeof(struct sctp_assoc_change)) return fail(t);
        if (n->sn_assoc_change.sac_state==SCTP_COMM_UP) return 0;
        if (n->sn_assoc_change.sac_state==SCTP_RESTART) {event->kind=5;return 1;}
        if (n->sn_assoc_change.sac_state!=SCTP_COMM_LOST && n->sn_assoc_change.sac_state!=SCTP_SHUTDOWN_COMP &&
            n->sn_assoc_change.sac_state!=SCTP_CANT_STR_ASSOC) return fail(t);
        if (t->used) return fail(t);
        event->kind=4;t->ended=1;return 1;
    case SCTP_SHUTDOWN_EVENT:
        if (size!=sizeof(struct sctp_shutdown_event) || t->used) return fail(t);
        event->kind=3;return 1;
    case SCTP_STREAM_RESET_EVENT: {
        size_t base=sizeof(struct sctp_stream_reset_event);
        if (size<base || (size-base)%2 || (size-base)/2>64) return fail(t);
        unsigned flags=n->sn_strreset_event.strreset_flags;
        if (!flags || flags & ~(SCTP_STREAM_RESET_INCOMING_SSN|SCTP_STREAM_RESET_OUTGOING_SSN|SCTP_STREAM_RESET_DENIED|SCTP_STREAM_RESET_FAILED)) return fail(t);
        event->kind=2;event->reset_flags=flags;event->reset_count=(unsigned)((size-base)/2);
        for (unsigned i=0;i<event->reset_count;i++) {
            unsigned id=n->sn_strreset_event.strreset_stream_list[i];
            if (id>=64) return fail(t);
            event->reset_streams[i]=(uint16_t)id;
        }
        return 1;
    }
    case SCTP_SENDER_DRY_EVENT:
        if (size!=sizeof(struct sctp_sender_dry_event)) return fail(t);
        t->pending_dry=1;return 0;
    case SCTP_SEND_FAILED_EVENT:
        if (size<sizeof(struct sctp_send_failed_event)) return fail(t);
        event->kind=6;event->stream=n->sn_send_failed_event.ssfe_info.snd_sid;
        event->context=n->sn_send_failed_event.ssfe_info.snd_context;
        return 1;
    case SCTP_PARTIAL_DELIVERY_EVENT:
        /* No partial record can become a native message after abandonment. */
        return fail(t);
    default: return fail(t);
    }
}
static int no_event(s6_sctp *t,s6_sctp_event *event) {
    if (t->pending_dry) {
        /* Linux SCTP has no SIOCOUTQ implementation. A queued sender-dry
           notification can predate a later send, so recheck the socket's
           current send allocation after draining earlier failure events.
           One-to-one admission makes this allocation association-specific. */
        uint32_t memory[SK_MEMINFO_VARS]={0};socklen_t size=sizeof memory;
        if (getsockopt(t->fd,SOL_SOCKET,SO_MEMINFO,memory,&size) || size!=sizeof memory) return fail(t);
        if (!memory[SK_MEMINFO_WMEM_ALLOC] && !memory[SK_MEMINFO_WMEM_QUEUED]) {
            t->pending_dry=0;event->kind=7;return 1;
        }
    }
    return 0;
}

int s6_sctp_receive(s6_sctp *t, void *data, size_t capacity, s6_sctp_event *event) {
    if (!t || t->failed || !data || capacity<t->maximum || !event) return -1;
    memset(event,0,sizeof *event);
    if (t->ended) return 0;
    /* Bound ignored setup notifications per call; next poll will retry. */
    for (unsigned attempt=0;attempt<8;attempt++) {
        union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct sctp_rcvinfo))]; } control={0};
        /* SCTP is message-oriented even on a SOCK_STREAM association. Read
           data in bounded fragments; retain metadata until native MSG_EOR. */
        unsigned char probe;
        struct iovec peek_iov={&probe,1};struct msghdr peek={0};
        peek.msg_iov=&peek_iov;peek.msg_iovlen=1;
        ssize_t available=recvmsg(t->fd,&peek,MSG_PEEK|MSG_DONTWAIT);
        if (available<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return no_event(t,event);
        if (available<0) return fail(t);
        size_t fragment=(peek.msg_flags&MSG_NOTIFICATION)?t->maximum+256:16384;
        if (fragment>t->maximum+256) fragment=t->maximum+256;
        struct iovec iov={t->scratch,fragment};struct msghdr msg={0};
        msg.msg_iov=&iov;msg.msg_iovlen=1;msg.msg_control=control.bytes;msg.msg_controllen=sizeof control.bytes;
        ssize_t size=recvmsg(t->fd,&msg,MSG_DONTWAIT);
        if (size<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR)) return no_event(t,event);
        if (size<0 || msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) return fail(t);
        if (!size) {if (t->used) return fail(t);event->kind=4;t->ended=1;return 1;}
        if (msg.msg_flags&MSG_NOTIFICATION) {
            if (!(msg.msg_flags&MSG_EOR)) return fail(t);
            int result=notification(t,(size_t)size,event);if (result) return result;
            continue;
        }
        struct sctp_rcvinfo info={0};int found=0;
        for (struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
            if (c->cmsg_level!=IPPROTO_SCTP || c->cmsg_type!=SCTP_RCVINFO ||
                c->cmsg_len!=CMSG_LEN(sizeof info) || found) return fail(t);
            memcpy(&info,CMSG_DATA(c),sizeof info);found=1;
        }
        if (!found || info.rcv_sid>=t->incoming || info.rcv_flags&~SCTP_UNORDERED ||
            (size_t)size>t->maximum-t->used) return fail(t);
        if (t->used && (info.rcv_sid!=t->info.rcv_sid || info.rcv_ssn!=t->info.rcv_ssn ||
            info.rcv_flags!=t->info.rcv_flags || info.rcv_ppid!=t->info.rcv_ppid)) return fail(t);
        if (!t->used) t->info=info;
        memcpy(t->assembly+t->used,t->scratch,(size_t)size);t->used+=(size_t)size;
        if (!(msg.msg_flags&MSG_EOR)) return 0;
        memcpy(data,t->assembly,t->used);event->kind=1;event->size=t->used;
        event->stream=info.rcv_sid;event->ordered=!(info.rcv_flags&SCTP_UNORDERED);event->ppid=ntohl(info.rcv_ppid);
        t->used=0;return 1;
    }
    return 0;
}
int s6_sctp_watch_sender(s6_sctp *t) {
    if (!t || t->failed || t->ended) return -1;
    struct sctp_event_subscribe events={0};socklen_t size=sizeof events;
    if (getsockopt(t->fd,IPPROTO_SCTP,SCTP_EVENTS,&events,&size)) return fail(t);
    events.sctp_sender_dry_event=1;
    return setsockopt(t->fd,IPPROTO_SCTP,SCTP_EVENTS,&events,sizeof events)?fail(t):0;
}

int s6_sctp_reset(s6_sctp *t, unsigned stream, int incoming, int outgoing) {
    if (!t || t->failed || t->ended || (!incoming && !outgoing) ||
        (incoming && stream>=t->incoming) || (outgoing && stream>=t->outgoing)) return -1;
    union { uint64_t align; unsigned char bytes[sizeof(struct sctp_reset_streams)+sizeof(uint16_t)]; } buffer={0};
    struct sctp_reset_streams *request=(struct sctp_reset_streams *)buffer.bytes;
    request->srs_flags=(incoming?SCTP_STREAM_RESET_INCOMING:0)|(outgoing?SCTP_STREAM_RESET_OUTGOING:0);
    request->srs_number_streams=1;request->srs_stream_list[0]=(uint16_t)stream;
    int result=setsockopt(t->fd,IPPROTO_SCTP,SCTP_RESET_STREAMS,request,sizeof buffer.bytes);
    if (result<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR || errno==EBUSY)) return 0;
    if (result<0) return fail(t);
    return 1;
}

#else
/* This build has no Linux SCTP backend; raw/TLS remain usable. Admission
   explicitly rejects SCTP. No message-provider capability is advertised. */
int s6_sctp_available(void) { return 0; }
int s6_sctp_prepare(int fd,unsigned streams) { (void)fd;(void)streams;return -1; }
s6_sctp *s6_sctp_attach(int fd,size_t maximum) { (void)fd;(void)maximum;return NULL; }
unsigned s6_sctp_stream_limit(s6_sctp *t) { (void)t;return 0; }
int s6_sctp_partial_reliability(s6_sctp *t) { (void)t;return 0; }
void s6_sctp_free(s6_sctp *t) { (void)t; }
int s6_sctp_send(s6_sctp *t,const void *data,size_t size,unsigned stream,int ordered,uint32_t ppid,uint32_t context,int policy,unsigned budget) {
    (void)t;(void)data;(void)size;(void)stream;(void)ordered;(void)ppid;(void)context;(void)policy;(void)budget;return -1;
}
int s6_sctp_receive(s6_sctp *t,void *data,size_t capacity,s6_sctp_event *event) {
    (void)t;(void)data;(void)capacity;(void)event;return -1;
}
int s6_sctp_watch_sender(s6_sctp *t) { (void)t;return -1; }
int s6_sctp_reset(s6_sctp *t,unsigned stream,int incoming,int outgoing) {
    (void)t;(void)stream;(void)incoming;(void)outgoing;return -1;
}
#endif
