/**
 * libsodium FFI wrapper for Idris 2
 * Provides safe C bindings for cryptographic operations
 */

#include <sodium.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdint.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

/* Initialize libsodium - must be called before any other function */
int idris_sodium_init(void) {
    return sodium_init();
}

/* Securely zero memory */
void idris_sodium_memzero(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
}

/* Ed25519 signature verification */
int idris_ed25519_verify(const unsigned char *sig,
                         const unsigned char *msg,
                         uint64_t msg_len,
                         const unsigned char *pubkey) {
    if (!sig || !msg || !pubkey) return -1;
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pubkey);
}

/* Check if AES-256-GCM is available on this CPU */
int idris_aes256gcm_available(void) {
    return crypto_aead_aes256gcm_is_available();
}

/* AES-256-GCM encryption */
int idris_aes256gcm_encrypt(unsigned char *ciphertext,
                            uint64_t *ciphertext_len,
                            const unsigned char *plaintext,
                            uint64_t plaintext_len,
                            const unsigned char *ad,
                            uint64_t ad_len,
                            const unsigned char *nsec,
                            const unsigned char *nonce,
                            const unsigned char *key) {
    if (!ciphertext || !plaintext || !nonce || !key || plaintext_len > 1048576 ||
        !crypto_aead_aes256gcm_is_available()) return -1;
    
    unsigned long long clen = 0;
    int result = crypto_aead_aes256gcm_encrypt(
        ciphertext, &clen,
        plaintext, plaintext_len,
        ad, ad_len,
        nsec,
        nonce,
        key
    );
    
    if (ciphertext_len) {
        *ciphertext_len = (uint64_t)clen;
    }
    
    return result;
}

/* AES-256-GCM decryption */
int idris_aes256gcm_decrypt(unsigned char *plaintext,
                            uint64_t *plaintext_len,
                            unsigned char *nsec,
                            const unsigned char *ciphertext,
                            uint64_t ciphertext_len,
                            const unsigned char *ad,
                            uint64_t ad_len,
                            const unsigned char *nonce,
                            const unsigned char *key) {
    if (!plaintext || !ciphertext || !nonce || !key || ciphertext_len < 16 ||
        ciphertext_len > 1048592 || !crypto_aead_aes256gcm_is_available()) return -1;
    
    unsigned long long plen = 0;
    int result = crypto_aead_aes256gcm_decrypt(
        plaintext, &plen,
        nsec,
        ciphertext, ciphertext_len,
        ad, ad_len,
        nonce,
        key
    );
    
    if (plaintext_len) {
        *plaintext_len = (uint64_t)plen;
    }
    
    return result;
}

/* SHA-256 hash */
int idris_sha256(unsigned char *out,
                 const unsigned char *in,
                 uint64_t in_len) {
    if (!out || !in) return -1;
    return crypto_hash_sha256(out, in, in_len);
}

/* Generate random bytes */
void idris_random_bytes(unsigned char *buf, size_t size) {
    randombytes_buf(buf, size);
}

/* Constant-time memory comparison */
int idris_memcmp_constant_time(const void *a, const void *b, size_t len) {
    return sodium_memcmp(a, b, len);
}

/* Bounded loopback integration primitive.  It never exposes a non-loopback
 * listener and accepts exactly one length-prefixed frame. */
int idris_loopback_exchange(const unsigned char *request, uint64_t request_len,
                            unsigned char *response, uint64_t response_cap) {
    if (!request || !response || request_len > 1200 || response_cap < request_len) return -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -2;
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int yes = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) || listen(s, 1)) { close(s); return -3; }
    socklen_t alen = sizeof(a); if (getsockname(s, (struct sockaddr*)&a, &alen)) { close(s); return -4; }
    int c = socket(AF_INET, SOCK_STREAM, 0); if (c < 0) { close(s); return -5; }
    if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) ||
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv)) { close(c); close(s); return -5; }
    if (connect(c, (struct sockaddr*)&a, sizeof(a))) { close(c); close(s); return -6; }
    int p = accept(s, NULL, NULL); if (p < 0) { close(c); close(s); return -7; }
    if (setsockopt(p, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) ||
        setsockopt(p, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv)) { close(p); close(c); close(s); return -7; }
    uint32_t n = htonl((uint32_t)request_len); if (send(c, &n, 4, MSG_NOSIGNAL) != 4 || send(c, request, request_len, MSG_NOSIGNAL) != (ssize_t)request_len) { close(p); close(c); close(s); return -8; }
    uint32_t rn = 0; unsigned char frame[1200];
    if (recv(p, &rn, 4, MSG_WAITALL) != 4) { close(p); close(c); close(s); return -9; }
    rn = ntohl(rn); if (rn > sizeof(frame) || recv(p, frame, rn, MSG_WAITALL) != (ssize_t)rn || rn != request_len || memcmp(frame, request, rn) != 0) { close(p); close(c); close(s); return -10; }
    if (send(p, &n, 4, MSG_NOSIGNAL) != 4 || send(p, request, request_len, MSG_NOSIGNAL) != (ssize_t)request_len) { close(p); close(c); close(s); return -11; }
    if (recv(c, &rn, 4, MSG_WAITALL) != 4) { close(p); close(c); close(s); return -12; }
    rn = ntohl(rn); if (rn > response_cap || rn > 1200 || recv(c, response, rn, MSG_WAITALL) != (ssize_t)rn) { close(p); close(c); close(s); return -13; }
    close(p); close(c); close(s); return (int)rn;
}

/* Full cryptographic loopback contract: Ed25519 identity, X25519 agreement,
 * and XChaCha20-Poly1305 data authentication. Returns 0 only when both a
 * valid exchange and rejection of tampered/unknown identity frames succeed. */
int idris_secure_loopback_test(void) {
    unsigned char apk[crypto_sign_PUBLICKEYBYTES], ask[crypto_sign_SECRETKEYBYTES];
    unsigned char bpk[crypto_sign_PUBLICKEYBYTES], bsk[crypto_sign_SECRETKEYBYTES];
    unsigned char msg[32], sig[crypto_sign_BYTES], shared[crypto_scalarmult_BYTES];
    unsigned char ax[32], bx[32], ap[32], bp[32];
    unsigned long long slen = 0;
    if (crypto_sign_keypair(apk, ask) || crypto_sign_keypair(bpk, bsk)) return -1;
    randombytes_buf(msg, sizeof(msg));
    if (crypto_sign_detached(sig, &slen, msg, sizeof(msg), ask) ||
        crypto_sign_verify_detached(sig, msg, sizeof(msg), apk) != 0) return -2;
    sig[0] ^= 1;
    if (crypto_sign_verify_detached(sig, msg, sizeof(msg), apk) == 0) return -3;
    sig[0] ^= 1;
    randombytes_buf(ax, 32); randombytes_buf(bx, 32);
    if (crypto_scalarmult_base(ap, ax) || crypto_scalarmult_base(bp, bx) ||
        crypto_scalarmult(shared, ax, bp) != 0) return -4;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], ct[128], out[128];
    unsigned long long clen = 0, plen = 0; const unsigned char text[] = "shadow6-secure-loopback";
    randombytes_buf(nonce, sizeof(nonce));
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &clen, text, sizeof(text),
        msg, sizeof(msg), NULL, nonce, shared) != 0) return -5;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &plen, NULL, ct, clen,
        msg, sizeof(msg), nonce, shared) != 0 || plen != sizeof(text) || memcmp(out, text, plen)) return -6;
    ct[0] ^= 1;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &plen, NULL, ct, clen,
        msg, sizeof(msg), nonce, shared) == 0) return -7;
    ct[0] ^= 1;
    unsigned char response[128];
    int exchanged = idris_loopback_exchange(ct, clen, response, sizeof response);
    if (exchanged != (int)clen || crypto_aead_xchacha20poly1305_ietf_decrypt(out, &plen, NULL,
        response, clen, msg, sizeof msg, nonce, shared) || plen != sizeof text || memcmp(out, text, plen)) return -8;
    sodium_memzero(ask, sizeof ask); sodium_memzero(bsk, sizeof bsk);
    sodium_memzero(ax, sizeof ax); sodium_memzero(bx, sizeof bx); sodium_memzero(shared, sizeof shared);
    return 0;
}

/* Bounded, loopback-only daemon primitive.  Idris owns policy and parsing;
 * this FFI only supplies socket I/O and never accepts a public bind. */
int idris_daemon_loop(unsigned short port, unsigned int max_packets) {
    if (max_packets == 0 || max_packets > 10000) return -1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) { close(fd); return -1; }
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv)) { close(fd); return -1; }
    struct timespec started, current;
    if (clock_gettime(CLOCK_MONOTONIC, &started)) { close(fd); return -1; }
    unsigned int handled = 0; unsigned char frame[1200];
    while (handled < max_packets) {
        if (clock_gettime(CLOCK_MONOTONIC, &current) || current.tv_sec - started.tv_sec >= 2) break;
        ssize_t n = recv(fd, frame, sizeof frame, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0) { close(fd); return -1; }
        ++handled;
    }
    close(fd); return (int)handled;
}

/* Native Idris agent/client data plane. The C boundary performs only bounded
 * fixed-peer UDP I/O and libsodium framing; Idris owns CLI policy. */
#define IDRIS_NATIVE_MAX 1024u
#define IDRIS_NATIVE_HEADER 34u
#define IDRIS_NATIVE_FRAME (IDRIS_NATIVE_HEADER + IDRIS_NATIVE_MAX + crypto_aead_xchacha20poly1305_ietf_ABYTES)
static void put64(unsigned char *p, uint64_t n) { for (int i=7;i>=0;--i){p[i]=(unsigned char)n;n>>=8;} }
static uint64_t get64(const unsigned char *p) { uint64_t n=0; for(int i=0;i<8;++i)n=(n<<8)|p[i]; return n; }
static int load_native_keys(const char *path, unsigned char *key, size_t length) {
    struct stat a,b; int fd=-1,rc=-1; ssize_t n; unsigned char extra;
    if (!path || !*path || strnlen(path,4096)>=4096) return -1;
    fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0||fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_uid!=geteuid()||(a.st_mode&07777)!=0600||a.st_nlink!=1||a.st_size!=(off_t)length)goto done;
    n=read(fd,key,length); if(n!=(ssize_t)length||read(fd,&extra,1)!=0||fstat(fd,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_size!=b.st_size||a.st_mode!=b.st_mode||a.st_uid!=b.st_uid||a.st_nlink!=b.st_nlink||a.st_mtime!=b.st_mtime||a.st_ctime!=b.st_ctime)goto done;
#if defined(__APPLE__)
    if(a.st_mtimespec.tv_nsec!=b.st_mtimespec.tv_nsec||a.st_ctimespec.tv_nsec!=b.st_ctimespec.tv_nsec)goto done;
#else
    if(a.st_mtim.tv_nsec!=b.st_mtim.tv_nsec||a.st_ctim.tv_nsec!=b.st_ctim.tv_nsec)goto done;
#endif
    rc=0;
done: if(fd>=0)close(fd);if(rc)sodium_memzero(key,length);return rc;
}
static int native_addr(const char *text,unsigned int port,struct sockaddr_in *out,int bind_addr){
    memset(out,0,sizeof *out);out->sin_family=AF_INET;out->sin_port=htons((uint16_t)port);
    if(!text||!port||port>65535||inet_pton(AF_INET,text,&out->sin_addr)!=1)return -1;
    uint32_t host=ntohl(out->sin_addr.s_addr);
    if((!bind_addr&&host==0)||(host&0xf0000000u)==0xe0000000u||host==0xffffffffu)return -1;
    return 0;
}
static int same_addr(const struct sockaddr_in *a,const struct sockaddr_in *b){return a->sin_port==b->sin_port&&a->sin_addr.s_addr==b->sin_addr.s_addr;}
static int native_seal(unsigned char *out,size_t *outn,const unsigned char *plain,size_t n,unsigned char direction,uint64_t seq,const unsigned char session[16],const unsigned char key[32]){
    if(!out||!outn||!plain||!session||!n||n>IDRIS_NATIVE_MAX||!seq||(direction!=1&&direction!=2))return -1;
    memcpy(out,"S6I1",4);out[4]=1;out[5]=direction;out[6]=out[7]=0;put64(out+8,seq);memcpy(out+16,session,16);out[32]=(unsigned char)(n>>8);out[33]=(unsigned char)n;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];unsigned long long clen=0;
    if(crypto_generichash(nonce,sizeof nonce,out,IDRIS_NATIVE_HEADER,key,32)||crypto_aead_xchacha20poly1305_ietf_encrypt(out+IDRIS_NATIVE_HEADER,&clen,plain,n,out,IDRIS_NATIVE_HEADER,NULL,nonce,key))return -1;
    *outn=IDRIS_NATIVE_HEADER+(size_t)clen;return 0;
}
static int native_open(unsigned char *plain,size_t *plainn,const unsigned char *frame,size_t n,unsigned char direction,uint64_t *last,unsigned char session[16],int *session_set,const unsigned char key[32]){
    if(!plain||!plainn||!frame||n<IDRIS_NATIVE_HEADER+crypto_aead_xchacha20poly1305_ietf_ABYTES||n>IDRIS_NATIVE_FRAME||memcmp(frame,"S6I1",4)||frame[4]!=1||frame[5]!=direction||frame[6]||frame[7])return -1;
    uint64_t seq=get64(frame+8);size_t claimed=((size_t)frame[32]<<8)|frame[33];if(!seq||seq<=*last||seq-*last>1024||claimed<1||claimed>IDRIS_NATIVE_MAX||n!=IDRIS_NATIVE_HEADER+claimed+crypto_aead_xchacha20poly1305_ietf_ABYTES||(*session_set&&sodium_memcmp(session,frame+16,16)))return -1;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];unsigned long long outn=0;
    if(crypto_generichash(nonce,sizeof nonce,frame,IDRIS_NATIVE_HEADER,key,32)||crypto_aead_xchacha20poly1305_ietf_decrypt(plain,&outn,NULL,frame+IDRIS_NATIVE_HEADER,n-IDRIS_NATIVE_HEADER,frame,IDRIS_NATIVE_HEADER,nonce,key)||outn!=claimed)return -1;
    if(!*session_set){memcpy(session,frame+16,16);*session_set=1;}*last=seq;*plainn=(size_t)outn;return 0;
}
#define IDRIS_CHAIN_WINDOW 256u
struct idris_pending_packet {
    unsigned char bytes[IDRIS_NATIVE_FRAME];
    size_t length;
    uint64_t sequence;
    int64_t retry_at;
    unsigned int retries;
    int used;
};
struct idris_received_packet {
    unsigned char bytes[IDRIS_NATIVE_MAX];
    size_t length;
    uint64_t sequence;
};
static int native_open_window(unsigned char *plain,size_t *plainn,const unsigned char *frame,size_t n,
                              unsigned char direction,unsigned char session[16],int *session_set,
                              const unsigned char key[32]) {
    if(!plain||!plainn||!frame||n<IDRIS_NATIVE_HEADER+17||n>IDRIS_NATIVE_FRAME||
       memcmp(frame,"S6I2",4)||frame[4]!=2||frame[5]!=direction||frame[6]||frame[7])return -1;
    uint64_t seq=get64(frame+8);size_t claimed=((size_t)frame[32]<<8)|frame[33];
    if(!seq||claimed<1||claimed>IDRIS_NATIVE_MAX||n!=IDRIS_NATIVE_HEADER+claimed+16||
       (*session_set&&sodium_memcmp(session,frame+16,16)))return -1;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];unsigned long long outn=0;
    if(crypto_generichash(nonce,sizeof nonce,frame,IDRIS_NATIVE_HEADER,key,32)||
       crypto_aead_xchacha20poly1305_ietf_decrypt(plain,&outn,NULL,frame+IDRIS_NATIVE_HEADER,n-IDRIS_NATIVE_HEADER,
                                                  frame,IDRIS_NATIVE_HEADER,nonce,key)||outn!=claimed)return -1;
    if(!*session_set){memcpy(session,frame+16,16);*session_set=1;}
    *plainn=(size_t)outn;return 0;
}

static int native_seal_window(unsigned char *out,size_t *outn,const unsigned char *plain,size_t n,
                              unsigned char direction,uint64_t seq,const unsigned char session[16],
                              const unsigned char key[32]) {
    if(!out||!outn||!plain||!session||!seq||!n||n>IDRIS_NATIVE_MAX||
       (direction!=1&&direction!=2))return -1;
    memcpy(out,"S6I2",4);out[4]=2;out[5]=direction;out[6]=0;out[7]=0;
    put64(out+8,seq);memcpy(out+16,session,16);out[32]=(unsigned char)(n>>8);out[33]=(unsigned char)n;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];unsigned long long clen=0;
    if(crypto_generichash(nonce,sizeof nonce,out,IDRIS_NATIVE_HEADER,key,32)||
       crypto_aead_xchacha20poly1305_ietf_encrypt(out+IDRIS_NATIVE_HEADER,&clen,plain,n,
           out,IDRIS_NATIVE_HEADER,NULL,nonce,key)||clen!=n+crypto_aead_xchacha20poly1305_ietf_ABYTES)return -1;
    *outn=IDRIS_NATIVE_HEADER+(size_t)clen;return 0;
}

/* Chain roles use an authenticated ACK with the data sequence in the header.
 * Type 1 is part of AEAD associated data and cannot be mistaken for payload. */
static int native_seal_ack(unsigned char *out,size_t *outn,unsigned char direction,uint64_t seq,const unsigned char session[16],const unsigned char key[32]){
    const unsigned char marker=0;
    if(!out||!outn||!session||!seq||(direction!=1&&direction!=2))return -1;
    memcpy(out,"S6I2",4);out[4]=2;out[5]=direction;out[6]=1;out[7]=0;
    put64(out+8,seq);memcpy(out+16,session,16);out[32]=0;out[33]=1;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];unsigned long long clen=0;
    if(crypto_generichash(nonce,sizeof nonce,out,IDRIS_NATIVE_HEADER,key,32)||
       crypto_aead_xchacha20poly1305_ietf_encrypt(out+IDRIS_NATIVE_HEADER,&clen,&marker,1,out,IDRIS_NATIVE_HEADER,NULL,nonce,key)||clen!=1+crypto_aead_xchacha20poly1305_ietf_ABYTES)return -1;
    *outn=IDRIS_NATIVE_HEADER+(size_t)clen;
    return 0;
}
static int native_open_ack(const unsigned char *frame,size_t n,unsigned char direction,uint64_t seq,
                           unsigned char session[16],int *session_set,const unsigned char key[32]){
    if(n!=IDRIS_NATIVE_HEADER+1+crypto_aead_xchacha20poly1305_ietf_ABYTES||memcmp(frame,"S6I2",4)||frame[4]!=2||frame[5]!=direction||frame[6]!=1||frame[7]||get64(frame+8)!=seq||frame[32]||frame[33]!=1)return -1;
    if(*session_set&&sodium_memcmp(session,frame+16,16))return -1;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES],marker=1;unsigned long long outn=0;
    if(crypto_generichash(nonce,sizeof nonce,frame,IDRIS_NATIVE_HEADER,key,32)||
       crypto_aead_xchacha20poly1305_ietf_decrypt(&marker,&outn,NULL,frame+IDRIS_NATIVE_HEADER,n-IDRIS_NATIVE_HEADER,frame,IDRIS_NATIVE_HEADER,nonce,key)||outn!=1||marker)return -1;
    if(!*session_set){memcpy(session,frame+16,16);*session_set=1;}
    return 0;
}
#include "native_chain.h"

int idris_native_relay(int role,const char *bind_ip,unsigned int bind_port,const char *peer_ip,unsigned int peer_port,const char *target_ip,unsigned int target_port,const char *key_path,unsigned int max_packets){
    if(role<1||role>5||max_packets<1||max_packets>1000000||sodium_init()<0)return -1;
    unsigned char key[32]={0},config[96]={0},plain[IDRIS_NATIVE_MAX+1],frame[IDRIS_NATIVE_FRAME+1],send_session[16],receive_session[16]={0};struct sockaddr_in bind_sa,peer_sa,target_sa,from,app_peer={0};
    if(native_addr(bind_ip,bind_port,&bind_sa,1)||native_addr(peer_ip,peer_port,&peer_sa,0)||native_addr(target_ip,target_port,&target_sa,0)){sodium_memzero(key,sizeof key);return -1;}
    if(role==3)return idris_chain_broker(&bind_sa,&peer_sa,&target_sa,key_path,max_packets);
    int chain=role>=4;
    if(chain){if(load_native_keys(key_path,config,sizeof config))return -1;role-=3;}
    else if(load_native_keys(key_path,key,sizeof key))return -1;
    randombytes_buf(send_session,sizeof send_session);int receive_session_set=0;
    int net=socket(AF_INET,SOCK_DGRAM,0),local=socket(AF_INET,SOCK_DGRAM,0),rc=-1;uint64_t received=0;unsigned int handled=0;socklen_t flen;
    struct idris_pending_packet pending[IDRIS_CHAIN_WINDOW]={0};
    struct idris_received_packet reordered[IDRIS_CHAIN_WINDOW]={0};
    uint64_t sent=0,next_deliver=1;
    unsigned pending_count=0;
    int64_t next_retry_scan=0;
    if(net<0||local<0)goto done;
    struct timeval tv={.tv_sec=0,.tv_usec=100000};
    if(setsockopt(net,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv)||setsockopt(local,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv))goto done;
    if(bind(net,(struct sockaddr*)&bind_sa,sizeof bind_sa))goto done;
    if(chain){
        puts("control ready");fflush(stdout);
        if(idris_chain_exchange(net,&peer_sa,role,config,key))goto done;
    }
    if(role==1){struct sockaddr_in app={0};app.sin_family=AF_INET;app.sin_addr.s_addr=htonl(INADDR_LOOPBACK);app.sin_port=target_sa.sin_port;if(bind(local,(struct sockaddr*)&app,sizeof app))goto done;}
    else if(connect(local,(struct sockaddr*)&target_sa,sizeof target_sa))goto done;
    if(chain){puts("session ready");fflush(stdout);}
    struct timespec activity,now;if(clock_gettime(CLOCK_MONOTONIC,&activity))goto done;
    time_t started=activity.tv_sec;
    for(unsigned attempts=0;handled<max_packets&&attempts<1000000;++attempts){
        if(clock_gettime(CLOCK_MONOTONIC,&now))goto done;
        int64_t milliseconds=(int64_t)now.tv_sec*1000+now.tv_nsec/1000000;
        if(now.tv_sec-activity.tv_sec>=30||now.tv_sec-started>=300)break;
        if(chain&&pending_count&&milliseconds>=next_retry_scan){
            for(unsigned i=0;i<IDRIS_CHAIN_WINDOW;++i)if(pending[i].used&&milliseconds>=pending[i].retry_at){
                if(pending[i].retries++>=8||sendto(net,pending[i].bytes,pending[i].length,0,(struct sockaddr*)&peer_sa,sizeof peer_sa)!=(ssize_t)pending[i].length)goto done;
                pending[i].retry_at=milliseconds+200;
            }
            next_retry_scan=milliseconds+20;
        }
        fd_set set;FD_ZERO(&set);FD_SET(net,&set);
        unsigned next_slot=(unsigned)((sent+1)&(IDRIS_CHAIN_WINDOW-1));
        int can_send=!chain||(pending_count<IDRIS_CHAIN_WINDOW&&!pending[next_slot].used);
        if(can_send)FD_SET(local,&set);
        int top=net>local?net:local;struct timeval wait={.tv_sec=0,.tv_usec=chain?20000:100000};
        int ready=select(top+1,&set,NULL,NULL,&wait);if(ready<0&&errno==EINTR)continue;if(ready<0)goto done;
        if(FD_ISSET(net,&set)){
            flen=sizeof from;ssize_t n=recvfrom(net,frame,sizeof frame,0,(struct sockaddr*)&from,&flen);
            if(n>0&&same_addr(&from,&peer_sa)){
                unsigned char direction=role==1?2:1;
                if(chain&&n>50&&frame[6]==1){
                    uint64_t seq=get64(frame+8);
                    if(native_open_ack(frame,(size_t)n,direction,seq,receive_session,&receive_session_set,key)==0){
                        unsigned slot=(unsigned)(seq&(IDRIS_CHAIN_WINDOW-1));
                        if(pending[slot].used&&pending[slot].sequence==seq){
                            pending[slot].used=0;sodium_memzero(&pending[slot],sizeof pending[slot]);
                            if(!pending_count)goto done;
                            --pending_count;
                            if(role==2)handled++;
                            clock_gettime(CLOCK_MONOTONIC,&activity);
                        }
                    }
                }else if(chain&&n>=IDRIS_NATIVE_HEADER+17&&frame[6]==0){
                    unsigned char decoded[IDRIS_NATIVE_MAX];size_t pn=0;uint64_t seq=get64(frame+8);
                    if(native_open_window(decoded,&pn,frame,(size_t)n,direction,receive_session,&receive_session_set,key)==0){
                        if(seq>=next_deliver&&seq-next_deliver<IDRIS_CHAIN_WINDOW){
                            unsigned slot=(unsigned)(seq&(IDRIS_CHAIN_WINDOW-1));
                            if(reordered[slot].sequence&&reordered[slot].sequence!=seq){sodium_memzero(decoded,sizeof decoded);continue;}
                            if(!reordered[slot].sequence){
                                memcpy(reordered[slot].bytes,decoded,pn);reordered[slot].length=pn;reordered[slot].sequence=seq;
                            }
                            while(reordered[next_deliver&(IDRIS_CHAIN_WINDOW-1)].sequence==next_deliver){
                                struct idris_received_packet *item=&reordered[next_deliver&(IDRIS_CHAIN_WINDOW-1)];
                                int delivered=role==1?
                                    (app_peer.sin_port&&sendto(local,item->bytes,item->length,0,(struct sockaddr*)&app_peer,sizeof app_peer)==(ssize_t)item->length):
                                    send(local,item->bytes,item->length,0)==(ssize_t)item->length;
                                if(!delivered)break;
                                size_t an=0;if(native_seal_ack(frame,&an,direction==1?2:1,next_deliver,send_session,key)||
                                   sendto(net,frame,an,0,(struct sockaddr*)&peer_sa,sizeof peer_sa)!=(ssize_t)an)goto done;
                                if(role==1)handled++;
                                sodium_memzero(item,sizeof *item);next_deliver++;
                                clock_gettime(CLOCK_MONOTONIC,&activity);
                            }
                        }else if(seq<next_deliver){
                            size_t an=0;if(native_seal_ack(frame,&an,direction==1?2:1,seq,send_session,key)||
                               sendto(net,frame,an,0,(struct sockaddr*)&peer_sa,sizeof peer_sa)!=(ssize_t)an)goto done;
                        }
                    }
                    sodium_memzero(decoded,sizeof decoded);
                }else if(!chain){
                    size_t pn=0;
                    if(native_open(plain,&pn,frame,(size_t)n,direction,&received,receive_session,&receive_session_set,key)==0){
                    /* Legacy single-packet mode remains strict and ordered. */
                    pn=((size_t)frame[32]<<8)|frame[33];
                    if(role==1){if(app_peer.sin_port&&sendto(local,plain,pn,0,(struct sockaddr*)&app_peer,sizeof app_peer)==(ssize_t)pn)handled++;}
                    else if(send(local,plain,pn,0)!=(ssize_t)pn)break;
                    clock_gettime(CLOCK_MONOTONIC,&activity);
                    }
                }
            }
        }
        if(FD_ISSET(local,&set)){
            ssize_t n;if(role==1){flen=sizeof from;n=recvfrom(local,plain,sizeof plain,0,(struct sockaddr*)&from,&flen);if(n>0&&n<=IDRIS_NATIVE_MAX&&ntohl(from.sin_addr.s_addr)==INADDR_LOOPBACK&&(!app_peer.sin_port||same_addr(&from,&app_peer)))app_peer=from;else n=-1;}
            else n=recv(local,plain,sizeof plain,0);
            if(n>0){
                if(!chain){size_t wn=0;if(native_seal(frame,&wn,plain,(size_t)n,role==1?1:2,++sent,send_session,key)||sendto(net,frame,wn,0,(struct sockaddr*)&peer_sa,sizeof peer_sa)!=(ssize_t)wn)break;if(role==2)handled++;}
                else{
                    unsigned slot=next_slot;
                    if(!pending[slot].used){size_t wn=0;uint64_t seq=++sent;
                        if(native_seal_window(pending[slot].bytes,&wn,plain,(size_t)n,
                           role==1?1:2,seq,send_session,key))goto done;
                        pending[slot].length=wn;pending[slot].sequence=seq;pending[slot].used=1;
                        if(sendto(net,pending[slot].bytes,wn,0,(struct sockaddr*)&peer_sa,sizeof peer_sa)!=(ssize_t)wn)goto done;
                        if(clock_gettime(CLOCK_MONOTONIC,&now))goto done;
                        pending[slot].retry_at=(int64_t)now.tv_sec*1000+now.tv_nsec/1000000+200;
                        ++pending_count;
                    }
                }
                clock_gettime(CLOCK_MONOTONIC,&activity);
            }
        }
    }
    rc=(int)handled;
done:
    for(unsigned i=0;i<IDRIS_CHAIN_WINDOW;++i)sodium_memzero(&pending[i],sizeof pending[i]);
    for(unsigned i=0;i<IDRIS_CHAIN_WINDOW;++i)sodium_memzero(&reordered[i],sizeof reordered[i]);
    if(net>=0)close(net);
    if(local>=0)close(local);
    sodium_memzero(config,sizeof config);sodium_memzero(key,sizeof key);sodium_memzero(plain,sizeof plain);
    sodium_memzero(send_session,sizeof send_session);sodium_memzero(receive_session,sizeof receive_session);return rc;
}

int idris_native_selftest(void){
    unsigned char key[32],plain[32],out[32],frame[IDRIS_NATIVE_FRAME],send_session[16],receive_session[16]={0};size_t fn=0,on=0;uint64_t last=0;int session_set=0,rc=-1;
    randombytes_buf(key,sizeof key);randombytes_buf(plain,sizeof plain);randombytes_buf(send_session,sizeof send_session);
    if(native_seal(frame,&fn,plain,sizeof plain,1,1,send_session,key)||native_open(out,&on,frame,fn,1,&last,receive_session,&session_set,key)||on!=sizeof plain||sodium_memcmp(out,plain,sizeof plain))goto done;
    if(native_open(out,&on,frame,fn,1,&last,receive_session,&session_set,key)==0||native_open(out,&on,frame,fn,2,&last,receive_session,&session_set,key)==0)goto done;
    frame[fn-1]^=1;last=0;if(native_open(out,&on,frame,fn,1,&last,receive_session,&session_set,key)==0)goto done;
    sodium_memzero(receive_session,sizeof receive_session);session_set=0;
    if(native_seal_window(frame,&fn,plain,sizeof plain,1,7,send_session,key)||
       native_open_window(out,&on,frame,fn,1,receive_session,&session_set,key)||
       on!=sizeof plain||sodium_memcmp(out,plain,sizeof plain))goto done;
    if(native_seal_ack(frame,&fn,2,1,send_session,key)||
       native_open_ack(frame,fn,2,1,receive_session,&session_set,key)||
       native_open_ack(frame,fn,2,2,receive_session,&session_set,key)==0)goto done;
    frame[fn-1]^=1;if(native_open_ack(frame,fn,2,1,receive_session,&session_set,key)==0)goto done;rc=0;
done: sodium_memzero(key,sizeof key);sodium_memzero(plain,sizeof plain);sodium_memzero(out,sizeof out);sodium_memzero(send_session,sizeof send_session);sodium_memzero(receive_session,sizeof receive_session);return rc;
}

#include "security_ffi.c"
