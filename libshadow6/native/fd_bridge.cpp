#include "../../Core-Cpp/src/json.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif

namespace {
struct Fd {
    int value{-1};
    explicit Fd(int v=-1):value(v) {}
    ~Fd() { if(value>=0) close(value); }
    Fd(const Fd&)=delete;
    Fd& operator=(const Fd&)=delete;
    int release() { int v=value;value=-1;return v; }
};
bool identity(const struct stat &a,const struct stat &b) {
#ifdef __APPLE__
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_mode==b.st_mode && a.st_uid==b.st_uid && a.st_size==b.st_size && a.st_nlink==b.st_nlink &&
      a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec &&
      a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;
#else
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_mode==b.st_mode && a.st_uid==b.st_uid && a.st_size==b.st_size && a.st_nlink==b.st_nlink &&
      a.st_mtim.tv_sec==b.st_mtim.tv_sec && a.st_mtim.tv_nsec==b.st_mtim.tv_nsec &&
      a.st_ctim.tv_sec==b.st_ctim.tv_sec && a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
#endif
}
int attach(const char *service,int *out_fd,char **out_metadata,char *error,size_t error_size,int timeout_ms,int cancel_fd) {
    auto fail=[&](const char *code) { if(error && error_size) std::snprintf(error,error_size,"%s",code);return -1; };
    if(!out_fd || !out_metadata) return fail("InvalidFDControlConfiguration");
    *out_fd=-1;*out_metadata=nullptr;
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout_ms);
    if(cancel_fd>=0) {
        pollfd cancelled{cancel_fd,POLLIN,0};
        if(poll(&cancelled,1,0)<0 || cancelled.revents) return fail("ConnectionCancelled");
    }
    const char *path=std::getenv("SHADOW6_CONTROL_SOCKET"),*token_path=std::getenv("SHADOW6_CONTROL_TOKEN_FILE");
    if(!path || !token_path || !service) return fail("InvalidFDControlConfiguration");
    struct stat parent{},socket_entry{},current{},before{},opened{},after{};
    std::string socket_path(path);
    auto slash=socket_path.find_last_of('/');
    if(slash==std::string::npos || socket_path.empty() || socket_path[0]!='/' || socket_path.size()>=sizeof(sockaddr_un::sun_path) ||
       lstat(socket_path.substr(0,slash).c_str(),&parent) || !S_ISDIR(parent.st_mode) || parent.st_uid!=geteuid() || (parent.st_mode&077) ||
       lstat(path,&socket_entry) || !S_ISSOCK(socket_entry.st_mode) || socket_entry.st_uid!=geteuid() || (socket_entry.st_mode&077)) return fail("UnsafeFDControlSocket");
    if(lstat(token_path,&before) || !S_ISREG(before.st_mode) || before.st_uid!=geteuid() ||
       (before.st_mode&07777)!=0600 || before.st_nlink!=1 || before.st_size<32 || before.st_size>4096) return fail("UnsafeFDControlCredential");
    Fd key(open(token_path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    if(key.value<0) return fail("UnsafeFDControlCredential");
    char token_bytes[4097];ssize_t count=read(key.value,token_bytes,sizeof(token_bytes));
    if(fstat(key.value,&opened) || fstat(key.value,&after) || lstat(token_path,&current) ||
       !identity(before,opened) || !identity(opened,after) || !identity(after,current) || count!=before.st_size) return fail("FDControlCredentialChanged");
    std::string token(token_bytes,static_cast<size_t>(count));
    while(!token.empty() && (token.back()=='\n' || token.back()=='\r')) token.pop_back();
    if(token.size()<32 || !shadow6::ascii(token)) return fail("InvalidFDControlCredential");
    unsigned char random[32];
#ifdef __linux__
    if(getrandom(random,sizeof(random),0)!=sizeof(random)) return fail("NonceUnavailable");
#else
    arc4random_buf(random,sizeof(random));
#endif
    const char *hex="0123456789abcdef";std::string nonce;
    for(unsigned char byte:random) { nonce+=hex[byte>>4];nonce+=hex[byte&15]; }
    shadow6::Json request=shadow6::Json::obj();
    request.object["schema"]=shadow6::Json("shadow6.fd-attachment.v1");
    request.object["nonce"]=shadow6::Json(nonce);request.object["token"]=shadow6::Json(token);
    request.object["name"]=shadow6::Json(service);request.object["issuedAt"]=shadow6::Json(static_cast<std::int64_t>(std::time(nullptr)));
    shadow6::Json confirmed;confirmed.kind=shadow6::Json::Boolean;confirmed.integer=1;request.object["confirmed"]=confirmed;
    std::string wire=shadow6::encode(request);
#ifdef __APPLE__
    constexpr int kind=SOCK_STREAM;
    unsigned size=static_cast<unsigned>(wire.size());
    char prefix[4]={static_cast<char>(size>>24),static_cast<char>(size>>16),static_cast<char>(size>>8),static_cast<char>(size)};
    wire.insert(0,prefix,4);
#else
    constexpr int kind=SOCK_SEQPACKET;
#endif
    Fd channel(socket(AF_UNIX,kind,0));
    if(channel.value<0 || fcntl(channel.value,F_SETFD,FD_CLOEXEC)) return fail("FDControlUnavailable");
    timeval timeout{timeout_ms/1000,(timeout_ms%1000)*1000};
    if(setsockopt(channel.value,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) || setsockopt(channel.value,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) return fail("FDControlUnavailable");
    sockaddr_un address{};address.sun_family=AF_UNIX;std::memcpy(address.sun_path,path,socket_path.size()+1);
    if(connect(channel.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return fail("FDControlUnavailable");
#ifdef __linux__
    ucred credentials{};socklen_t credential_size=sizeof(credentials);
    if(getsockopt(channel.value,SOL_SOCKET,SO_PEERCRED,&credentials,&credential_size) || credentials.uid!=geteuid() || credentials.pid<=1) return fail("FDControlPeerRejected");
#else
    uid_t uid;gid_t gid;
    if(getpeereid(channel.value,&uid,&gid) || uid!=geteuid()) return fail("FDControlPeerRejected");
    int one=1;
#ifdef SO_NOSIGPIPE
    if(setsockopt(channel.value,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))) return fail("FDControlUnavailable");
#else
    (void)one;
#endif
#endif
    if(lstat(path,&current) || !identity(socket_entry,current)) return fail("FDControlSocketChanged");
#ifdef MSG_NOSIGNAL
    constexpr int send_flags=MSG_NOSIGNAL;
#else
    constexpr int send_flags=0;
#endif
    size_t sent=0;
    while(sent<wire.size()) {
        count=send(channel.value,wire.data()+sent,wire.size()-sent,send_flags);
        if(count<=0 || (kind==SOCK_SEQPACKET && static_cast<size_t>(count)!=wire.size())) return fail("FDControlRequestFailed");
        sent+=static_cast<size_t>(count);
    }
    char body[65541];alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int)*4)]{};
    iovec vector{body,sizeof(body)};msghdr message{};message.msg_iov=&vector;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
#ifdef MSG_CMSG_CLOEXEC
    constexpr int receive_flags=MSG_CMSG_CLOEXEC;
#else
    constexpr int receive_flags=0;
#endif
    auto wait_read=[&]() {
        while(std::chrono::steady_clock::now()<deadline) {
            pollfd waits[2]={{channel.value,POLLIN,0},{cancel_fd,POLLIN,0}};
            int ready=poll(waits,cancel_fd>=0?2:1,25);
            if(ready<0 && errno!=EINTR) return -1;
            if(cancel_fd>=0 && waits[1].revents) return -2;
            if(waits[0].revents) return 0;
        }
        return -3;
    };
    int readiness=wait_read();
    if(readiness) return fail(readiness==-2?"ConnectionCancelled":readiness==-3?"ConnectionTimedOut":"FDControlUnavailable");
    count=recvmsg(channel.value,&message,receive_flags);
    Fd received;size_t descriptors=0;
    if(count>=0) for(cmsghdr *header=CMSG_FIRSTHDR(&message);header;header=CMSG_NXTHDR(&message,header)) {
        if(header->cmsg_level!=SOL_SOCKET || header->cmsg_type!=SCM_RIGHTS || header->cmsg_len<CMSG_LEN(0)) continue;
        size_t size=(header->cmsg_len-CMSG_LEN(0))/sizeof(int);
        auto *fds=reinterpret_cast<int*>(CMSG_DATA(header));
        for(size_t i=0;i<size;i++) { descriptors++;if(received.value<0) received.value=fds[i];else close(fds[i]); }
    }
    if(count<=0 || (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))) return fail("InvalidFDControlResponse");
    size_t length=static_cast<size_t>(count),offset=0;
#ifdef __APPLE__
    size_t expected=0;
    while(length<4 || length<expected+4) {
        if(length>=4) {
            expected=(static_cast<unsigned char>(body[0])<<24)|(static_cast<unsigned char>(body[1])<<16)|(static_cast<unsigned char>(body[2])<<8)|static_cast<unsigned char>(body[3]);
            if(expected>65536) return fail("InvalidFDControlResponse");
            if(length>=expected+4) break;
        }
        readiness=wait_read();
        if(readiness) return fail(readiness==-2?"ConnectionCancelled":"ConnectionTimedOut");
        count=recv(channel.value,body+length,sizeof(body)-length,0);
        if(count<=0) return fail("InvalidFDControlResponse");
        length+=static_cast<size_t>(count);
    }
    if(length!=expected+4) return fail("InvalidFDControlResponse");
    offset=4;length-=4;
#endif
    if(length>65536) return fail("InvalidFDControlResponse");
    shadow6::Json response;shadow6::JsonParser parser;
    if(!parser.parse(std::string_view(body+offset,length),response) || response.at("schema").text!="shadow6.fd-attachment.v1" || response.at("nonce").text!=nonce) return fail("InvalidFDControlResponse");
    if(shadow6::schema(response,{{"schema",shadow6::Json::String},{"nonce",shadow6::Json::String},{"error",shadow6::Json::String}})) {
        const auto &code=response.at("error").text;bool safe=!code.empty() && code.size()<96;
        for(char c:code) if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z'))) safe=false;
        return fail(safe?code.c_str():"FDAttachmentRejected");
    }
    const auto &metadata=response.at("connection");
    if(!shadow6::schema(response,{{"schema",shadow6::Json::String},{"nonce",shadow6::Json::String},{"connection",shadow6::Json::Object}}) || descriptors!=1 ||
       metadata.at("schema").text!="shadow6.connection-handle.v1" || metadata.at("name").text!=service || metadata.at("state").text!="connected" ||
       fstat(received.value,&current) || !S_ISSOCK(current.st_mode) || fcntl(received.value,F_SETFD,FD_CLOEXEC)) return fail("InvalidFDControlResponse");
    std::string encoded=shadow6::encode(metadata);
    *out_metadata=strdup(encoded.c_str());
    if(!*out_metadata) return fail("ResourceUnavailable");
    *out_fd=received.release();return 0;
}
}
extern "C" int s6_fd_open(const char *service,int *out_fd,char **out_metadata,char *error,size_t error_size,int timeout_ms,int cancel_fd) {
    try { return attach(service,out_fd,out_metadata,error,error_size,timeout_ms,cancel_fd); }
    catch(...) { if(error && error_size) std::snprintf(error,error_size,"ResourceUnavailable");return -1; }
}
