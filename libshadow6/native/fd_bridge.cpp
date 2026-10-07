#include "../../Core-Cpp/src/json.hpp"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" int s6_fd_open(const char *service, int *out_fd, char **out_metadata, char *error, size_t error_size) {
    const char *path = std::getenv("SHADOW6_CONTROL_SOCKET");
    const char *token_path = std::getenv("SHADOW6_CONTROL_TOKEN_FILE");
    if (!path) return 1; // The caller may use the compatible CLI facade.
    auto fail = [&](const char *code) { if (error && error_size) std::snprintf(error,error_size,"%s",code); return -1; };
    if (!token_path || !service || !out_fd || !out_metadata) return fail("InvalidFDControlConfiguration");
    *out_fd=-1;*out_metadata=nullptr;
    struct stat parent{},entry{},before{},opened{},after{};
    std::string socket_path(path);
    auto slash = socket_path.find_last_of('/');
    if (slash==std::string::npos || socket_path.empty() || socket_path[0]!='/' || socket_path.size()>=sizeof(sockaddr_un::sun_path) ||
        lstat(socket_path.substr(0,slash).c_str(),&parent) || !S_ISDIR(parent.st_mode) || parent.st_uid!=geteuid() || (parent.st_mode&077) ||
        lstat(path,&entry) || !S_ISSOCK(entry.st_mode) || entry.st_uid!=geteuid() || (entry.st_mode&077)) return fail("UnsafeFDControlSocket");
    if (lstat(token_path,&before) || !S_ISREG(before.st_mode) || before.st_uid!=geteuid() ||
        (before.st_mode&07777)!=0600 || before.st_nlink!=1 || before.st_size<32 || before.st_size>4096) return fail("UnsafeFDControlCredential");
    int key_fd=open(token_path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (key_fd<0) return fail("UnsafeFDControlCredential");
    char token_bytes[4097];ssize_t count=read(key_fd,token_bytes,sizeof(token_bytes));
    bool stable = !fstat(key_fd,&opened) && !fstat(key_fd,&after) && !lstat(token_path,&entry) &&
        opened.st_dev==before.st_dev && opened.st_ino==before.st_ino && opened.st_mode==before.st_mode &&
        opened.st_uid==before.st_uid && opened.st_size==before.st_size && opened.st_nlink==1 &&
        after.st_mtim.tv_sec==before.st_mtim.tv_sec && after.st_mtim.tv_nsec==before.st_mtim.tv_nsec &&
        after.st_ctim.tv_sec==before.st_ctim.tv_sec && after.st_ctim.tv_nsec==before.st_ctim.tv_nsec &&
        entry.st_dev==before.st_dev && entry.st_ino==before.st_ino;
    close(key_fd);
    if (!stable || count!=before.st_size || count>4096) return fail("FDControlCredentialChanged");
    std::string token(token_bytes,static_cast<size_t>(count));
    while (!token.empty() && (token.back()=='\n' || token.back()=='\r')) token.pop_back();
    if (token.size()<32 || !shadow6::ascii(token)) return fail("InvalidFDControlCredential");
    unsigned char nonce_bytes[32];
    if (getrandom(nonce_bytes,sizeof(nonce_bytes),0)!=sizeof(nonce_bytes)) return fail("NonceUnavailable");
    const char *hex="0123456789abcdef";std::string nonce;
    for (unsigned char byte:nonce_bytes) { nonce+=hex[byte>>4];nonce+=hex[byte&15]; }
    shadow6::Json request=shadow6::Json::obj();
    request.object["schema"]=shadow6::Json("shadow6.fd-attachment.v1");
    request.object["nonce"]=shadow6::Json(nonce);request.object["token"]=shadow6::Json(token);
    request.object["name"]=shadow6::Json(service);
    shadow6::Json confirmed;confirmed.kind=shadow6::Json::Boolean;confirmed.integer=1;request.object["confirmed"]=confirmed;
    std::string wire=shadow6::encode(request);
    int channel=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if (channel<0) return fail("FDControlUnavailable");
    timeval timeout{30,0};setsockopt(channel,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(channel,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    sockaddr_un address{};address.sun_family=AF_UNIX;std::memcpy(address.sun_path,path,socket_path.size()+1);
    if (connect(channel,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { close(channel);return fail("FDControlUnavailable"); }
    ucred credentials{};socklen_t credential_size=sizeof(credentials);
    if (getsockopt(channel,SOL_SOCKET,SO_PEERCRED,&credentials,&credential_size) || credentials.uid!=geteuid() || credentials.pid<=1) {
        close(channel);return fail("FDControlPeerRejected");
    }
    if (send(channel,wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) { close(channel);return fail("FDControlRequestFailed"); }
    char body[65537];char control[CMSG_SPACE(sizeof(int)*4)]{};
    iovec vector{body,sizeof(body)};msghdr message{};message.msg_iov=&vector;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);
    count=recvmsg(channel,&message,MSG_CMSG_CLOEXEC);close(channel);
    int received=-1;size_t descriptors=0;
    if (count>=0) for (cmsghdr *header=CMSG_FIRSTHDR(&message);header;header=CMSG_NXTHDR(&message,header)) {
        if (header->cmsg_level!=SOL_SOCKET || header->cmsg_type!=SCM_RIGHTS || header->cmsg_len<CMSG_LEN(0)) continue;
        size_t size=(header->cmsg_len-CMSG_LEN(0))/sizeof(int);
        auto *fds=reinterpret_cast<int*>(CMSG_DATA(header));
        for (size_t i=0;i<size;i++) { descriptors++;if (received<0) received=fds[i];else close(fds[i]); }
    }
    auto reject = [&](const char *code) { if (received>=0) close(received);return fail(code); };
    if (count<=0 || count>65536 || (message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))) return reject("InvalidFDControlResponse");
    shadow6::Json response;shadow6::JsonParser parser;
    if (!parser.parse(std::string_view(body,static_cast<size_t>(count)),response) || response.at("schema").text!="shadow6.fd-attachment.v1" || response.at("nonce").text!=nonce) return reject("InvalidFDControlResponse");
    if (shadow6::schema(response,{{"schema",shadow6::Json::String},{"nonce",shadow6::Json::String},{"error",shadow6::Json::String}})) {
        const auto &code=response.at("error").text;
        bool safe=!code.empty() && code.size()<96;
        for (char c:code) if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z'))) safe=false;
        return reject(safe ? code.c_str() : "FDAttachmentRejected");
    }
    if (!shadow6::schema(response,{{"schema",shadow6::Json::String},{"nonce",shadow6::Json::String},{"connection",shadow6::Json::Object}}) || descriptors!=1 ||
        response.at("connection").at("schema").text!="shadow6.connection-handle.v1" || fstat(received,&entry) || !S_ISSOCK(entry.st_mode)) return reject("InvalidFDControlResponse");
    std::string metadata=shadow6::encode(response.at("connection"));
    *out_metadata=strdup(metadata.c_str());
    if (!*out_metadata) return reject("ResourceUnavailable");
    *out_fd=received;return 0;
}
