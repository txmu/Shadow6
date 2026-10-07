#include "shadow6.h"
#include <stdio.h>
#include <stdlib.h>
/* A third-party application owns its socket event loop, framing and protocol. */
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr,"usage: %s NAMED_SERVICE\n",argv[0]); return 2; }
    s6_connection *connection=NULL; s6_error error;
    if (s6_connection_open(S6_APPLICATION_ABI_V1,argv[1],&connection,&error)) {
        fprintf(stderr,"connect: %s\n",error.code); return 1;
    }
    size_t size=0;
    s6_connection_descriptor(connection,NULL,0,&size);
    char *descriptor=malloc(size);
    if (!descriptor) { s6_connection_destroy(connection); return 1; }
    if (s6_connection_descriptor(connection,descriptor,size,&size)) {
        free(descriptor); s6_connection_destroy(connection); return 1;
    }
    printf("%s\nApplication socket fd: %d\n",descriptor,s6_connection_fd(connection));
    /* Register the fd with poll/epoll and use recv/send directly. Consult the
     * descriptor semantics before framing data. There are no Core branches. */
    free(descriptor); s6_connection_destroy(connection); return 0;
}
