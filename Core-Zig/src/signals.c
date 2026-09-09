#include <signal.h>

/* Keep libc's function-pointer macros in C: Apple SDK annotations cannot
 * always be translated by Zig. Use the target ABI, never integer sentinels. */
int shadow6_ignore_sigpipe(void) {
    return signal(SIGPIPE, SIG_IGN) == SIG_ERR ? -1 : 0;
}
