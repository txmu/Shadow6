#define _POSIX_C_SOURCE 200809L
#define SHADOW6_QUEUE_TEST
#include "../src/rtc_bridge.c"
#include <assert.h>
#include <stdio.h>

static atomic_int completed;
static void *producer(void *unused) {
    (void)unused;
    for (unsigned i = 4; i < 1000; ++i) message(1, (const char *)&i, sizeof i, NULL);
    atomic_store(&completed, 1);
    return NULL;
}
static void *blocked(void *unused) {
    (void)unused;
    unsigned value = 99;
    message(2, (const char *)&value, sizeof value, NULL);
    return NULL;
}
int main(void) {
    assert(watch(1) == 1);
    assert(nim_rtc_wait(1) == 0); /* empty queue wait is bounded */
    assert(nim_rtc_wait(999) == -1);
    int tcp[2]; assert(!pipe(tcp));
    assert(nim_rtc_wait_io(999,tcp[0],POLLIN)==-1);
    assert(nim_rtc_wait_io(1,tcp[0],POLLIN)==0);
    assert(write(tcp[1],"x",1)==1);
    assert(nim_rtc_wait_io(1,tcp[0],POLLIN)==1);
    char token; assert(read(tcp[0],&token,1)==1);
    assert(nim_rtc_wait_io(1,tcp[1],POLLOUT)==1);
    close(tcp[0]); close(tcp[1]);
    for (unsigned i = 0; i < 4; ++i) message(1, (const char *)&i, sizeof i, NULL);
    assert(nim_rtc_wait(1) == 1); /* do not sleep with queued data */
    assert(nim_rtc_wait_io(1,-1,0)==1);
    pthread_t worker;
    assert(!pthread_create(&worker, NULL, producer, NULL));
    struct timespec pause = {0, 20000000};
    nanosleep(&pause, NULL);
    assert(!atomic_load(&completed));
    for (unsigned expected = 0; expected < 1000; ++expected) {
        unsigned actual = 0; int size = sizeof actual, result;
        do {
            size = sizeof actual;
            result = nim_rtc_receive(1, (char *)&actual, &size);
            if (result == RTC_ERR_NOT_AVAIL) assert(nim_rtc_wait(1) >= 0);
        } while (result == RTC_ERR_NOT_AVAIL);
        assert(result == 0 && size == sizeof actual && actual == expected);
    }
    assert(!pthread_join(worker, NULL));
    nim_rtc_forget(1);
    assert(nim_rtc_wait(1) == -1);
    assert(watch(999) == -1); /* callback registration rolls its slot back */
    assert(watch(2) == 2);
    for (unsigned i = 0; i < 4; ++i) message(2, (const char *)&i, sizeof i, NULL);
    assert(!pthread_create(&worker, NULL, blocked, NULL));
    nanosleep(&pause, NULL);
    nim_rtc_forget(2); /* deletion wakes a blocked callback before joining it */
    assert(watch(2) == 2);
    assert(!pthread_join(worker, NULL));
    unsigned actual; int size = sizeof actual;
    assert(nim_rtc_receive(2, (char *)&actual, &size) == RTC_ERR_NOT_AVAIL);
    assert(nim_rtc_wait(2) == 0); /* reuse must not expose old messages */
    message(2, "", 0, NULL);
    assert(nim_rtc_wait(2) == -1); /* malformed callback fails closed */
    for (int i = 3; i < 22; ++i) assert(watch(i) == i);
    assert(watch(22) == -1); /* fixed global slot bound */
    puts("PASS: 1000 ordered messages, transient backpressure, deletion, slot reuse and bounds");
}
