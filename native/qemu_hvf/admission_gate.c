/* Q1 child bootstrap only: no Hypervisor or database calls. */
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

int hermes_hvf_admission_gate(void) {
    struct rlimit disabled = {0, 0}, observed = {1, 1};
    if (setrlimit(RLIMIT_CORE, &disabled) != 0 || getrlimit(RLIMIT_CORE, &observed) != 0 ||
        observed.rlim_cur != 0 || observed.rlim_max != 0) return 2;
    fprintf(stderr, "HERMES_HVF_CORE_LIMIT_V1 pid=%d current=0 maximum=0\n", getpid());
    fflush(stderr);
    const char expected[] = "HERMES_HVF_RELEASE_V1\n";
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return 2;
    size_t i = 0;
    while (i < sizeof(expected) - 1) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 2;
        long remaining_ms = 60000 - (now.tv_sec - start.tv_sec) * 1000 -
                            (now.tv_nsec - start.tv_nsec) / 1000000;
        if (remaining_ms <= 0) return 2;
        struct pollfd input = {STDIN_FILENO, POLLIN, 0};
        int ready = poll(&input, 1, (int)remaining_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready != 1 || !(input.revents & POLLIN)) return 2;
        char byte;
        if (read(STDIN_FILENO, &byte, 1) != 1 || byte != expected[i]) return 2;
        i++;
    }
    return 0;
}
#ifdef HERMES_HVF_GATE_TEST_MAIN
int main(void) {
    int result = hermes_hvf_admission_gate();
    if (result == 0) puts("HERMES_HVF_GATE_TEST_RELEASED_NO_VM");
    return result;
}
#endif
