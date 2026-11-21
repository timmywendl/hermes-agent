/* Harmless self-process counterexample, not an ES client or VZ observer.
 * A live non-file-backed Mach right need not change either libproc file list.
 * No task port for another process, subscription, VM, or credential is used. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct snapshot {
    struct proc_fdinfo fds[4096];
    struct proc_fileportinfo fileports[4096];
    int fd_bytes;
    int fileport_bytes;
};

static bool snapshot_self(struct snapshot *s) {
    memset(s, 0, sizeof(*s));
    errno = 0;
    s->fd_bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0,
                             s->fds, sizeof(s->fds));
    if (s->fd_bytes <= 0 || errno || s->fd_bytes >= (int)sizeof(s->fds) ||
        s->fd_bytes % sizeof(struct proc_fdinfo)) return false;
    errno = 0;
    s->fileport_bytes = proc_pidinfo(getpid(), PROC_PIDLISTFILEPORTS, 0,
                                   s->fileports, sizeof(s->fileports));
    return s->fileport_bytes >= 0 && !errno &&
           s->fileport_bytes < (int)sizeof(s->fileports) &&
           !(s->fileport_bytes % sizeof(struct proc_fileportinfo));
}

int main(void) {
    struct snapshot before, retained, released, positive;
    mach_port_t port = MACH_PORT_NULL;
    mach_port_urefs_t references = 0;
    if (!snapshot_self(&before)) return 2;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)
        != KERN_SUCCESS) return 2;
    bool made_send = mach_port_insert_right(mach_task_self(), port, port,
                                            MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS;
    bool measured = made_send && snapshot_self(&retained) &&
        mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND,
                           &references) == KERN_SUCCESS;
    kern_return_t dropped_send = made_send ? mach_port_deallocate(mach_task_self(), port) : KERN_SUCCESS;
    kern_return_t dropped_receive = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    if (!measured || dropped_send != KERN_SUCCESS || dropped_receive != KERN_SUCCESS ||
        !snapshot_self(&released)) return 2;
    mach_port_type_t remaining_type = 0;
    bool own_right_released = mach_port_type(mach_task_self(), port, &remaining_type) == KERN_INVALID_NAME;
    bool same_fds = before.fd_bytes == retained.fd_bytes &&
        !memcmp(before.fds, retained.fds, before.fd_bytes);
    bool same_fileports = before.fileport_bytes == retained.fileport_bytes &&
        !memcmp(before.fileports, retained.fileports, before.fileport_bytes);
    bool restored = before.fd_bytes == released.fd_bytes &&
        before.fileport_bytes == released.fileport_bytes &&
        !memcmp(before.fds, released.fds, before.fd_bytes) &&
        !memcmp(before.fileports, released.fileports, before.fileport_bytes);
    int channel[2];
    if (pipe(channel) != 0) return 2;
    bool control_measured = snapshot_self(&positive);
    int closed_read = close(channel[0]);
    int closed_write = close(channel[1]);
    bool saw_pipe = control_measured && closed_read == 0 && closed_write == 0 &&
        positive.fd_bytes == released.fd_bytes + 2 * (int)sizeof(struct proc_fdinfo);
    /* Compile the actual SDK event payload/counters; never start an ES client. */
    es_event_xpc_connect_t event = {0};
    es_message_t message = {0};
    event.service_name.length = 0;
    event.service_domain_type = ES_XPC_DOMAIN_TYPE_USER;
    message.seq_num = 0;
    message.global_seq_num = 0;
    (void)event;
    (void)message;
    printf("{\"self_only\":true,\"same_fd_snapshot\":%s,"
           "\"same_fileport_snapshot\":%s,\"live_mach_send_refs\":%u,"
           "\"restored_snapshots\":%s,\"pipe_positive_control\":%s,"
           "\"own_right_released\":%s,\"per_vm_vz_release\":\"UNKNOWN\","
           "\"native\":\"NOT_RUN\",\"es_client\":\"NOT_CREATED\"}\n",
           same_fds ? "true" : "false", same_fileports ? "true" : "false",
           references, restored ? "true" : "false", saw_pipe ? "true" : "false",
           own_right_released ? "true" : "false");
    return same_fds && same_fileports && references > 0 && restored && saw_pipe && own_right_released ? 0 : 2;
}
