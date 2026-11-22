#define _GNU_SOURCE
/* Portable boot-frame codec. CODEC_ONLY is consumed by deterministic Host tests;
 * it excludes Linux PID1 and never starts a Guest or Worker. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

struct hermes_boot_state { unsigned seq, last_stage; int disabled; };
struct hermes_boot_io {
    ssize_t (*write_bytes)(int, const void *, size_t);
    int (*writable)(int, int);
    int64_t (*now_ms)(void);
};

int hermes_boot_scope(const char *scope) {
    if (!scope || strnlen(scope, 65) != 64) return 0;
    return strspn(scope, "0123456789abcdef") == 64;
}

size_t hermes_boot_encode(unsigned char *out, size_t capacity, const char *scope,
                          unsigned seq, unsigned milestone, int error, int failed) {
    if (!out || !hermes_boot_scope(scope) || seq < 1 || seq > 16 || milestone < 1 || milestone > 14 ||
            error < 0 || error > 4095 || (failed != 0 && failed != 1) || (!failed && error) || capacity < 5)
        return 0;
    int count = snprintf((char *)out + 4, capacity - 4,
        "{\"boot\":1,\"errno\":%d,\"failed\":%d,\"scope_sha256\":\"%s\",\"seq\":%u,\"stage\":%u}",
        error, failed, scope, seq, milestone);
    if (count < 0 || count > 192 || (size_t)count >= capacity - 4) return 0;
    out[0] = (unsigned)count >> 24; out[1] = (unsigned)count >> 16;
    out[2] = (unsigned)count >> 8; out[3] = (unsigned)count;
    return (size_t)count + 4;
}

int hermes_boot_emit(struct hermes_boot_state *state, const struct hermes_boot_io *io,
                     int fd, const char *scope, unsigned milestone, int error, int failed) {
    unsigned char raw[197];
    if (state->disabled || milestone < state->last_stage ||
            (!failed && milestone != state->last_stage + 1)) return 0;
    size_t size = hermes_boot_encode(raw, sizeof(raw), scope, state->seq + 1, milestone, error, failed);
    if (!size) { state->disabled = 1; return 0; }
    int64_t started = io->now_ms();
    if (started < 0) { state->disabled = 1; return 0; }
    int64_t deadline = started + 10;
    size_t offset = 0;
    unsigned attempts = 0;
    while (offset < size && attempts++ < 256) {
        int64_t now = io->now_ms();
        int64_t left = deadline - now;
        if (now < 0 || left <= 0) break;
        int ready = io->writable(fd, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) break;
        ssize_t count = io->write_bytes(fd, raw + offset, size - offset);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0 || (size_t)count > size - offset) break;
        offset += (size_t)count;
    }
    if (offset != size) { state->disabled = 1; return 0; }
    state->seq++; state->last_stage = milestone;
    if (failed) state->disabled = 1;
    return 1;
}

/* Never last-close the UART during root handoff, even after diagnostic loss.
 * CLOEXEC is enabled only once the original Worker fd3 is already open. */
int hermes_boot_descriptor(int fd, int worker_ready) {
    int flags = fcntl(fd, F_GETFD);
    if (fd < 4 || flags < 0) return 0;
    return fcntl(fd, F_SETFD, worker_ready ? flags | FD_CLOEXEC : flags & ~FD_CLOEXEC) == 0;
}

#ifndef HERMES_BOOT_CODEC_ONLY
/* One-shot Linux image initialization, not an Owner or Worker implementation.
 * The only application exec is the accepted PR16 Guest entry. Not run by build.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/reboot.h>
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#include "q2_policy.h"

static int boot_fd = -1;
static unsigned boot_stage = 1;
static struct hermes_boot_state boot_state;
static const char *boot_scope;

static int64_t boot_now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int boot_writable(int fd, int timeout) {
    struct pollfd p = {fd, POLLOUT, 0};
    int result = poll(&p, 1, timeout);
    if (result <= 0) return result;
    return (p.revents & POLLOUT) && !(p.revents & (POLLERR | POLLHUP | POLLNVAL));
}

static void boot_hint(int failed, int error) {
    int saved = errno;
    const struct hermes_boot_io io = {write, boot_writable, boot_now};
    if (boot_fd >= 0)
        (void)hermes_boot_emit(&boot_state, &io, boot_fd, boot_scope, boot_stage,
                               error >= 0 && error <= 4095 ? error : 0, failed);
    errno = saved;
}

static void boot_prepare(void) {
    boot_scope = getenv("HERMES_Q2_SCOPE_SHA256");
    const char *prior = getenv("HERMES_Q2_BOOT_SEQ");
    const char *off = getenv("HERMES_Q2_BOOT_OFF");
    if (!hermes_boot_scope(boot_scope) || (off && strcmp(off, "0"))) boot_state.disabled = 1;
    if (prior) {
        char *end;
        unsigned long count = strtoul(prior, &end, 10);
        if (*end || count > 7 || (!boot_state.disabled && count != 7)) boot_state.disabled = 1;
        else boot_state.seq = boot_state.last_stage = (unsigned)count;
    }
    if (prior) {
        const char *text = getenv("HERMES_Q2_BOOT_FD");
        char *end;
        long inherited = text ? strtol(text, &end, 10) : -1;
        struct stat info;
        int flags = inherited >= 4 && inherited <= 1023 ? fcntl((int)inherited, F_GETFL) : -1;
        if (!text || *end || inherited < 4 || inherited > 1023 ||
                fstat((int)inherited, &info) || !S_ISCHR(info.st_mode) ||
                major(info.st_rdev) != 204 || minor(info.st_rdev) != 64 ||
                flags < 0 || !(flags & O_NONBLOCK)) {
            boot_state.disabled = 1; return;
        }
        boot_fd = (int)inherited;
    } else {
        if (boot_state.disabled) return;
        int original = open("/dev/ttyAMA0", O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
        if (original < 0) { boot_state.disabled = 1; return; }
        /* Keep this one open file description across root exec: last-close can
         * discard queued UART bytes. fd3 is reserved for the original Worker. */
        boot_fd = fcntl(original, F_DUPFD, 4);
        close(original);
    }
    if (boot_state.disabled) return;  /* adopted fd still has a known lifetime */
    struct termios raw;
    if (boot_fd < 0 || tcgetattr(boot_fd, &raw)) { boot_state.disabled = 1; return; }
    cfmakeraw(&raw);
    raw.c_cflag |= CLOCAL | CREAD;
    if (tcsetattr(boot_fd, TCSANOW, &raw)) { boot_state.disabled = 1; return; }
    boot_stage = prior ? 8 : 1;
    boot_hint(0, 0);
}

static void boot_start(void) {
    int saved = errno;
    boot_prepare();
    errno = saved;
}

static int stage = Q2_STAGE_ROOT_TRANSITION, diagnostic_enabled = 0, developer = 0;
struct diagnostic { int stage, error, exception, exit_code, signal; };

static int diagnostic_directory(void) {
    int task = open("/task", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (task < 0) return -1;
    int fd = openat(task, ".hermes-q2-startup-v1",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(task);
    struct stat info;
    if (fd >= 0 && (fstat(fd, &info) || info.st_uid != Q2_UID ||
                    info.st_gid != Q2_GID || (info.st_mode & 07777) != 0700)) {
        close(fd); fd = -1;
    }
    return fd;
}

static int encode_diagnostic(char *raw, size_t size, struct diagnostic d) {
    return snprintf(raw, size,
        "{\"errno\":%d,\"exception\":%d,\"exit_code\":%d,\"signal\":%d,\"stage\":%d,\"version\":1}\n",
        d.error, d.exception, d.exit_code, d.signal, d.stage);
}

static int save_diagnostic(struct diagnostic d) {
    if (!diagnostic_enabled) return -1;
    char raw[160];
    int length = encode_diagnostic(raw, sizeof(raw), d);
    if (length < 0 || (size_t)length >= sizeof(raw)) return -1;
    int dir = diagnostic_directory();
    if (dir < 0) return -1;
    int fd = openat(dir, ".pending", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int result = -1;
    if (fd >= 0) {
        int owned = geteuid() != 0 || fchown(fd, Q2_UID, Q2_GID) == 0;
        if (owned && write(fd, raw, length) == length && fsync(fd) == 0) result = 0;
        if (close(fd) != 0) result = -1;
        if (result == 0 && renameat(dir, ".pending", dir, "receipt.json") != 0) result = -1;
        if (result == 0 && fsync(dir) != 0) result = -1;
    }
    close(dir);
    return result;
}

static int number(char **cursor, const char *prefix, int *value) {
    size_t size = strlen(prefix);
    if (strncmp(*cursor, prefix, size)) return -1;
    char *start = *cursor + size, *end;
    errno = 0;
    long parsed = strtol(start, &end, 10);
    if (errno || end == start || parsed < INT_MIN || parsed > INT_MAX) return -1;
    *value = (int)parsed;
    *cursor = end;
    return 0;
}

static int decode_diagnostic(char *raw, int length, struct diagnostic *out) {
    struct diagnostic d;
    char *cursor = raw, canonical[160];
    if (number(&cursor, "{\"errno\":", &d.error) ||
            number(&cursor, ",\"exception\":", &d.exception) ||
            number(&cursor, ",\"exit_code\":", &d.exit_code) ||
            number(&cursor, ",\"signal\":", &d.signal) ||
            number(&cursor, ",\"stage\":", &d.stage) ||
            strcmp(cursor, ",\"version\":1}\n") ||
            d.stage < Q2_STAGE_ROOT_TRANSITION || d.stage > Q2_STAGE_INVALID_DIAGNOSTIC ||
            d.error < 0 || d.error > 4095 || d.exception < 0 || d.exception > 8 ||
            d.exit_code != -1 || d.signal != 0 ||
            encode_diagnostic(canonical, sizeof(canonical), d) != length ||
            memcmp(raw, canonical, length)) return -1;
    *out = d;
    return 0;
}

static int read_diagnostic(struct diagnostic *d) {
    int dir = diagnostic_directory();
    if (dir < 0) return -1;
    int fd = openat(dir, "receipt.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int error = errno;
    close(dir);
    if (fd < 0) return error == ENOENT ? 1 : -1;
    struct stat info;
    char raw[160] = {0};
    int length = -1;
    if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
            info.st_uid == Q2_UID && info.st_gid == Q2_GID &&
            (info.st_mode & 0777) == 0600 && info.st_size > 0 && info.st_size < 160)
        length = read(fd, raw, sizeof(raw) - 1);
    close(fd);
    return length > 0 ? decode_diagnostic(raw, length, d) : -1;
}

static void fail(const char *operation) {
    int error = errno;
    boot_hint(1, error);
    struct diagnostic d = {stage, error >= 0 && error <= 4095 ? error : 0, 0, -1, 0};
    (void)save_diagnostic(d);
    dprintf(2, "Q2_INIT_FAILURE:%s:%d\n", operation, error);
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    _exit(111);
}

static void checked_mount(const char *source, const char *target, const char *type,
                          unsigned long flags, const char *options) {
    if (mount(source, target, type, flags, options) != 0) fail(target);
}

static void load_module(const char *name) {
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail(name);
    if (syscall(SYS_finit_module, fd, "", 0) != 0 && errno != EEXIST) fail(name);
    if (close(fd) != 0) fail("module_close");
}

static void root_transition(void) {
    boot_stage = 2;
    checked_mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
    boot_hint(0, 0); boot_stage = 3;
    checked_mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
    boot_hint(0, 0); boot_stage = 4;
    checked_mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
    boot_hint(0, 0); boot_stage = 5;
    /* virtio PCI is built into the exact Debian kernel. No NIC/vsock modules. */
    const char *modules[] = {"/modules/virtio_blk.ko", "/modules/crc16.ko",
                            "/modules/mbcache.ko", "/modules/jbd2.ko", "/modules/ext4.ko"};
    for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) load_module(modules[i]);
    boot_hint(0, 0); boot_stage = 6;
    int ready = 0;
    for (int i = 0; i < 100; ++i) {
        if (access("/dev/vda", F_OK) == 0) { ready = 1; break; }
        usleep(100000);
    }
    if (!ready) fail("root_device_timeout");
    boot_hint(0, 0); boot_stage = 7;
    checked_mount("/dev/vda", "/newroot", "ext4", MS_RDONLY | MS_NOSUID, "");
    boot_hint(0, 0); boot_stage = 8;
    checked_mount("/dev", "/newroot/dev", NULL, MS_MOVE, NULL);
    checked_mount("/proc", "/newroot/proc", NULL, MS_MOVE, NULL);
    checked_mount("/sys", "/newroot/sys", NULL, MS_MOVE, NULL);
    if (chdir("/newroot") != 0) fail("newroot_chdir");
    checked_mount(".", "/", NULL, MS_MOVE, NULL);
    if (chroot(".") != 0 || chdir("/") != 0) fail("root_chroot");
    char sequence[32], disabled[32], scope[96], descriptor[32];
    if (boot_fd >= 0 && !hermes_boot_descriptor(boot_fd, 0)) boot_state.disabled = 1;
    snprintf(sequence, sizeof(sequence), "HERMES_Q2_BOOT_SEQ=%u", boot_state.seq);
    snprintf(disabled, sizeof(disabled), "HERMES_Q2_BOOT_OFF=%d", boot_state.disabled);
    snprintf(scope, sizeof(scope), "HERMES_Q2_SCOPE_SHA256=%s", boot_scope ? boot_scope : "");
    snprintf(descriptor, sizeof(descriptor), "HERMES_Q2_BOOT_FD=%d", boot_fd);
    char *const env[] = {sequence, disabled, scope, descriptor, NULL};
    execle("/sbin/q2-init", "q2-init", (char *)NULL, env);
    fail("root_init_exec");
}

static void mount_private_storage(void) {
    boot_stage = 9;
    stage = Q2_STAGE_MOUNTS;
    unsigned long flags = MS_NOSUID | MS_NODEV;
    checked_mount("tmpfs", "/run", "tmpfs", flags, Q2_RUN_OPTIONS);
    checked_mount("tmpfs", "/tmp", "tmpfs", flags, Q2_TMP_OPTIONS);
    checked_mount("tmpfs", "/home/guest", "tmpfs", flags, Q2_HOME_OPTIONS);
    if (mkdir("/run/outbox", 0700) != 0 || mkdir("/run/log", 0700) != 0 ||
        mkdir("/run/hermes", 0700) != 0 || chown("/run/hermes", Q2_UID, Q2_GID) != 0) fail("runtime_dirs");
    checked_mount("tmpfs", "/run/outbox", "tmpfs", flags, Q2_OUTBOX_OPTIONS);
    checked_mount("tmpfs", "/run/log", "tmpfs", flags, Q2_LOG_OPTIONS);
    boot_hint(0, 0); boot_stage = 10;
    checked_mount("/dev/vdc", "/assignment", "ext4", flags | MS_RDONLY, "");
    int fd = open("/assignment/policy", O_RDONLY | O_CLOEXEC);
    char role[32] = {0};
    if (fd < 0) fail("role_open");
    ssize_t size = read(fd, role, sizeof(role));
    if (close(fd) != 0) fail("role_close");
    if (size == 9 && memcmp(role, "reviewer\n", 9) == 0) flags |= MS_RDONLY;
    else if (size != 10 || memcmp(role, "developer\n", 10) != 0) fail("role_policy");
    else developer = 1;
    boot_hint(0, 0); boot_stage = 11;
    checked_mount("/dev/vdb", "/task", "ext4", flags, "");
    boot_hint(0, 0); boot_stage = 12;
    stage = Q2_STAGE_TASK_MOUNTED;
    if (developer) {
        /* The offline image owns bootstrap. A directory-creation failure must
         * not be a prerequisite for enabling its own failure recorder. */
        int diagnostic = diagnostic_directory();
        if (diagnostic < 0) fail("diagnostic_directory");
        diagnostic_enabled = 1;
        if (close(diagnostic) != 0) fail("diagnostic_directory_close");
    }
}

static void bounded_unprivileged_exec(void) {
    boot_stage = 13;
    /* initramfs need not have supplied console descriptors. Reserve stdio first
     * so duplicating stdin cannot accidentally overwrite the log descriptor. */
    int null = open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, 0) != 0 || dup2(null, 1) != 1 || dup2(null, 2) != 2) fail("null_stdio");
    if (null > 2 && close(null) != 0) fail("null_close");
    stage = Q2_STAGE_UART;
    int serial = open("/dev/ttyAMA0", O_RDWR | O_NOCTTY);
    if (serial < 0) fail("serial_open");
    if (serial != 3) {
        if (dup2(serial, 3) != 3 || close(serial) != 0) fail("serial_fd");
    }
    /* The normal RPC fd3 is now open, so closing boot_fd at Python exec
     * cannot be the UART's last-close. No diagnostic fd reaches the Worker. */
    if (boot_fd >= 0 && !hermes_boot_descriptor(boot_fd, 1)) {
        close(boot_fd); boot_fd = -1; boot_state.disabled = 1;
    }
    int output = open("/run/log/worker.log", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int input = open("/dev/null", O_RDONLY);
    if (output < 0 || input < 0 || dup2(input, 0) != 0 ||
        dup2(output, 1) != 1 || dup2(output, 2) != 2) fail("stdio");
    for (int fd = 4; fd < 1024; ++fd) if (fd != boot_fd) close(fd);
    stage = Q2_STAGE_LIMITS;
    struct rlimit core = {Q2_CORE_LIMIT, Q2_CORE_LIMIT}, fds = {Q2_FDS_LIMIT, Q2_FDS_LIMIT};
    struct rlimit processes = {Q2_PROCESSES_LIMIT, Q2_PROCESSES_LIMIT};
    struct rlimit file = {Q2_FILE_LIMIT, Q2_FILE_LIMIT};
    if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_NOFILE, &fds) ||
        setrlimit(RLIMIT_NPROC, &processes) || setrlimit(RLIMIT_FSIZE, &file)) fail("rlimit");
    for (int cap = 0; cap <= 40; ++cap)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) fail("cap_drop");
    stage = Q2_STAGE_IDENTITY;
    if (setgroups(0, NULL) || setgid(Q2_GID) || setuid(Q2_UID) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("unprivileged_identity");
    boot_hint(0, 0);
    stage = Q2_STAGE_TASK_CWD;
    if (chdir("/task") != 0) fail("task_chdir");
    char *const env[] = {"PATH=/opt/python/bin:/usr/bin:/bin", "HOME=/home/guest", "TMPDIR=/tmp",
        "PYTHONPATH=/opt/hermes", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1",
        "HERMES_HOME=/run/hermes", "HERMES_RUNTIME_DIR=/run/hermes/runtime", "LANG=C.UTF-8", NULL};
    char *const args[] = {"/opt/python/bin/python3", "/sbin/q2-startup.py",
        "--serial-fd", "3", "--assignment", "/assignment/work.json",
        "--outbox", "/run/outbox", NULL};
    stage = Q2_STAGE_PYTHON_EXEC;
    boot_stage = 14; boot_hint(0, 0);
    execve(args[0], args, env);
    fail("accepted_guest_entry_exec");
}

int main(void) {
    if (getpid() != 1 || geteuid() != 0) return 111;
    boot_start();
    if (access("/sbin/q2-init", X_OK) != 0) root_transition();
    mount_private_storage();
    boot_hint(0, 0);
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (child == 0) bounded_unprivileged_exec();
    boot_state.disabled = 1;
    if (boot_fd >= 0) close(boot_fd);
    int status = 0;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) fail("worker_wait");
    if (diagnostic_enabled) {
        struct diagnostic d = {Q2_STAGE_CHILD_EXIT, 0, 0, -1, 0};
        if (read_diagnostic(&d) < 0) d.stage = Q2_STAGE_INVALID_DIAGNOSTIC;
        d.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        d.signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        (void)save_diagnostic(d);
    }
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    return 111;
}

#endif /* HERMES_BOOT_CODEC_ONLY */
