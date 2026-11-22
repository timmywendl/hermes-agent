/* One-shot Linux image initialization, not an Owner or Worker implementation.
 * The only application exec is the accepted PR16 Guest entry. Not run by build.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/reboot.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "q2_policy.h"

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
    struct diagnostic d = {stage, error >= 0 && error <= 4095 ? error : 0, 0, -1, 0};
    (void)save_diagnostic(d);
    dprintf(2, "Q2_INIT_FAILURE:%s:%d\n", operation, errno);
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
    checked_mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
    checked_mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "");
    checked_mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
    /* virtio PCI is built into the exact Debian kernel. No NIC/vsock modules. */
    const char *modules[] = {"/modules/virtio_blk.ko", "/modules/crc16.ko",
                            "/modules/mbcache.ko", "/modules/jbd2.ko", "/modules/ext4.ko"};
    for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i) load_module(modules[i]);
    int ready = 0;
    for (int i = 0; i < 100; ++i) {
        if (access("/dev/vda", F_OK) == 0) { ready = 1; break; }
        usleep(100000);
    }
    if (!ready) fail("root_device_timeout");
    checked_mount("/dev/vda", "/newroot", "ext4", MS_RDONLY | MS_NOSUID, "");
    checked_mount("/dev", "/newroot/dev", NULL, MS_MOVE, NULL);
    checked_mount("/proc", "/newroot/proc", NULL, MS_MOVE, NULL);
    checked_mount("/sys", "/newroot/sys", NULL, MS_MOVE, NULL);
    if (chdir("/newroot") != 0) fail("newroot_chdir");
    checked_mount(".", "/", NULL, MS_MOVE, NULL);
    if (chroot(".") != 0 || chdir("/") != 0) fail("root_chroot");
    execl("/sbin/q2-init", "q2-init", (char *)NULL);
    fail("root_init_exec");
}

static void mount_private_storage(void) {
    stage = Q2_STAGE_MOUNTS;
    unsigned long flags = MS_NOSUID | MS_NODEV;
    checked_mount("tmpfs", "/run", "tmpfs", flags, Q2_RUN_OPTIONS);
    checked_mount("tmpfs", "/tmp", "tmpfs", flags, Q2_TMP_OPTIONS);
    checked_mount("tmpfs", "/home/guest", "tmpfs", flags, Q2_HOME_OPTIONS);
    if (mkdir("/run/outbox", 0700) != 0 || mkdir("/run/log", 0700) != 0 ||
        mkdir("/run/hermes", 0700) != 0 || chown("/run/hermes", Q2_UID, Q2_GID) != 0) fail("runtime_dirs");
    checked_mount("tmpfs", "/run/outbox", "tmpfs", flags, Q2_OUTBOX_OPTIONS);
    checked_mount("tmpfs", "/run/log", "tmpfs", flags, Q2_LOG_OPTIONS);
    checked_mount("/dev/vdc", "/assignment", "ext4", flags | MS_RDONLY, "");
    int fd = open("/assignment/policy", O_RDONLY | O_CLOEXEC);
    char role[32] = {0};
    if (fd < 0) fail("role_open");
    ssize_t size = read(fd, role, sizeof(role));
    if (close(fd) != 0) fail("role_close");
    if (size == 9 && memcmp(role, "reviewer\n", 9) == 0) flags |= MS_RDONLY;
    else if (size != 10 || memcmp(role, "developer\n", 10) != 0) fail("role_policy");
    else developer = 1;
    checked_mount("/dev/vdb", "/task", "ext4", flags, "");
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
    int output = open("/run/log/worker.log", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int input = open("/dev/null", O_RDONLY);
    if (output < 0 || input < 0 || dup2(input, 0) != 0 ||
        dup2(output, 1) != 1 || dup2(output, 2) != 2) fail("stdio");
    for (int fd = 4; fd < 1024; ++fd) close(fd);
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
    stage = Q2_STAGE_TASK_CWD;
    if (chdir("/task") != 0) fail("task_chdir");
    char *const env[] = {"PATH=/opt/python/bin:/usr/bin:/bin", "HOME=/home/guest", "TMPDIR=/tmp",
        "PYTHONPATH=/opt/hermes", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1",
        "HERMES_HOME=/run/hermes", "HERMES_RUNTIME_DIR=/run/hermes/runtime", "LANG=C.UTF-8", NULL};
    char *const args[] = {"/opt/python/bin/python3", "/sbin/q2-startup.py",
        "--serial-fd", "3", "--assignment", "/assignment/work.json",
        "--outbox", "/run/outbox", NULL};
    stage = Q2_STAGE_PYTHON_EXEC;
    execve(args[0], args, env);
    fail("accepted_guest_entry_exec");
}

int main(void) {
    if (getpid() != 1 || geteuid() != 0) return 111;
    if (access("/sbin/q2-init", X_OK) != 0) root_transition();
    mount_private_storage();
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (child == 0) bounded_unprivileged_exec();
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
