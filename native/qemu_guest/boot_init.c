/* One-shot Linux image initialization, not an Owner or Worker implementation.
 * The only application exec is the accepted PR16 Guest entry. Not run by build.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/reboot.h>
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

static void fail(const char *operation) {
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
    checked_mount("/dev/vdb", "/task", "ext4", flags, "");
}

static void bounded_unprivileged_exec(void) {
    /* initramfs need not have supplied console descriptors. Reserve stdio first
     * so duplicating stdin cannot accidentally overwrite the log descriptor. */
    int null = open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, 0) != 0 || dup2(null, 1) != 1 || dup2(null, 2) != 2) fail("null_stdio");
    if (null > 2 && close(null) != 0) fail("null_close");
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
    struct rlimit core = {Q2_CORE_LIMIT, Q2_CORE_LIMIT}, fds = {Q2_FDS_LIMIT, Q2_FDS_LIMIT};
    struct rlimit processes = {Q2_PROCESSES_LIMIT, Q2_PROCESSES_LIMIT};
    struct rlimit file = {Q2_FILE_LIMIT, Q2_FILE_LIMIT};
    if (setrlimit(RLIMIT_CORE, &core) || setrlimit(RLIMIT_NOFILE, &fds) ||
        setrlimit(RLIMIT_NPROC, &processes) || setrlimit(RLIMIT_FSIZE, &file)) fail("rlimit");
    for (int cap = 0; cap <= 40; ++cap)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) fail("cap_drop");
    if (setgroups(0, NULL) || setgid(Q2_GID) || setuid(Q2_UID) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) fail("unprivileged_identity");
    if (chdir("/task") != 0) fail("task_chdir");
    char *const env[] = {"PATH=/opt/python/bin:/usr/bin:/bin", "HOME=/home/guest", "TMPDIR=/tmp",
        "PYTHONPATH=/opt/hermes", "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1",
        "HERMES_HOME=/run/hermes", "HERMES_RUNTIME_DIR=/run/hermes/runtime", "LANG=C.UTF-8", NULL};
    char *const args[] = {"/opt/python/bin/python3", "-m", "native.qemu_guest.guest_entry",
        "--serial-fd", "3", "--assignment", "/assignment/work.json",
        "--outbox", "/run/outbox", NULL};
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
    sync();
    reboot(LINUX_REBOOT_CMD_POWER_OFF);
    return 111;
}
