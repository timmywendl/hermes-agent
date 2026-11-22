/* Q2 composes the accepted Q1 release reader once; it never creates a VM. */
#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

extern int hermes_hvf_admission_gate(void);
extern int hermes_q2_preflight(const char *plan, int argc, char **argv);

int hermes_q2_fd_identity(int fd, unsigned long long dev, unsigned long long ino,
                         unsigned long long size, bool writable) {
    struct stat info;
    int flags = fcntl(fd, F_GETFL);
    return fd >= 3 && flags >= 0 && fstat(fd, &info) == 0 &&
           S_ISREG(info.st_mode) && info.st_nlink == 1 &&
           (unsigned long long)info.st_dev == dev &&
           (unsigned long long)info.st_ino == ino &&
           (unsigned long long)info.st_size == size &&
           (flags & O_ACCMODE) == (writable ? O_RDWR : O_RDONLY);
}

int hermes_q2_serial_identity(int fd) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    int type = 0;
    socklen_t type_length = sizeof(type);
    return fd >= 3 && getsockname(fd, (struct sockaddr *)&address, &length) == 0 &&
           address.ss_family == AF_UNIX &&
           getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
           type == SOCK_STREAM;
}

int hermes_q2_gate(const char *plan, int argc, char **argv) {
    if (hermes_q2_preflight(plan, argc, argv) != 0) return 2;
    /* The sole stdin reader, core-limit setter and release protocol. */
    return hermes_hvf_admission_gate();
}
