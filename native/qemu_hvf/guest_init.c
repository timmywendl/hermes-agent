/* SPDX-License-Identifier: MIT
 * Q1 serial-only inert PID 1. No libc, fork/exec, sockets, shell or model.
 * Guest messages are untrusted observations, never Host retirement evidence.
 */
typedef unsigned long usize;
struct timespec { long sec, nsec; };
struct pollfd { int fd; short events, revents; };
struct termios { unsigned int iflag, oflag, cflag, lflag; unsigned char line, cc[19]; };
static long syscall6(long n, long a, long b, long c, long d, long e, long f) {
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    register long x8 __asm__("x8")=n;
    __asm__ volatile("svc 0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");
    return x0;
}
static usize length(const char *s) { usize n=0; while(s[n])n++; return n; }
static void emit(const char *s) {
    usize n=length(s), off=0;
    while(off<n) { long r=syscall6(64,1,(long)(s+off),n-off,0,0,0); if(r<=0)return; off+=(usize)r; }
}
static long now(void) {
    struct timespec t={0,0};
    return syscall6(113,1,(long)&t,0,0,0,0)<0 ? -1 : t.sec;
}
static void mount_fs(const char *name,const char *path) {
    syscall6(40,(long)name,(long)path,(long)name,2|8,0,0);
}
static int equals(const char *b,usize n,const char *wanted) {
    if(n!=length(wanted))return 0;
    for(usize i=0;i<n;i++)if(b[i]!=wanted[i])return 0;
    return 1;
}
static void poweroff(void) {
    syscall6(142,0xfee1dead,672274793,0x4321fedc,0,0,0);
    emit("{\"schema\":\"HERMES_HVF_INERT_V1\",\"event\":\"POWEROFF_FAILED\"}\n");
}
__attribute__((noreturn)) void _start(void) {
    mount_fs("devtmpfs","/dev");
    long console=syscall6(56,-100,(long)"/dev/ttyAMA0",2|256,0,0,0);
    if(console>=0) {
        for(int fd=0;fd<3;fd++)if(fd!=console)syscall6(24,console,fd,0,0,0,0);
        if(console>2)syscall6(57,console,0,0,0,0,0);
    }
    struct termios raw={0};
    if(syscall6(29,0,0x5401,(long)&raw,0,0,0)==0) {
        raw.iflag=0; raw.oflag=0; raw.lflag=0; raw.cc[6]=1; raw.cc[5]=0;
        syscall6(29,0,0x5402,(long)&raw,0,0,0);
    }
    mount_fs("proc","/proc"); mount_fs("sysfs","/sys");
    emit("{\"schema\":\"HERMES_HVF_INERT_V1\",\"event\":\"READY\",\"agent\":false,\"worker\":false}\n");
    long start=now(); char frame[64]; usize used=0;
    for(;;) {
        long current=now();
        if(start<0||current<0||current-start>=240) {
            emit("{\"schema\":\"HERMES_HVF_INERT_V1\",\"event\":\"WINDOW_EXPIRED\"}\n");
            poweroff(); break;
        }
        struct pollfd p={0,1,0}; struct timespec timeout={1,0};
        if(syscall6(73,(long)&p,1,(long)&timeout,0,0,0)!=1 || !(p.revents&1))continue;
        long n=syscall6(63,0,(long)(frame+used),1,0,0,0);
        if(n!=1)break;
        used++;
        if(frame[used-1]=='\n') {
            if(equals(frame,used,"HERMES_HVF_STOP_V1\n")) {
                emit("{\"schema\":\"HERMES_HVF_INERT_V1\",\"event\":\"ORDERLY_SHUTDOWN\"}\n");
                poweroff(); break;
            }
            used=0;
        }
        if(used==sizeof frame)used=0;
    }
    for(;;) { struct timespec idle={1,0}; syscall6(101,(long)&idle,0,0,0,0,0); }
}
