/* No Hypervisor calls; only explicit disposable inputs, sockets and own task state. */
#import <Foundation/Foundation.h>
#include <Security/SecTask.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern NSDictionary *hermes_hvf_legacy_probe(const char *path);
static bool entitlement(CFStringRef name) {
    SecTaskRef task = SecTaskCreateFromSelf(NULL);
    if (!task) return false;
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, name, NULL);
    bool yes = value && CFEqual(value, kCFBooleanTrue);
    if (value) CFRelease(value);
    CFRelease(task); return yes;
}
static NSDictionary *file_probe(NSString *path, bool write) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, write ? O_CREAT|O_EXCL|O_WRONLY : O_RDONLY, 0600);
    int error = errno;
    if (fd >= 0) { close(fd); if (write) unlink(path.fileSystemRepresentation); }
    return @{ @"allowed": @(fd >= 0), @"errno": @(error) };
}
static bool denied(NSDictionary *record) {
    int error = [record[@"errno"] intValue];
    return ![record[@"allowed"] boolValue] && (error == EPERM || error == EACCES);
}
static NSDictionary *write_capability(NSString *path) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, O_WRONLY);
    int error = errno;
    if (fd >= 0) close(fd); /* No bytes or truncation: only the disposable marker is probed. */
    return @{ @"allowed": @(fd >= 0), @"errno": @(error) };
}
static NSDictionary *unix_probe(NSString *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path.fileSystemRepresentation) >= sizeof(address.sun_path))
        return @{ @"allowed": @NO, @"errno": @(EINVAL) };
    strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof(address.sun_path));
    address.sun_len = sizeof(address);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); errno = 0;
    int connected = fd >= 0 ? connect(fd, (struct sockaddr *)&address, sizeof(address)) : -1;
    int error = errno;
    if (fd >= 0) close(fd);
    return @{ @"allowed": @(connected == 0), @"errno": @(error) };
}
static NSDictionary *network_probe(int port, int kind, bool server) {
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET,
        .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int fd = socket(AF_INET, kind, 0); errno = 0;
    int result = -1;
    if (fd >= 0) result = server ? bind(fd, (struct sockaddr *)&address, sizeof(address)) :
                                  connect(fd, (struct sockaddr *)&address, sizeof(address));
    int error = errno;
    if (fd >= 0) close(fd);
    return @{ @"allowed": @(result == 0), @"errno": @(error) };
}

int hermes_hvf_preflight(const char *plan_path) {
    @autoreleasepool {
        NSData *bytes = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:plan_path]];
        NSDictionary *plan = bytes ? [NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL] : nil;
        if (![plan isKindOfClass:NSDictionary.class] || ![plan[@"forbidden"] isKindOfClass:NSDictionary.class] ||
            ![plan[@"approved"] isKindOfClass:NSArray.class] || ![plan[@"unix"] isKindOfClass:NSDictionary.class]) return 2;
        NSMutableDictionary *negative = [NSMutableDictionary dictionary];
        bool all_denied = [plan[@"forbidden"] count] == 5 && [plan[@"unix"] count] == 2;
        for (NSString *name in plan[@"forbidden"]) {
            if (![plan[@"forbidden"][name] isKindOfClass:NSString.class]) return 2;
            negative[name] = file_probe(plan[@"forbidden"][name], false);
            all_denied &= denied(negative[name]);
        }
        for (NSString *name in plan[@"unix"]) {
            if (![plan[@"unix"][name] isKindOfClass:NSString.class]) return 2;
            negative[name] = unix_probe(plan[@"unix"][name]);
            all_denied &= denied(negative[name]);
        }
        bool approved = [plan[@"approved"] count] >= 1;
        for (NSString *path in plan[@"approved"]) approved &= [file_probe(path, false)[@"allowed"] boolValue];
        if (![plan[@"write_probe"] isKindOfClass:NSString.class] ||
            ![plan[@"legacy_fixture"] isKindOfClass:NSString.class] ||
            ![plan[@"outside_write"] isKindOfClass:NSString.class]) return 2;
        NSDictionary *legacy = hermes_hvf_legacy_probe([plan[@"legacy_fixture"] fileSystemRepresentation]);
        /* Exact scoped fixture succeeds in the paired unrestricted positive control. */
        bool keychain_denied = [legacy[@"query_status"] intValue] != 0 && ![legacy[@"public_dummy_matches"] boolValue];
        NSDictionary *external_write = file_probe(plan[@"outside_write"], true);
        NSDictionary *bundle_write = write_capability(plan[@"write_probe"]);
        int tcp_port = [plan[@"tcp_port"] intValue], udp_port = [plan[@"udp_port"] intValue];
        if (tcp_port < 1 || tcp_port > 65535 || udp_port < 1 || udp_port > 65535) return 2;
        NSDictionary *tcp = network_probe(tcp_port, SOCK_STREAM, false);
        NSDictionary *udp = network_probe(udp_port, SOCK_DGRAM, false);
        NSDictionary *server = network_probe(0, SOCK_STREAM, true);
        NSString *scratch = [NSTemporaryDirectory() stringByAppendingPathComponent:@"hermes-pr15-XXXXXX"];
        char *name = strdup(scratch.fileSystemRepresentation);
        int scratch_fd = name ? mkstemp(name) : -1;
        bool scratch_ok = scratch_fd >= 0;
        if (scratch_fd >= 0) { close(scratch_fd); scratch_ok &= unlink(name) == 0; }
        free(name);
        mach_port_t parent = MACH_PORT_NULL;
        kern_return_t parent_status = task_for_pid(mach_task_self(), getppid(), &parent);
        if (parent_status == KERN_SUCCESS) mach_port_deallocate(mach_task_self(), parent);
        bool sandbox = entitlement(CFSTR("com.apple.security.app-sandbox"));
        bool hv = entitlement(CFSTR("com.apple.security.hypervisor"));
        bool network_entitlements_absent = !entitlement(CFSTR("com.apple.security.network.client")) &&
                                          !entitlement(CFSTR("com.apple.security.network.server"));
        bool pass = sandbox && hv && network_entitlements_absent && approved && all_denied &&
                    keychain_denied && denied(bundle_write) && denied(external_write) && denied(tcp) && denied(udp) &&
                    denied(server) && scratch_ok && parent_status != KERN_SUCCESS;
        NSDictionary *report = @{ @"schema": @"HERMES_HVF_SANDBOX_V1", @"pass": @(pass),
            @"sandbox_entitlement": @(sandbox), @"hypervisor_entitlement": @(hv),
            @"network_entitlements_absent": @(network_entitlements_absent),
            @"approved_reads": @(approved), @"negative": negative, @"legacy_keychain": legacy,
            @"bundle_write": bundle_write, @"outside_write": external_write, @"tcp_client": tcp, @"udp_client": udp,
            @"tcp_server": server, @"private_scratch": @(scratch_ok),
            @"parent_task_status": @(parent_status), @"vm_created": @NO };
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:NULL];
        fputs("HERMES_HVF_SANDBOX_V1 ", stderr); fwrite(json.bytes, 1, json.length, stderr); fputc('\n', stderr); fflush(stderr);
        return pass ? 0 : 2;
    }
}
#ifndef HERMES_HVF_EMBEDDED
int main(int argc, char **argv) {
    return argc == 2 ? hermes_hvf_preflight(argv[1]) : 2;
}
#endif
