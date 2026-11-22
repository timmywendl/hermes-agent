/* This exact object is linked into the no-HVF canary and QEMU bootstrap.
 * No database, default keychain, credential discovery, or Hypervisor call. */
#import <Foundation/Foundation.h>
#include <Security/SecTask.h>
#include <Security/SecCode.h>
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

extern int hermes_q2_fd_identity(int, unsigned long long, unsigned long long,
                                unsigned long long, bool);
extern int hermes_q2_serial_identity(int);
extern NSDictionary *hermes_hvf_legacy_probe(const char *);

static bool entitlement(CFStringRef name) {
    SecTaskRef task = SecTaskCreateFromSelf(NULL);
    if (!task) return false;
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, name, NULL);
    bool yes = value && CFEqual(value, kCFBooleanTrue);
    if (value) CFRelease(value);
    CFRelease(task);
    return yes;
}

static NSDictionary *file_probe(NSString *path, bool write) {
    errno = 0;
    int fd = open(path.fileSystemRepresentation, write ? O_WRONLY : O_RDONLY);
    int error = errno;
    if (fd >= 0) close(fd);
    return @{@"allowed": @((bool)(fd >= 0)), @"errno": @(error)};
}

static bool denied(NSDictionary *record) {
    int error = [record[@"errno"] intValue];
    return ![record[@"allowed"] boolValue] && (error == EPERM || error == EACCES);
}

static NSDictionary *unix_probe(NSString *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path.fileSystemRepresentation) >= sizeof(address.sun_path))
        return @{@"allowed": @NO, @"errno": @(EINVAL)};
    strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof(address.sun_path));
    address.sun_len = sizeof(address);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    int result = -1, error = errno;
    if (fd >= 0) {
        result = connect(fd, (struct sockaddr *)&address, sizeof(address));
        error = errno;
        close(fd);
    }
    return @{@"allowed": @((bool)(result == 0)), @"errno": @(error)};
}

static NSDictionary *network_probe(int port, int family, int kind, bool server) {
    struct sockaddr_storage storage = {0};
    socklen_t size;
    if (family == AF_INET6) {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
        address->sin6_len = sizeof(*address); address->sin6_family = AF_INET6;
        address->sin6_port = htons(port); address->sin6_addr = in6addr_loopback;
        size = sizeof(*address);
    } else {
        struct sockaddr_in *address = (struct sockaddr_in *)&storage;
        address->sin_len = sizeof(*address); address->sin_family = AF_INET;
        address->sin_port = htons(port); address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        size = sizeof(*address);
    }
    int fd = socket(family, kind, 0);
    int result = -1, error = errno;
    if (fd >= 0) {
        result = server ? bind(fd, (struct sockaddr *)&storage, size) :
                          connect(fd, (struct sockaddr *)&storage, size);
        error = errno;
        close(fd);
    }
    return @{@"allowed": @((bool)(result == 0)), @"errno": @(error)};
}

static NSString *hex(NSData *value) {
    NSMutableString *result = [NSMutableString string];
    const unsigned char *bytes = value.bytes;
    for (NSUInteger i = 0; i < value.length; i++) [result appendFormat:@"%02x", bytes[i]];
    return result;
}

static NSString *file_sha256(NSString *path) {
    if (!path) return @"";
    NSData *bytes = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL];
    if (!bytes || bytes.length > UINT32_MAX) return @"";
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes.bytes, (CC_LONG)bytes.length, hash);
    return hex([NSData dataWithBytes:hash length:sizeof(hash)]);
}

static NSDictionary *code_identity(bool diagnostic) {
    SecCodeRef code = NULL;
    CFDictionaryRef info = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess) {
        if (code) CFRelease(code);
        return @{};
    }
    NSDictionary *data = (__bridge NSDictionary *)info;
    NSString *identifier = data[(__bridge NSString *)kSecCodeInfoIdentifier];
    NSData *cdhash = data[(__bridge NSString *)kSecCodeInfoUnique];
    NSMutableDictionary *result = [@{@"identifier": identifier ?: @"",
                                     @"cdhash": cdhash ? hex(cdhash) : @""} mutableCopy];
    if (diagnostic) {
        NSURL *executable = data[(__bridge NSString *)kSecCodeInfoMainExecutable];
        NSString *app = [NSBundle mainBundle].bundlePath;
        NSMutableDictionary *inventory = [NSMutableDictionary dictionary];
        NSDirectoryEnumerator *paths = [NSFileManager.defaultManager enumeratorAtPath:app];
        for (NSString *relative in paths) {
            NSString *path = [app stringByAppendingPathComponent:relative];
            struct stat record;
            if (lstat(path.fileSystemRepresentation, &record) || S_ISLNK(record.st_mode)) {
                CFRelease(info); CFRelease(code); return @{};
            }
            if (S_ISREG(record.st_mode)) {
                if (record.st_nlink != 1) {
                    CFRelease(info); CFRelease(code); return @{};
                }
                inventory[path] = file_sha256(path);
            }
        }
        result[@"executable"] = executable.path ?: @"";
        result[@"executable_sha256"] = file_sha256(executable.path);
        result[@"entitlements"] = data[(__bridge NSString *)kSecCodeInfoEntitlementsDict] ?: @{};
        result[@"package_inventory"] = inventory;
    }
    CFRelease(info); CFRelease(code);
    return result;
}

static bool descriptors(NSDictionary *plan, int manifest_fd) {
    NSDictionary *devices = plan[@"devices"];
    if (![devices isKindOfClass:NSDictionary.class] ||
        ![[NSSet setWithArray:devices.allKeys] isEqualToSet:
          [NSSet setWithArray:@[@"root", @"task", @"assignment"]]]) return false;
    NSString *role = plan[@"role"];
    if (![role isEqual:@"developer"] && ![role isEqual:@"reviewer"]) return false;
    NSMutableSet *identities = [NSMutableSet set];
    NSMutableSet *fds = [NSMutableSet setWithArray:@[@0, @1, @2, @(manifest_fd)]];
    for (NSString *name in @[@"root", @"task", @"assignment"]) {
        NSDictionary *record = devices[name];
        if (![record isKindOfClass:NSDictionary.class] ||
            ![[NSSet setWithArray:record.allKeys] isEqualToSet:
              [NSSet setWithArray:@[@"fd", @"st_dev", @"st_ino", @"size"]]]) return false;
        int fd = [record[@"fd"] intValue];
        bool writable = [name isEqual:@"task"] && [role isEqual:@"developer"];
        if ([record[@"size"] unsignedLongLongValue] > 8ULL * 1024 * 1024 * 1024 ||
            !hermes_q2_fd_identity(fd, [record[@"st_dev"] unsignedLongLongValue],
                [record[@"st_ino"] unsignedLongLongValue], [record[@"size"] unsignedLongLongValue], writable))
            return false;
        NSString *identity = [NSString stringWithFormat:@"%@:%@", record[@"st_dev"], record[@"st_ino"]];
        if ([identities containsObject:identity] || [fds containsObject:@(fd)]) return false;
        [identities addObject:identity]; [fds addObject:@(fd)];
    }
    int serial = [plan[@"serial_fd"] intValue];
    if (!hermes_q2_serial_identity(serial) || [fds containsObject:@(serial)]) return false;
    [fds addObject:@(serial)];
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) return false;
    rlim_t maximum = limit.rlim_cur < 65536 ? limit.rlim_cur : 65536;
    for (int fd = 3; (rlim_t)fd < maximum; fd++)
        if (fcntl(fd, F_GETFD) != -1 && ![fds containsObject:@(fd)]) {
            fprintf(stderr, "HERMES_Q2_PREFLIGHT_REFUSED extra_fd=%d\n", fd);
            return false;
        }
    return true;
}

static NSArray *qemu_arguments(NSDictionary *plan, NSString *resources) {
    NSString *serial = [NSString stringWithFormat:@"socket,id=worker,fd=%d", [plan[@"serial_fd"] intValue]];
    NSMutableArray *args = [NSMutableArray arrayWithArray:@[
        @"-L", resources, @"-nodefaults", @"-display", @"none", @"-monitor", @"none", @"-qmp", @"stdio",
        @"-chardev", serial, @"-serial", @"chardev:worker", @"-nic", @"none", @"-accel", @"hvf",
        @"-machine", @"virt", @"-cpu", @"host", @"-smp", @"2", @"-m", @"2048", @"-no-reboot",
        @"-kernel", [resources stringByAppendingPathComponent:@"kernel.Image"],
        @"-initrd", [resources stringByAppendingPathComponent:@"initramfs.cpio.gz"],
        @"-append", @"console=tty0 root=/dev/vda ro rdinit=/init panic=-1"]];
    int index = 1;
    for (NSString *name in @[@"root", @"task", @"assignment"]) {
        int fd = [plan[@"devices"][name][@"fd"] intValue];
        bool writable = [name isEqual:@"task"] && [plan[@"role"] isEqual:@"developer"];
        [args addObjectsFromArray:@[@"-add-fd", [NSString stringWithFormat:@"fd=%d,set=%d", fd, index],
            @"-drive", [NSString stringWithFormat:@"file=/dev/fdset/%d,format=raw,if=none,id=%@,readonly=%@",
                       index, name, writable ? @"off" : @"on"],
            @"-device", [@"virtio-blk-pci,drive=" stringByAppendingString:name]]];
        index++;
    }
    return args;
}

static NSDictionary *manifest(const char *path, int *manifest_fd) {
    NSString *text = [NSString stringWithUTF8String:path];
    if (![text hasPrefix:@"/dev/fd/"]) return nil;
    NSString *number = [text substringFromIndex:8];
    NSScanner *scanner = [NSScanner scannerWithString:number];
    int fd = -1;
    if (![scanner scanInt:&fd] || !scanner.isAtEnd || fd < 3) return nil;
    struct stat info, after;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
        info.st_size < 2 || info.st_size > 65536 || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY) return nil;
    NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)info.st_size];
    if (pread(fd, bytes.mutableBytes, bytes.length, 0) != (ssize_t)bytes.length ||
        fstat(fd, &after) || info.st_dev != after.st_dev || info.st_ino != after.st_ino ||
        info.st_size != after.st_size || info.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        info.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec) return nil;
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL];
    if (![value isKindOfClass:NSDictionary.class] ||
        ![[NSSet setWithArray:value.allKeys] isEqualToSet:[NSSet setWithArray:
          @[@"schema", @"role", @"policy_sha256", @"devices", @"serial_fd", @"qemu_argv", @"owner"]]]) return nil;
    NSData *canonical = [NSJSONSerialization dataWithJSONObject:value
        options:NSJSONWritingSortedKeys | NSJSONWritingWithoutEscapingSlashes error:NULL];
    if (![canonical isEqualToData:bytes]) return nil;
    NSDictionary *owner = value[@"owner"];
    if (![owner isKindOfClass:NSDictionary.class] ||
        ![[NSSet setWithArray:owner.allKeys] isEqualToSet:[NSSet setWithArray:
          @[@"task_id", @"run_id", @"epoch", @"vm_id", @"attempt", @"instance"]]]) return nil;
    if (![owner[@"task_id"] isKindOfClass:NSString.class] || [owner[@"task_id"] length] < 1 ||
        ![owner[@"vm_id"] isKindOfClass:NSString.class] || [owner[@"vm_id"] length] < 1 ||
        ![owner[@"attempt"] isKindOfClass:NSString.class] || [owner[@"attempt"] length] < 1 ||
        ![owner[@"instance"] isKindOfClass:NSString.class] || [owner[@"instance"] length] < 1 ||
        [owner[@"run_id"] integerValue] < 1 || [owner[@"epoch"] integerValue] < 1) return nil;
    *manifest_fd = fd;
    return value;
}

static NSDictionary *device_control(NSDictionary *plan, bool canary) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    for (NSString *name in @[@"root", @"task", @"assignment"]) {
        int fd = [plan[@"devices"][name][@"fd"] intValue];
        char value = 0;
        errno = 0;
        ssize_t read = pread(fd, &value, 1, 0); int read_error = errno;
        errno = 0;
        ssize_t write = canary ? pwrite(fd, &value, 1, 0) : -1; int write_error = errno;
        int access = fcntl(fd, F_GETFL) & O_ACCMODE;
        struct stat info = {0};
        bool observed = fstat(fd, &info) == 0;
        result[name] = @{@"read": @((bool)(read == 1)), @"read_errno": @(read_error),
                         @"write": @((bool)(write == 1)), @"write_errno": @(write_error), @"access": @(access),
                         @"observed": @(observed), @"fd": @(fd), @"st_dev": @(info.st_dev),
                         @"st_ino": @(info.st_ino), @"size": @(info.st_size)};
    }
    /* No nonce/data is injected into a real Worker UART. Identity only. */
    result[@"serial_identity"] = @((bool)hermes_q2_serial_identity([plan[@"serial_fd"] intValue]));
    return result;
}

static int preflight(const char *path, int argc, char **argv, bool canary) {
    @autoreleasepool {
        int manifest_fd = -1;
        NSDictionary *plan = manifest(path, &manifest_fd);
        NSString *resources = [[NSBundle mainBundle] resourcePath];
        NSData *policy_bytes = [NSData dataWithContentsOfFile:[resources stringByAppendingPathComponent:@"static-policy.json"]];
        NSDictionary *policy = policy_bytes ? [NSJSONSerialization JSONObjectWithData:policy_bytes options:0 error:NULL] : nil;
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        if (!policy || policy_bytes.length > 65536) {
            fprintf(stderr, "HERMES_Q2_PREFLIGHT_REFUSED policy_unavailable errno=%d resources=%s\n", errno, resources.fileSystemRepresentation);
            return 2;
        }
        CC_SHA256(policy_bytes.bytes, (CC_LONG)policy_bytes.length, hash);
        NSString *policy_hash = hex([NSData dataWithBytes:hash length:sizeof(hash)]);
        if (!plan || ![plan[@"schema"] isEqual:@"HERMES_Q2_SANDBOX_PLAN_V1"] ||
            ![plan[@"policy_sha256"] isEqual:policy_hash] ||
            ![policy[@"schema"] isEqual:@"HERMES_Q2_STATIC_POLICY_V1"] ||
            ![policy[@"forbidden"] isKindOfClass:NSDictionary.class] ||
            ![policy[@"unix"] isKindOfClass:NSDictionary.class] ||
            ![policy[@"approved"] isKindOfClass:NSArray.class] ||
            !descriptors(plan, manifest_fd)) {
            fprintf(stderr, "HERMES_Q2_PREFLIGHT_REFUSED manifest_policy_or_fd errno=%d manifest=%d\n", errno, manifest_fd);
            return 2;
        }
        NSArray *expected = qemu_arguments(plan, resources);
        if (![plan[@"qemu_argv"] isEqual:expected] || (NSUInteger)argc != expected.count) {
            fprintf(stderr, "HERMES_Q2_PREFLIGHT_REFUSED argv resources=%s\n", resources.fileSystemRepresentation);
            return 2;
        }
        for (int index = 0; index < argc; index++)
            if (![expected[index] isEqualToString:[NSString stringWithUTF8String:argv[index]]]) return 2;
        NSMutableDictionary *negative = [NSMutableDictionary dictionary];
        NSMutableDictionary *negative_writes = [NSMutableDictionary dictionary];
        bool all_denied = [policy[@"forbidden"] count] == 6 && [policy[@"unix"] count] == 2;
        for (NSString *name in policy[@"forbidden"]) {
            negative[name] = file_probe(policy[@"forbidden"][name], false);
            negative_writes[name] = file_probe(policy[@"forbidden"][name], true);
            all_denied &= denied(negative[name]) && denied(negative_writes[name]);
        }
        for (NSString *name in policy[@"unix"]) {
            negative[name] = unix_probe(policy[@"unix"][name]);
            all_denied &= denied(negative[name]);
        }
        bool approved = [policy[@"approved"] count] >= 2;
        for (NSString *name in policy[@"approved"])
            approved &= [file_probe(name, false)[@"allowed"] boolValue];
        NSDictionary *bundle_write = file_probe(policy[@"approved"][0], true);
        NSDictionary *devices = device_control(plan, canary);
        bool devices_ok = [devices[@"serial_identity"] boolValue];
        for (NSString *name in @[@"root", @"task", @"assignment"]) {
            bool writable = [name isEqual:@"task"] && [plan[@"role"] isEqual:@"developer"];
            devices_ok &= [devices[name][@"read"] boolValue] &&
                          (canary ? ([devices[name][@"write"] boolValue] == writable) :
                           [devices[name][@"access"] intValue] == (writable ? O_RDWR : O_RDONLY));
        }
        NSDictionary *legacy = hermes_hvf_legacy_probe([policy[@"legacy_fixture"] fileSystemRepresentation]);
        NSMutableDictionary *network = [NSMutableDictionary dictionary];
        bool net_denied = true;
        for (NSString *key in @[@"tcp4", @"udp4", @"tcp6", @"udp6"]) {
            int family = [key hasSuffix:@"6"] ? AF_INET6 : AF_INET;
            int kind = [key hasPrefix:@"tcp"] ? SOCK_STREAM : SOCK_DGRAM;
            int port = [policy[@"ports"][key] intValue];
            if (port < 1 || port > 65535) return 2;
            network[key] = network_probe(port, family, kind, false);
            net_denied &= denied(network[key]);
        }
        network[@"listen4"] = network_probe(0, AF_INET, SOCK_STREAM, true);
        network[@"listen6"] = network_probe(0, AF_INET6, SOCK_STREAM, true);
        net_denied &= denied(network[@"listen4"]) && denied(network[@"listen6"]);
        bool sandbox = entitlement(CFSTR("com.apple.security.app-sandbox"));
        bool hv = entitlement(CFSTR("com.apple.security.hypervisor"));
        bool no_network = !entitlement(CFSTR("com.apple.security.network.client")) &&
                          !entitlement(CFSTR("com.apple.security.network.server"));
        bool keychain_denied = [legacy[@"query_status"] intValue] != 0 &&
                               ![legacy[@"public_dummy_matches"] boolValue];
        bool pass = sandbox && hv && no_network && approved && all_denied &&
                    devices_ok && net_denied && keychain_denied && denied(bundle_write);
        NSDictionary *report = @{@"schema": @"HERMES_Q2_SANDBOX_RESULT_V1", @"pass": @(pass),
            @"sandbox": @(sandbox), @"hypervisor": @(hv), @"network_entitlements_absent": @(no_network),
            @"approved_reads": @(approved), @"negative": negative, @"negative_writes": negative_writes,
            @"bundle_write": bundle_write, @"devices": devices,
            @"network": network, @"legacy_keychain": legacy, @"identity": code_identity(canary),
            @"vm_created": @NO, @"descriptor_identity": @YES, @"pid": @(getpid()), @"canary": @(canary),
            @"role": plan[@"role"], @"serial_fd": plan[@"serial_fd"]};
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:NULL];
        fputs("HERMES_Q2_SANDBOX_RESULT_V1 ", stderr);
        fwrite(json.bytes, 1, json.length, stderr); fputc('\n', stderr); fflush(stderr);
        return pass ? 0 : 2;
    }
}
int hermes_q2_preflight(const char *path, int argc, char **argv) {
    return preflight(path, argc, argv, false);
}

int hermes_q2_canary(const char *path, int argc, char **argv) {
    return preflight(path, argc, argv, true);
}
