/* Explicit public Apple test fixture only. Never use a default/search-list keychain. */
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LAContext.h>
#include <Security/Security.h>
#include <stdio.h>

NSDictionary *hermes_hvf_legacy_probe(const char *path) {
    @autoreleasepool {
        /* The deprecated interface is itself a required legacy denial surface. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        SecKeychainSetUserInteractionAllowed(false);
        SecKeychainRef fixture = NULL;
        OSStatus opened = SecKeychainOpen(path, &fixture);
        OSStatus unlocked = opened == errSecSuccess ?
            SecKeychainUnlock(fixture, 8, "password", true) : opened;
#pragma clang diagnostic pop
        LAContext *context = [[LAContext alloc] init];
        context.interactionNotAllowed = YES;
        CFTypeRef value = NULL;
        OSStatus queried = unlocked;
        if (fixture && unlocked == errSecSuccess) {
            NSDictionary *query = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecMatchSearchList: @[(__bridge id)fixture],
                (__bridge id)kSecAttrService: @"test_service",
                (__bridge id)kSecAttrAccount: @"test_account",
                (__bridge id)kSecReturnData: @YES,
                (__bridge id)kSecUseAuthenticationContext: context,
            };
            queried = SecItemCopyMatching((__bridge CFDictionaryRef)query, &value);
        }
        NSData *expected = [@"test_password" dataUsingEncoding:NSUTF8StringEncoding];
        BOOL matched = value && CFGetTypeID(value) == CFDataGetTypeID() &&
            [(__bridge NSData *)value isEqualToData:expected];
        if (value) CFRelease(value);
        if (fixture) CFRelease(fixture);
        return @{ @"fixture_only": @YES, @"opened": @(opened), @"unlocked": @(unlocked),
                  @"query_status": @(queried), @"public_dummy_matches": @(matched), @"vm_created": @NO };
    }
}
#ifndef HERMES_HVF_EMBEDDED
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    @autoreleasepool {
        NSData *json = [NSJSONSerialization dataWithJSONObject:hermes_hvf_legacy_probe(argv[1]) options:0 error:NULL];
        fwrite(json.bytes, 1, json.length, stdout); fputc('\n', stdout);
    }
    return 0;
}
#endif
