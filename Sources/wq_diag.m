//
//  wq_diag.m
//  Read-only diagnostic helpers for the worse_query verification harness.
//

#import "wq_diag.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

// SecTask lives in Security.framework. The public headers do not always expose
// these two symbols, so declare them the same way WQFiles does.
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task,
                                                CFStringRef entitlement,
                                                CFErrorRef *error);

NSArray<NSString *> *wq_entitled_app_groups(void) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return @[];

    CFTypeRef value = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.security.application-groups"), NULL);
    CFRelease(task);

    if (!value) return @[];
    NSArray *raw = (__bridge_transfer NSArray *)value;
    if (![raw isKindOfClass:[NSArray class]]) return @[];

    NSMutableArray<NSString *> *groups = [NSMutableArray array];
    for (id item in raw) {
        if ([item isKindOfClass:[NSString class]]) [groups addObject:item];
    }
    return groups;
}

NSString *wq_own_app_group(void) {
    for (NSString *candidate in wq_entitled_app_groups()) {
        NSURL *root = [NSFileManager.defaultManager
                       containerURLForSecurityApplicationGroupIdentifier:candidate];
        if (root) return candidate;
    }
    return nil;
}

NSString *wq_diag_symbol_report(void) {
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) {
        return [NSString stringWithFormat:@"FAIL: dlopen: %s", dlerror()];
    }

    static const char *names[] = {
        "container_query_create",
        "container_query_set_class",
        "container_query_set_group_identifiers",
        "container_query_operation_set_flags",
        "container_query_operation_set_part",
        "container_query_get_single_result",
        "container_query_free",
        "container_copy_sandbox_token",
    };

    NSMutableArray<NSString *> *missing = [NSMutableArray array];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!dlsym(mgr, names[i])) {
            [missing addObject:[NSString stringWithUTF8String:names[i]]];
        }
    }
    if (!dlsym(RTLD_DEFAULT, "sandbox_extension_consume")) [missing addObject:@"sandbox_extension_consume"];
    if (!dlsym(RTLD_DEFAULT, "sandbox_extension_release")) [missing addObject:@"sandbox_extension_release"];

    dlclose(mgr);
    if (missing.count > 0) {
        return [@"FAIL: missing " stringByAppendingString:
                [missing componentsJoinedByString:@", "]];
    }
    return @"OK: all private symbols resolved";
}

NSArray<NSString *> *wq_listdir(NSString *path, int32_t *errp, NSInteger limit) {
    if (errp) *errp = 0;
    DIR *dir = opendir(path.fileSystemRepresentation);
    if (!dir) {
        if (errp) *errp = errno;
        return nil;
    }

    NSMutableArray<NSString *> *items = [NSMutableArray array];
    struct dirent *ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        NSString *name = [NSString stringWithUTF8String:ent->d_name];
        if (name) [items addObject:name];
        if (limit > 0 && (NSInteger)items.count >= limit) break;
    }
    closedir(dir);
    return items;
}

NSData *wq_readfile(NSString *path, NSInteger maxLen, int32_t *errp) {
    if (errp) *errp = 0;
    int fd = open(path.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) {
        if (errp) *errp = errno;
        return nil;
    }

    NSUInteger cap = maxLen > 0 ? (NSUInteger)maxLen : 1;
    NSMutableData *data = [NSMutableData dataWithLength:cap];
    ssize_t n = read(fd, data.mutableBytes, cap);
    int saved = errno;
    close(fd);

    if (n < 0) {
        if (errp) *errp = saved;
        return nil;
    }
    data.length = (NSUInteger)n;
    return data;
}

NSString *wq_container_id(NSString *path) {
    char buf[512];
    memset(buf, 0, sizeof(buf));
    ssize_t n = getxattr(path.fileSystemRepresentation,
                         "com.apple.containermanager.identifier",
                         buf, sizeof(buf) - 1, 0, 0);
    if (n <= 0) return nil;
    return [NSString stringWithUTF8String:buf];
}

NSDictionary<NSString *, id> *wq_container_metadata(NSString *containerPath) {
    NSString *metaPath = [containerPath stringByAppendingPathComponent:
                          @".com.apple.mobile_container_manager.metadata.plist"];
    int32_t err = 0;
    NSData *data = wq_readfile(metaPath, 64 * 1024, &err);
    if (!data) return nil;

    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    return [plist isKindOfClass:[NSDictionary class]] ? (NSDictionary *)plist : nil;
}