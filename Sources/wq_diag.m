//
//  wq_diag.m
//  Read-only diagnostic helpers for the worse_query verification harness.
//

#import "wq_diag.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
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

uint64_t wq_baseline_inode(void) {
    NSString *name = [NSString stringWithFormat:@"wq-baseline-%@", NSUUID.UUID.UUIDString];
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:name];
    uint64_t inode = 0;

    if ([@"x" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        struct stat st;
        if (stat(path.fileSystemRepresentation, &st) == 0) inode = (uint64_t)st.st_ino;
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }
    return inode;
}

NSDictionary<NSString *, NSArray<NSString *> *> *wq_scan_children(NSArray<NSString *> *parents,
                                                                  uint64_t maxInode,
                                                                  NSInteger limitPerParent,
                                                                  double seconds) {
    NSMutableArray<NSString *> *dirs = [NSMutableArray array];
    for (NSString *parent in parents) {
        if (![parent isKindOfClass:[NSString class]] || parent.length == 0) continue;
        NSString *dir = parent;
        while (dir.length > 1 && [dir hasSuffix:@"/"]) {
            dir = [dir substringToIndex:dir.length - 1];
        }
        if (![dirs containsObject:dir]) [dirs addObject:dir];
    }
    if (dirs.count == 0 || maxInode < 1) return @{};

    struct statfs sfs;
    if (statfs(dirs.firstObject.fileSystemRepresentation, &sfs) != 0) {
        if (statfs("/private/var", &sfs) != 0) return @{};
    }
    fsid_t fsid = sfs.f_fsid;

    NSUInteger count = dirs.count;
    char **prefixes = calloc(count, sizeof(char *));
    size_t *lengths = calloc(count, sizeof(size_t));
    if (!prefixes || !lengths) {
        if (prefixes) free(prefixes);
        if (lengths) free(lengths);
        return @{};
    }

    NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *found =
        [NSMutableDictionary dictionary];

    for (NSUInteger i = 0; i < count; i++) {
        NSString *dir = dirs[i];
        found[dir] = [NSMutableArray array];

        char buf[PATH_MAX];
        if (![dir getFileSystemRepresentation:buf maxLength:sizeof(buf)]) continue;
        size_t len = strlen(buf);
        if (len == 1 && buf[0] == '/') len = 0;
        prefixes[i] = strdup(buf);
        lengths[i] = len;
    }

    double deadline = CFAbsoluteTimeGetCurrent() + (seconds > 0 ? seconds : 25.0);
    char buffer[PATH_MAX];

    for (uint64_t inode = 1; inode <= maxInode; inode++) {
        if ((inode & 0xFFFF) == 0) {
            if (CFAbsoluteTimeGetCurrent() > deadline) break;

            BOOL allFull = YES;
            for (NSUInteger i = 0; i < count; i++) {
                NSMutableArray<NSString *> *items = found[dirs[i]];
                if (items.count < (NSUInteger)limitPerParent) {
                    allFull = NO;
                    break;
                }
            }
            if (allFull) break;
        }

        ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
        if (n <= 0) continue;

        for (NSUInteger i = 0; i < count; i++) {
            if (!prefixes[i]) continue;
            size_t len = lengths[i];
            if (strncmp(buffer, prefixes[i], len) != 0) continue;
            if (buffer[len] != '/') continue;
            if (strchr(buffer + len + 1, '/')) continue;

            NSMutableArray<NSString *> *items = found[dirs[i]];
            if (limitPerParent > 0 && (NSInteger)items.count >= limitPerParent) continue;

            NSString *path = [NSString stringWithUTF8String:buffer];
            if (path && ![items containsObject:path]) [items addObject:path];
        }
    }

    for (NSUInteger i = 0; i < count; i++) {
        if (prefixes[i]) free(prefixes[i]);
    }
    free(prefixes);
    free(lengths);
    return (NSDictionary<NSString *, NSArray<NSString *> *> *)found;
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