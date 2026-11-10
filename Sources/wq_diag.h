//
//  wq_diag.h
//  Diagnostic and file-access helpers for the worse_query verification harness.
//
//  Lookup helpers are read-only. wq_writefile/wq_removefile are only used by
//  the explicit write probe (target tmp, unique file, deleted immediately) and
//  by the explicit text save action after user confirmation.
//

#ifndef wq_diag_h
#define wq_diag_h

#import <Foundation/Foundation.h>
#include <stdint.h>

/// Returns "OK: ..." when every private symbol resolves, otherwise "FAIL: ...".
NSString *wq_diag_symbol_report(void);

/// Lists a directory. Returns nil on failure and writes errno to *errp.
NSArray<NSString *> *wq_listdir(NSString *path, int32_t *errp, NSInteger limit);

/// Reads up to maxLen bytes from a file. Returns nil on failure and writes errno to *errp.
NSData *wq_readfile(NSString *path, NSInteger maxLen, int32_t *errp);

/// Creates a temp file on the data volume and returns its inode. Used as a
/// conservative upper bound for the fsgetpath inode scan.
uint64_t wq_baseline_inode(void);

/// One fsgetpath pass over 1...maxInode. For each parent, collects up to
/// limitPerParent direct child paths, stopping after `seconds`.
/// Returns a dictionary keyed by the normalized parent path.
NSDictionary<NSString *, NSArray<NSString *> *> *wq_scan_children(NSArray<NSString *> *parents,
                                                                  uint64_t maxInode,
                                                                  NSInteger limitPerParent,
                                                                  double seconds);

/// Multithreaded version of wq_scan_children. Chunks the inode range and
/// merges results under a lock. 0 limit means unlimited.
NSDictionary<NSString *, NSArray<NSString *> *> *wq_scan_children_all(NSArray<NSString *> *parents,
                                                                      uint64_t maxInode,
                                                                      NSInteger limitPerParent,
                                                                      double seconds);

/// Writes data to path. overwrite=NO uses O_EXCL; YES truncates in place.
/// Returns 0 on success, errno on failure. O_NOFOLLOW is always set.
int wq_writefile(NSString *path, NSData *data, BOOL overwrite);

/// unlink(2). Returns 0 on success, errno on failure.
int wq_removefile(NSString *path);

/// Every App Group string present in this app's own code-signing entitlements.
/// Empty when the signer dropped the application-groups entitlement.
NSArray<NSString *> *wq_entitled_app_groups(void);

/// The first entitled App Group that actually resolves to a container.
/// This is the group the signer injected, not a hardcoded identifier.
NSString *wq_own_app_group(void);

/// Reads com.apple.containermanager.identifier from a container directory.
/// Requires a consumed sandbox extension for that path.
NSString *wq_container_id(NSString *path);

/// Reads .com.apple.mobile_container_manager.metadata.plist from a container root.
/// Requires a consumed sandbox extension for that path.
NSDictionary<NSString *, id> *wq_container_metadata(NSString *containerPath);

#endif /* wq_diag_h */