//
//  wq_diag.h
//  Read-only diagnostic helpers for the worse_query verification harness.
//
//  These helpers only perform lookups (opendir/read/open/getxattr). They do
//  not modify anything outside the app's own App Group container.
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