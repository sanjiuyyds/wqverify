//
//  BrowserView.swift
//  Full container enumeration, directory browser, file viewer and write probe.
//
//  Read-only except for the explicit write probe (target tmp only, unique file,
//  deleted immediately) and the explicit "save" action in the text viewer.
//

import SwiftUI
import UIKit
import Foundation

struct FileEntry: Identifiable {
    let name: String
    let path: String
    let isDirectory: Bool
    let size: Int

    var id: String { path }
}

struct SelectedFile: Identifiable {
    let path: String
    let data: Data

    var id: String { path }
}

/// The App Group actually injected by the signer. Info.plist value is a fallback.
func resolvedAppGroup() -> String {
    if let g = wq_own_app_group(), !g.isEmpty {
        return g
    }
    return Bundle.main.object(forInfoDictionaryKey: "WQAppGroup") as? String ?? ""
}

// MARK: - Container list

struct ContainerListView: View {
    @State private var scanning = false
    @State private var paths: [String] = []
    @State private var message = ""

    private let group = resolvedAppGroup()

    private let parents = [
        "/private/var/mobile/Containers/Shared/AppGroup",
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Data/InternalDaemon",
        "/private/var/mobile/Containers/Data/PluginKitPlugin",
        "/private/var/containers/Shared/SystemGroup",
        "/private/var/containers/Data/System"
    ]

    var body: some View {
        List {
            Section {
                Button {
                    scanAll()
                } label: {
                    HStack {
                        Image(systemName: "magnifyingglass")
                        Text(scanning ? "扫描中..." : "全量扫描容器")
                        Spacer()
                        if scanning {
                            ProgressView()
                        }
                    }
                }
                .disabled(scanning || group.isEmpty)

                if group.isEmpty {
                    Text("拿不到 App Group，先看诊断面板的 Stage 1。")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                if !message.isEmpty {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("容器 (\(paths.count))") {
                ForEach(paths, id: \.self) { path in
                    NavigationLink {
                        ContainerBrowserView(root: path, group: group)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text((path as NSString).lastPathComponent)
                                .font(.subheadline.monospaced())
                            Text(path)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                }
            }
        }
        .navigationTitle("容器浏览")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func scanAll() {
        guard !scanning else { return }
        scanning = true
        message = "多线程扫描中，最多 90 秒..."

        let parents = self.parents

        DispatchQueue.global(qos: .userInitiated).async {
            let baseline = wq_baseline_inode()
            let maxInode = baseline > 0 ? baseline + 1_000_000 : 5_000_000
            var found: [String] = []

            if maxInode > 0 {
                let dict = (wq_scan_children_all(parents, maxInode, 3000, 90.0)
                            as? [String: [String]]) ?? [:]
                for (_, list) in dict {
                    found.append(contentsOf: list)
                }
            }

            found.sort()

            DispatchQueue.main.async {
                self.paths = found
                self.message = "找到 \(found.count) 个容器（baseline \(baseline)）"
                self.scanning = false
            }
        }
    }
}

// MARK: - Container browser

struct ContainerBrowserView: View {
    let root: String
    let group: String

    @State private var currentPath: String
    @State private var entries: [FileEntry] = []
    @State private var containerID = ""
    @State private var error = ""
    @State private var selectedFile: SelectedFile?
    @State private var showWriteConfirm = false
    @State private var showWriteResult = false
    @State private var writeResult = ""

    init(root: String, path: String? = nil, group: String) {
        self.root = root
        self.group = group
        _currentPath = State(initialValue: path ?? root)
    }

    var body: some View {
        List {
            Section {
                HStack {
                    Text(containerID.isEmpty ? (currentPath as NSString).lastPathComponent : containerID)
                        .font(.caption.monospaced())
                        .lineLimit(1)
                    Spacer()
                    Text("\(entries.count) 项")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !error.isEmpty {
                    Text(error)
                        .font(.caption2)
                        .foregroundStyle(.red)
                }
            }

            Section {
                ForEach(entries) { entry in
                    if entry.isDirectory {
                        NavigationLink {
                            ContainerBrowserView(root: root, path: entry.path, group: group)
                        } label: {
                            row(entry)
                        }
                    } else {
                        Button {
                            openFile(entry.path)
                        } label: {
                            row(entry)
                        }
                    }
                }
            }
        }
        .navigationTitle((currentPath as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    showWriteConfirm = true
                } label: {
                    Image(systemName: "pencil.and.outline")
                }
                .disabled(group.isEmpty)
            }
        }
        .onAppear {
            loadDirectory(currentPath)
        }
        .alert("写能力测试", isPresented: $showWriteConfirm) {
            Button("取消", role: .cancel) {}
            Button("写入并删除", role: .destructive) { runWriteProbe() }
        } message: {
            Text("只会在 \(root)/tmp 写入一个探针文件并立即删除，不碰其他文件。仅限你拥有的设备。")
        }
        .alert("写测试结果", isPresented: $showWriteResult) {
            Button("好", role: .cancel) {}
        } message: {
            Text(writeResult)
        }
        .sheet(item: $selectedFile) { file in
            FileViewerView(path: file.path, data: file.data, group: group)
        }
    }

    private func row(_ entry: FileEntry) -> some View {
        HStack(spacing: 8) {
            Image(systemName: entry.isDirectory ? "folder" : "doc")
                .foregroundStyle(entry.isDirectory ? Color.blue : Color.secondary)
            Text(entry.name)
                .font(.subheadline)
                .lineLimit(1)
            Spacer()
            if !entry.isDirectory {
                Text(sizeText(entry.size))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func sizeText(_ n: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
    }

    private func loadDirectory(_ dir: String) {
        guard !group.isEmpty else {
            error = "没有 App Group"
            return
        }

        let h = worse_query(dir, group, false, true)
        guard h >= 0 else {
            error = "extension 失败 \(h)"
            return
        }
        defer { worse_query_release(h) }

        if let cid = wq_container_id(dir), !cid.isEmpty {
            containerID = cid
        }

        do {
            let names = try FileManager.default.contentsOfDirectory(atPath: dir)
            var out: [FileEntry] = []

            for name in names {
                let p = dir + "/" + name
                let url = URL(fileURLWithPath: p)
                let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .fileSizeKey])
                out.append(FileEntry(name: name,
                                     path: p,
                                     isDirectory: values?.isDirectory ?? false,
                                     size: values?.fileSize ?? 0))
            }

            entries = out.sorted { a, b in
                if a.isDirectory != b.isDirectory { return a.isDirectory }
                return a.name.localizedStandardCompare(b.name) == .orderedAscending
            }
            error = ""
        } catch {
            self.error = "列目录失败: \(error.localizedDescription)"
        }
    }

    private func openFile(_ file: String) {
        guard !group.isEmpty else {
            error = "没有 App Group"
            return
        }

        var h = worse_query(file, group, false, true)
        if h < 0 {
            let parent = (file as NSString).deletingLastPathComponent
            h = worse_query(parent, group, false, true)
        }
        guard h >= 0 else {
            error = "文件 extension 失败 \(h)"
            return
        }
        defer { worse_query_release(h) }

        var err: Int32 = 0
        guard let data = wq_readfile(file, 1_048_576, &err) else {
            error = "读取失败 errno \(err)"
            return
        }

        selectedFile = SelectedFile(path: file, data: data)
    }

    /// Writes one unique file into root/tmp, reads it back, deletes it.
    /// This tells us whether the extension token is read-only or read-write.
    private func runWriteProbe() {
        let tmp = root + "/tmp"
        let probe = tmp + "/wq_probe_\(UUID().uuidString).txt"
        let payload = Data("worse_query write probe\n".utf8)

        let h = worse_query(tmp, group, false, true)
        guard h >= 0 else {
            writeResult = "拿不到 tmp 的 extension：\(h)。tmp 可能不存在，或没有权限。"
            showWriteResult = true
            return
        }
        defer { worse_query_release(h) }

        let wr = wq_writefile(probe, payload, false)
        guard wr == 0 else {
            writeResult = "写入失败 errno \(wr)：token 是只读，或 tmp 不存在。"
            showWriteResult = true
            return
        }

        var err: Int32 = 0
        let back = wq_readfile(probe, 1024, &err)
        let rm = wq_removefile(probe)

        if back == payload {
            writeResult = "读写 token 确认：写入 + 读回一致，探针已删除（rm=\(rm)）。"
        } else {
            writeResult = "写入成功但读回不一致；探针删除 rm=\(rm)，errno \(err)。"
        }
        showWriteResult = true
    }
}

// MARK: - File viewer

struct FileViewerView: View {
    let path: String
    let data: Data
    let group: String

    @Environment(\.dismiss) private var dismiss

    @State private var mode: Mode
    @State private var text: String
    @State private var editable = false
    @State private var status = ""
    @State private var backupData: Data?
    @State private var showSaveConfirm = false
    @State private var showRestoreConfirm = false

    enum Mode: String, CaseIterable, Hashable {
        case text = "文本"
        case hex = "Hex"
        case plist = "Plist"
    }

    init(path: String, data: Data, group: String) {
        self.path = path
        self.data = data
        self.group = group
        _text = State(initialValue: String(data: data, encoding: .utf8) ?? "")
        _mode = State(initialValue: FileViewerView.initialMode(for: data))
    }

    static func initialMode(for data: Data) -> Mode {
        if (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) != nil {
            return .plist
        }
        if String(data: data, encoding: .utf8) != nil {
            return .text
        }
        return .hex
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("模式", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { m in
                        Text(m.rawValue).tag(m)
                    }
                }
                .pickerStyle(.segmented)
                .padding()

                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                if !status.isEmpty {
                    Text(status)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
            }
            .navigationTitle((path as NSString).lastPathComponent)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("关闭") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button("备份到 App Documents") { backup() }
                        Button("从本次备份恢复") { showRestoreConfirm = true }
                            .disabled(backupData == nil)
                        if mode == .text {
                            Button(editable ? "取消编辑" : "编辑文本") {
                                editable.toggle()
                            }
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
                if editable {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("保存") { showSaveConfirm = true }
                    }
                }
            }
            .alert("覆盖原文件？", isPresented: $showSaveConfirm) {
                Button("取消", role: .cancel) {}
                Button("写回", role: .destructive) { save() }
            } message: {
                Text("先自动备份原始内容到 App Documents，再写回 \(path)。")
            }
            .alert("恢复本次备份？", isPresented: $showRestoreConfirm) {
                Button("取消", role: .cancel) {}
                Button("恢复", role: .destructive) { restore() }
            } message: {
                Text("会用本次打开时缓存的内容覆盖 \(path)。")
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch mode {
        case .text:
            if editable {
                TextEditor(text: $text)
                    .font(.system(.caption, design: .monospaced))
                    .padding(6)
            } else {
                ScrollView {
                    Text(text.isEmpty ? "(不是 UTF-8 文本)" : text)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
            }
        case .hex:
            ScrollView {
                Text(hexString(data))
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
        case .plist:
            ScrollView {
                Text(plistString())
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
        }
    }

    private func hexString(_ data: Data, limit: Int = 4096) -> String {
        let bytes = [UInt8](data.prefix(limit))
        if bytes.isEmpty { return "(空文件)" }

        let printable = Array(#" !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"#)

        var lines: [String] = []
        var offset = 0

        while offset < bytes.count {
            let end = min(offset + 16, bytes.count)
            let chunk = bytes[offset..<end]
            let hex = chunk.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = chunk.map { byte -> Character in
                (byte >= 32 && byte < 127) ? printable[Int(byte) - 32] : "."
            }
            let padded = hex.padding(toLength: 47, withPad: " ", startingAt: 0)
            let offsetHex = String(offset, radix: 16)
            let offsetPadded = String(repeating: "0", count: max(0, 8 - offsetHex.count)) + offsetHex
            lines.append(offsetPadded + "  " + padded + "  " + String(ascii))
            offset = end
        }

        if data.count > limit {
            lines.append("")
            lines.append("… 只显示前 \(limit) 字节，原文件 \(data.count) 字节")
        }
        return lines.joined(separator: "\n")
    }

    private func plistString() -> String {
        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else {
            return "不是合法 plist"
        }
        return render(plist, indent: 0)
    }

    private func render(_ value: Any, indent: Int) -> String {
        let pad = String(repeating: "  ", count: indent)

        if let dict = value as? [String: Any] {
            var out = "\(pad){\n"
            for key in dict.keys.sorted() {
                if let child = dict[key] {
                    out += "\(pad)  \(key):\n"
                    out += render(child, indent: indent + 2) + "\n"
                }
            }
            return out + "\(pad)}"
        }

        if let arr = value as? [Any] {
            var out = "\(pad)[\n"
            for item in arr {
                out += render(item, indent: indent + 1) + "\n"
            }
            return out + "\(pad)]"
        }

        return pad + String(describing: value)
    }

    private func ensureBackup() {
        guard backupData == nil else { return }
        backupData = data
        writeBackupFile(data)
    }

    private func backup() {
        ensureBackup()
        status = "已缓存原始内容；备份文件见 Documents/Backups/"
    }

    private func writeBackupFile(_ payload: Data) {
        let fm = FileManager.default
        guard let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
        let dir = docs.appendingPathComponent("Backups", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)

        let name = "\(Int(Date().timeIntervalSince1970))_\((path as NSString).lastPathComponent)"
        let url = dir.appendingPathComponent(name)
        do {
            try payload.write(to: url)
        } catch {
            status = "备份写入失败: \(error.localizedDescription)"
        }
    }

    private func save() {
        ensureBackup()
        let payload = Data(text.utf8)

        let parent = (path as NSString).deletingLastPathComponent

        var h = worse_query(path, group, false, true)
        if h < 0 {
            h = worse_query(parent, group, false, true)
        }
        guard h >= 0 else {
            status = "保存失败：拿不到 extension \(h)"
            return
        }
        defer { worse_query_release(h) }

        let rc = wq_writefile(path, payload, true)
        status = rc == 0 ? "已保存 \(payload.count) 字节" : "保存失败 errno \(rc)"
        if rc == 0 {
            editable = false
        }
    }

    private func restore() {
        guard let payload = backupData else { return }

        let parent = (path as NSString).deletingLastPathComponent()

        var h = worse_query(path, group, false, true)
        if h < 0 {
            h = worse_query(parent, group, false, true)
        }
        guard h >= 0 else {
            status = "恢复失败：拿不到 extension \(h)"
            return
        }
        defer { worse_query_release(h) }

        let rc = wq_writefile(path, payload, true)
        status = rc == 0 ? "已恢复 \(payload.count) 字节" : "恢复失败 errno \(rc)"
        if rc == 0 {
            text = String(data: payload, encoding: .utf8) ?? ""
        }
    }
}