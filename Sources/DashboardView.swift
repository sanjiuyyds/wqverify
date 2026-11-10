//
//  DashboardView.swift
//  Dashboard for the wqverify verification app.
//

import SwiftUI
import UIKit
import Foundation

final class DiagModel: ObservableObject {
    @Published var report: Diagnostics.Report?
    @Published var running = false

    func run() {
        guard !running else { return }
        running = true

        let group = Bundle.main.object(forInfoDictionaryKey: "WQAppGroup") as? String ?? ""

        DispatchQueue.global(qos: .userInitiated).async {
            let result = Diagnostics.run(group: group)

            // Keep the report pullable from Documents, like the old harness.
            let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            try? result.shareText.write(to: dir.appendingPathComponent("wq_report.txt"),
                                        atomically: true, encoding: .utf8)

            // Also emit to stdout for `idevicesyslog` / Xcode console capture.
            print("WQDIAG VERDICT: \(result.headline) | \(result.subheadline)")
            print(result.rawLog)

            DispatchQueue.main.async {
                self.report = result
                self.running = false
            }
        }
    }
}

struct DashboardView: View {
    @StateObject private var model = DiagModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if model.running {
                        HStack(spacing: 10) {
                            ProgressView()
                            Text("正在检测，大约需要几秒...")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.top, 60)
                    } else if let report = model.report {
                        VerdictCard(report: report)
                        MetricsGrid(report: report)
                        StageSection(report: report)
                        TargetSection(report: report)
                        RawSection(report: report)

                        Text("只读探测。严格 PASS 只认真实文件读取（read=...B 或 metadata）；id ok 仅是 container id xattr，不算 PASS。仅用于你拥有的设备。")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.top, 4)
                    } else {
                        Text("准备中...")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.top, 60)
                    }
                }
                .padding()
            }
            .navigationTitle("worse_query 验证")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    if let report = model.report {
                        ShareLink(item: report.shareText) {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        model.run()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(model.running)
                }
            }
        }
        .onAppear {
            if model.report == nil && !model.running {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                    model.run()
                }
            }
        }
    }
}

// MARK: - Verdict

struct VerdictCard: View {
    let report: Diagnostics.Report

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: report.verdict.symbol)
                    .font(.system(size: 46))
                    .foregroundStyle(report.verdict.color)

                VStack(alignment: .leading, spacing: 4) {
                    Text(report.headline)
                        .font(.title2.bold())
                    Text(report.subheadline)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 0)
            }

            Divider()

            HStack {
                Label("iOS \(report.iosVersion)", systemImage: "iphone")
                Spacer()
                Text(report.device)
                    .font(.caption.monospaced())
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Button {
                UIPasteboard.general.string = report.shareText
            } label: {
                Label("复制结论", systemImage: "doc.on.doc")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .padding(16)
        .background(report.verdict.color.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(report.verdict.color.opacity(0.35), lineWidth: 1)
        )
    }
}

// MARK: - Metrics

struct MetricsGrid: View {
    let report: Diagnostics.Report

    var body: some View {
        HStack(spacing: 8) {
            MetricTile(title: "严格 PASS",
                       value: "\(report.reachableTargets)/\(report.targets.count)",
                       tint: .green)
            MetricTile(title: "文件读取",
                       value: "\(report.deepReads)",
                       tint: .purple)
            MetricTile(title: "id 访问",
                       value: "\(report.idReads)",
                       tint: .orange)
            MetricTile(title: "扫描容器",
                       value: "\(report.scanChildrenTotal)",
                       tint: .indigo)
        }
    }
}

struct MetricTile: View {
    let title: String
    let value: String
    let tint: Color

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.title3.bold().monospacedDigit())
                .foregroundStyle(tint)
            Text(title)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
        .background(tint.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Stages

struct StageSection: View {
    let report: Diagnostics.Report

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("阶段检查")
                .font(.headline)

            ForEach(report.stages.indices, id: \.self) { i in
                let stage = report.stages[i]

                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: stage.status.symbol)
                        .foregroundStyle(stage.status.color)
                        .font(.body)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(stage.title)
                            .font(.subheadline.weight(.semibold))
                        Text(stage.detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer(minLength: 0)
                }
                .padding(12)
                .background(Color.gray.opacity(0.07))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }
}

// MARK: - Targets

struct TargetSection: View {
    let report: Diagnostics.Report

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("目标路径")
                .font(.headline)

            ForEach(report.targets.indices, id: \.self) { i in
                TargetCard(target: report.targets[i])
            }
        }
    }
}

struct TargetCard: View {
    let target: Diagnostics.TargetResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(target.label)
                    .font(.subheadline.weight(.semibold))
                Spacer()
                StatusChip(status: target.status)
            }

            Text(target.path)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)

            Text(target.summaryLine)
                .font(.caption2)
                .foregroundStyle(.secondary)

            let visible = target.displayChildren
            ForEach(visible.indices, id: \.self) { j in
                let child = visible[j]

                Text(childLine(child))
                    .font(.caption2.monospaced())
                    .foregroundStyle(child.readBytes > 0 || child.metadataRead || child.idRead ? Color.green : Color.secondary)
                    .lineLimit(2)
            }
        }
        .padding(12)
        .background(Color.gray.opacity(0.07))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func childLine(_ child: Diagnostics.ChildResult) -> String {
        let id = String(child.containerID.prefix(28))
        let body = child.readBytes > 0
            ? "read \(child.readBytes)B"
            : (child.metadataRead ? "meta ok"
               : (child.idRead ? "id ok" : (child.error.isEmpty ? "no read" : child.error)))
        return "· \(String(child.name.prefix(8)))  id=\(id)  \(body)"
    }
}

struct StatusChip: View {
    let status: Diagnostics.Status

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: status.symbol)
                .font(.caption2)
            Text(status.text)
                .font(.caption2.weight(.bold))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(status.color.opacity(0.15))
        .foregroundStyle(status.color)
        .clipShape(Capsule())
    }
}

// MARK: - Raw log

struct RawSection: View {
    let report: Diagnostics.Report
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            Text(report.rawLog)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 8)
        } label: {
            Label("原始日志", systemImage: "doc.text.magnifyingglass")
                .font(.subheadline.weight(.semibold))
        }
        .padding(12)
        .background(Color.gray.opacity(0.07))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - Presentation helpers

extension Diagnostics.Verdict {
    var color: Color {
        switch self {
        case .pass: return .green
        case .partial: return .orange
        case .fail: return .red
        case .untestable: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .pass: return "checkmark.shield.fill"
        case .partial: return "exclamationmark.shield.fill"
        case .fail: return "xmark.shield.fill"
        case .untestable: return "questionmark.circle.fill"
        }
    }
}

extension Diagnostics.Status {
    var color: Color {
        switch self {
        case .pass: return .green
        case .fail: return .red
        case .warn: return .orange
        case .info: return .blue
        case .skip: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .pass: return "checkmark.circle.fill"
        case .fail: return "xmark.octagon.fill"
        case .warn: return "exclamationmark.triangle.fill"
        case .info: return "info.circle.fill"
        case .skip: return "minus.circle"
        }
    }
}