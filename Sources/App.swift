//
//  App.swift
//  Minimal verification harness for the worse_query sandbox escape PoC.
//

import SwiftUI

@main
struct WQDiagApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

final class DiagModel: ObservableObject {
    @Published var report = ""
    @Published var running = false

    func run() {
        guard !running else { return }
        running = true
        report = "Running diagnostics...\n"

        let group = Bundle.main.object(forInfoDictionaryKey: "WQAppGroup") as? String ?? ""

        DispatchQueue.global(qos: .userInitiated).async {
            let text = Diagnostics.run(group: group)
            DispatchQueue.main.async {
                self.report = text
                self.running = false
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var model = DiagModel()

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Button {
                        model.run()
                    } label: {
                        Label(model.running ? "Running..." : "Run verification",
                              systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.running)

                    ShareLink(item: model.report) {
                        Label("Share report", systemImage: "square.and.arrow.up")
                    }
                    .disabled(model.report.isEmpty || model.running)
                }
                .padding(.horizontal)

                Text("Read-only PoC. Use only on a device you own.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)

                ScrollView {
                    Text(model.report)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(Color.gray.opacity(0.08))
            }
            .padding(.top, 8)
            .navigationTitle("worse_query verify")
            .navigationBarTitleDisplayMode(.inline)
        }
        .onAppear {
            if model.report.isEmpty {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                    model.run()
                }
            }
        }
    }
}