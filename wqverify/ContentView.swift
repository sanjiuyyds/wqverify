import SwiftUI
import Foundation

struct ContentView: View {
    var body: some View {
        if ProcessInfo.processInfo.arguments.contains("--hello") {
            HelloView()
        } else {
            DashboardView()
        }
    }
}

/// Kept from the original minimal harness: `dvt launch "<BUNDLE_ID> --hello"`
/// still dumps argv / home and writes result.txt to Documents.
struct HelloView: View {
    @State private var text = "running..."

    var body: some View {
        ScrollView {
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .onAppear {
            let args = ProcessInfo.processInfo.arguments
            let out = """
            Hello from launch argument

            argv = \(args)
            home = \(NSHomeDirectory())
            uid  = \(getuid())
            pid  = \(getpid())
            """
            text = out
            writeResult("result.txt", out)
        }
    }

    private func writeResult(_ name: String, _ content: String) {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = dir.appendingPathComponent(name)
        try? content.write(to: url, atomically: true, encoding: .utf8)
    }
}