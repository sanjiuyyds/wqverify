import SwiftUI

struct ContentView: View {
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

            // ★ 启动参数分发入口
            // 用法：dvt launch "<BUNDLE_ID> --hello"
            if args.contains("--hello") {
                let out = """
                Hello from launch argument

                argv = \(args)
                home = \(NSHomeDirectory())
                uid  = \(getuid())
                pid  = \(getpid())
                """
                text = out
                writeResult("result.txt", out)
                return
            }

            // 默认行为
            let out = """
            默认路径（无启动参数）

            argv = \(args)
            home = \(NSHomeDirectory())
            """
            text = out
            writeResult("result.txt", out)
        }
    }

    /// 写到 Documents/，可用 `pymobiledevice3 apps pull` 取回
    private func writeResult(_ name: String, _ content: String) {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = dir.appendingPathComponent(name)
        try? content.write(to: url, atomically: true, encoding: .utf8)
    }
}
