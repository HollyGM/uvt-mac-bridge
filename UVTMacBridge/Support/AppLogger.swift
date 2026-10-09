import Foundation

final class AppLogger: @unchecked Sendable {
    static let shared = AppLogger()
    var onEntry: ((String) -> Void)?

    /// Arquivo de log do app. Nunca recebe senhas, cabeçalhos de autenticação nem o corpo das respostas.
    static let fileURL: URL = FileManager.default
        .urls(for: .libraryDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("Logs/UVTMacBridge/uvt-mac-bridge.log")

    private static let maxFileBytes = 5_000_000

    private let formatter: DateFormatter
    private let fileQueue = DispatchQueue(label: "br.local.uvtmacbridge.log")

    private init() {
        formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
    }

    func info(_ message: String) { write("INFO", message) }
    func error(_ message: String) { write("ERRO", message) }

    private func write(_ level: String, _ message: String) {
        let line = "[\(formatter.string(from: Date()))] [\(level)] \(redact(message))"
        NSLog("%@", line)
        appendToFile(line)
        DispatchQueue.main.async { [weak self] in
            self?.onEntry?(line)
        }
    }

    private func appendToFile(_ line: String) {
        let stamped = "\(ISO8601DateFormatter().string(from: Date())) \(line)\n"
        fileQueue.async {
            let url = Self.fileURL
            let manager = FileManager.default
            try? manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            if let size = (try? manager.attributesOfItem(atPath: url.path)[.size]) as? Int, size > Self.maxFileBytes {
                let old = url.appendingPathExtension("old")
                try? manager.removeItem(at: old)
                try? manager.moveItem(at: url, to: old)
            }
            if !manager.fileExists(atPath: url.path) {
                manager.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            guard let handle = try? FileHandle(forWritingTo: url), let data = stamped.data(using: .utf8) else { return }
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        }
    }

    private func redact(_ text: String) -> String {
        // Evita registrar tokens JWT completos por acidente.
        text.replacingOccurrences(
            of: #"eyJ[A-Za-z0-9_\-\.]{24,}"#,
            with: "<token-redigido>",
            options: .regularExpression
        )
    }
}
