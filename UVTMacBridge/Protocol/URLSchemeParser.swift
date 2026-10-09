import Foundation

enum URLSchemeParserError: LocalizedError {
    case invalidScheme
    case emptyPayload
    case invalidBase64
    case invalidJSON(String)

    var errorDescription: String? {
        switch self {
        case .invalidScheme: return "Protocolo inválido; esperado sefazrnuvt://"
        case .emptyPayload: return "Payload vazio"
        case .invalidBase64: return "Payload não é Base64 válido"
        case .invalidJSON(let detail): return "JSON da requisição inválido: \(detail)"
        }
    }
}

struct URLSchemeParser {
    func parse(url: URL) throws -> BrowserRequest {
        guard url.scheme?.lowercased() == "sefazrnuvt" else {
            throw URLSchemeParserError.invalidScheme
        }

        let absolute = url.absoluteString
        guard let range = absolute.range(of: "sefazrnuvt://", options: [.caseInsensitive]) else {
            throw URLSchemeParserError.invalidScheme
        }

        var encoded = String(absolute[range.upperBound...])
        encoded = encoded.removingPercentEncoding ?? encoded
        encoded = encoded.trimmingCharacters(in: .whitespacesAndNewlines)
        // Alguns navegadores acrescentam "/" ao final de URLs de protocolo. Só as barras finais são
        // descartadas, para não corromper um Base64 padrão que contenha "/" no meio.
        while encoded.hasSuffix("/") { encoded.removeLast() }
        guard !encoded.isEmpty else { throw URLSchemeParserError.emptyPayload }

        // Aceita Base64 normal e URL-safe, inclusive sem padding.
        encoded = encoded.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = encoded.count % 4
        if remainder != 0 {
            encoded += String(repeating: "=", count: 4 - remainder)
        }

        guard let data = Data(base64Encoded: encoded, options: [.ignoreUnknownCharacters]) else {
            throw URLSchemeParserError.invalidBase64
        }

        do {
            return try JSONDecoder().decode(BrowserRequest.self, from: data)
        } catch {
            let preview = String(data: data, encoding: .utf8) ?? "<dados não UTF-8>"
            AppLogger.shared.error("Payload decodificado: \(preview)")
            throw URLSchemeParserError.invalidJSON(error.localizedDescription)
        }
    }
}
