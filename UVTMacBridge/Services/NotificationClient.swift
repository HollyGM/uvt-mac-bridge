import Foundation

enum NotificationClientError: LocalizedError {
    case hostNotAllowed(String)
    case invalidHost
    case encoding
    case http(Int, String)

    var errorDescription: String? {
        switch self {
        case .hostNotAllowed(let host): return "Host de retorno recusado pela política de segurança local: \(host)"
        case .invalidHost: return "Host de retorno inválido"
        case .encoding: return "Não foi possível serializar a resposta"
        case .http(let code, let body): return "UVT respondeu HTTP \(code) ao receber a notificação: \(body)"
        }
    }
}

/// Entrega a resposta ao navegador: a UVT recebe uma "notificação" identificada pelo `token` da
/// requisição e a repassa à página (SignalR).
struct NotificationClient: Sendable {
    /// Lista fechada de hosts; a comparação é exata, inclusive a barra final.
    static let allowedHosts: Set<String> = [
        "https://apidev.set.rn.gov.br/usuarios/",
        "https://apihom2.set.rn.gov.br/usuarios/",
        "https://api.set.rn.gov.br/usuarios/",
        "https://apidev.sefaz.rn.gov.br/usuarios/",
        "https://apihom2.sefaz.rn.gov.br/usuarios/",
        "https://apihom.sefaz.rn.gov.br/usuarios/",
        "https://api.sefaz.rn.gov.br/usuarios/"
    ]

    let transport: UVTTransport

    static func isAllowed(host: String) -> Bool {
        allowedHosts.contains(host)
    }

    /// Endpoints de autenticação: HTTPS e domínio SEFAZ/RN ou SET/RN (inclui subdomínios).
    static func isAllowed(endpoint url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https", let host = url.host?.lowercased() else { return false }
        return ["sefaz.rn.gov.br", "set.rn.gov.br"].contains { host == $0 || host.hasSuffix("." + $0) }
    }

    func send(response: BrowserResponse, action: String, host: String, token: String) async throws {
        guard Self.isAllowed(host: host) else { throw NotificationClientError.hostNotAllowed(host) }
        guard let url = URL(string: host + "v1/notificacao/view/enviar") else { throw NotificationClientError.invalidHost }

        let payload: String
        do {
            payload = try response.jsonData().base64EncodedString()
        } catch {
            throw NotificationClientError.encoding
        }

        let first = try await post(url: url, action: action, token: token, payload: payload)
        guard !(200...299).contains(first.status) else { return }

        // Se a notificação falhar, tenta avisar a página do erro.
        AppLogger.shared.error("Notificação recusada (HTTP \(first.status)); reenviando como erro")
        let fallbackPayload = String(
            data: try BrowserResponse(type: "error", error: first.body, data: nil).jsonData(),
            encoding: .utf8
        ) ?? ""
        let second = try await post(url: url, action: action, token: token, payload: fallbackPayload)
        guard (200...299).contains(second.status) else {
            throw NotificationClientError.http(second.status, second.body)
        }
    }

    private func post(url: URL, action: String, token: String, payload: String) async throws -> UVTHTTPResponse {
        let title = "uvt-ms-action:\(action)"
        let body: [String: Any] = [
            "Titulo": title,
            "Conteudo": title,
            "Contexto": "",
            "Dados": ["payload": payload],
            "UserSystem": true,
            "Token": token
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.withoutEscapingSlashes]) else {
            throw NotificationClientError.encoding
        }
        return try await transport.postJSON(url, body: data)
    }
}
