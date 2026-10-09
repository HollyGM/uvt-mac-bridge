import Foundation
import Security

struct UVTHTTPResponse: Sendable {
    let status: Int
    let body: String
}

/// Transporte HTTP usado pelo fluxo UVT. Respostas HTTP de qualquer status (inclusive 4xx/5xx) são
/// devolvidas normalmente; só falhas de transporte (DNS, TLS, timeout) viram erro.
protocol UVTTransport: Sendable {
    /// - Parameters:
    ///   - identity: certificado de cliente apresentado no handshake TLS (autenticação mútua).
    ///   - intermediates: cadeia enviada junto do certificado de cliente.
    func get(
        _ url: URL,
        headers: [String: String],
        identity: SecIdentity?,
        intermediates: [SecCertificate]
    ) async throws -> UVTHTTPResponse

    func postJSON(_ url: URL, body: Data) async throws -> UVTHTTPResponse
}

extension UVTTransport {
    func get(_ url: URL) async throws -> UVTHTTPResponse {
        try await get(url, headers: [:], identity: nil, intermediates: [])
    }
}

final class UVTHTTPClient: UVTTransport {
    private let timeout: TimeInterval
    private let trustAnchors: [SecCertificate]
    private let secureTransport: SecureTransportClient

    /// - Parameter trustAnchors: raízes adicionais aceitas para o servidor (além das do sistema).
    ///   Vazio em produção; usado pelos testes com um servidor local e CA própria.
    init(timeout: TimeInterval = 30, trustAnchors: [SecCertificate] = []) {
        self.timeout = timeout
        self.trustAnchors = trustAnchors
        self.secureTransport = SecureTransportClient(timeout: timeout, trustAnchors: trustAnchors)
    }

    func get(
        _ url: URL,
        headers: [String: String],
        identity: SecIdentity?,
        intermediates: [SecCertificate]
    ) async throws -> UVTHTTPResponse {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "GET"
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if identity != nil {
            // Chamadas com certificado de cliente: o IIS da UVT pede o certificado por renegociação TLS,
            // o que o URLSession atual não completa (-1206). Ver SecureTransportClient.
            return try await secureTransport.get(url, headers: headers, identity: identity, intermediates: intermediates)
        }
        return try await perform(request, identity: identity, intermediates: intermediates)
    }

    func postJSON(_ url: URL, body: Data) async throws -> UVTHTTPResponse {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return try await perform(request, identity: nil, intermediates: [])
    }

    private func perform(
        _ request: URLRequest,
        identity: SecIdentity?,
        intermediates: [SecCertificate]
    ) async throws -> UVTHTTPResponse {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12

        // Uma sessão por chamada: o certificado de cliente fica atrelado ao delegate e nenhuma
        // sessão TLS é reaproveitada entre usuários/certificados diferentes.
        let delegate = SessionDelegate(identity: identity, intermediates: intermediates, trustAnchors: trustAnchors)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        return try await withCheckedThrowingContinuation { continuation in
            session.dataTask(with: request) { data, response, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let http = response as? HTTPURLResponse else {
                    continuation.resume(throwing: URLError(.badServerResponse))
                    return
                }
                let body = String(data: data ?? Data(), encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                continuation.resume(returning: UVTHTTPResponse(status: http.statusCode, body: body))
            }.resume()
        }
    }
}

private final class SessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let identity: SecIdentity?
    private let intermediates: [SecCertificate]
    private let trustAnchors: [SecCertificate]

    init(identity: SecIdentity?, intermediates: [SecCertificate], trustAnchors: [SecCertificate]) {
        self.identity = identity
        self.intermediates = intermediates
        self.trustAnchors = trustAnchors
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let method = challenge.protectionSpace.authenticationMethod
        if method == NSURLAuthenticationMethodServerTrust, !trustAnchors.isEmpty,
           let trust = challenge.protectionSpace.serverTrust {
            SecTrustSetAnchorCertificates(trust, trustAnchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, false)
            if SecTrustEvaluateWithError(trust, nil) {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
            return
        }
        guard method == NSURLAuthenticationMethodClientCertificate, let identity else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let credential = URLCredential(identity: identity, certificates: intermediates.isEmpty ? nil : intermediates, persistence: .none)
        completionHandler(.useCredential, credential)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // A UVT devolve o resultado do requestpass com HTTP 302 e o JSON no corpo; esse 302 é a
        // resposta final. Seguir o redirecionamento perderia o corpo.
        // Os demais redirecionamentos (301/303/307/308) são seguidos.
        completionHandler(response.statusCode == 302 ? nil : request)
    }
}
