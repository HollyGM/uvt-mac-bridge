import Foundation
import Security

enum ProxyLoginError: LocalizedError {
    case invalidServerResponse
    case decryptionFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidServerResponse:
            return "Resposta de requestpass sem result.password/result.certificado"
        case .decryptionFailed(let detail):
            return "Não foi possível descriptografar a senha com o certificado selecionado (\(detail)). Verifique o PIN do token e a permissão de acesso à chave no Keychain."
        }
    }
}

/// Credenciais do usuário usadas no fluxo. `decrypt` aplica a chave privada (RSA PKCS#1 v1.5).
struct LoginCredential {
    let certificate: SecCertificate
    let identity: SecIdentity?
    let intermediates: [SecCertificate]
    let decrypt: (Data) throws -> Data
}

/// Fluxo de login da UVT.
///
/// Sequência, sempre com GET em `url?<params>&action=<ação>` e certificado de cliente no TLS:
///
///     requestpass ─┬─ 302 ─▶ decifra `result.password`, recifra com `result.certificado`
///                  │         ─▶ authenticate (header SET-CERPWD) ─▶ resposta final
///                  ├─ 407 ─▶ pede senha SIGAT ─▶ register ─▶ 201 ─▶ requestpass
///                  └─ 400/404 (senha inválida) ─▶ avisa ─▶ pede senha SIGAT ─▶ register
struct ProxyLoginFlow {
    /// Teto de chamadas HTTP por login, para evitar laços infinitos caso o servidor fique alternando 407/201.
    static let maxRequests = 12

    let transport: UVTTransport
    let credential: LoginCredential
    let prompts: UserPrompting
    let log: @Sendable (String) -> Void

    func run(url: URL, params: [String: JSONValue]) async -> BrowserResponse {
        var action = "requestpass"
        var headers: [String: String] = [:]

        for _ in 0..<Self.maxRequests {
            var query = params
            query["action"] = .string(action)

            let target: URL
            do {
                target = try Self.queryURL(base: url, params: query)
            } catch {
                return .failure("Can't get parameters")
            }

            let http: UVTHTTPResponse
            do {
                http = try await transport.get(
                    target,
                    headers: headers,
                    identity: credential.identity,
                    intermediates: credential.intermediates
                )
            } catch {
                let nsError = error as NSError
                log("Falha de transporte em \(action): \(nsError.domain) \(nsError.code) \(error.localizedDescription)")
                return .failure(error.localizedDescription, status: 0)
            }
            log("\(action) → HTTP \(http.status)\(Self.pageTitle(in: http.body).map { " (página: \($0))" } ?? "")")

            switch http.status {
            case 302:
                do {
                    headers = try authenticateHeaders(fromRequestPassBody: http.body)
                    action = "authenticate"
                } catch {
                    return .failure(error.localizedDescription)
                }

            case 201:
                // Senha registrada; volta ao início do fluxo.
                headers = [:]
                action = "requestpass"

            case 407, 404, 400:
                if http.status != 407 {
                    await prompts.showInvalidSigatPassword()
                }
                guard let password = await prompts.requestSigatPassword(),
                      !password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    return .failure("Acesso negado. ", status: 403)
                }
                do {
                    headers = try registerHeaders(sigatPassword: password)
                    action = "register"
                } catch {
                    return .failure(error.localizedDescription)
                }

            default:
                return Self.finalResponse(from: http)
            }
        }
        return .failure("Número máximo de tentativas de autenticação excedido")
    }

    // MARK: - Etapas

    /// 302 de `requestpass`: `{"result":{"password":"<RSA(cert do usuário)>","certificado":"<cert do servidor>"}}`.
    /// A senha volta recifrada com a chave pública do servidor no header `SET-CERPWD`.
    func authenticateHeaders(fromRequestPassBody body: String) throws -> [String: String] {
        guard let result = JSONValue.parse(body)?["result"],
              let encryptedPassword = result["password"]?.stringValue,
              let serverCertificateText = result["certificado"]?.stringValue,
              let ciphertext = Data(base64Encoded: encryptedPassword) else {
            throw ProxyLoginError.invalidServerResponse
        }
        let serverCertificate = try UVTCrypto.certificate(fromServerText: serverCertificateText)

        let clear: Data
        do {
            clear = try credential.decrypt(ciphertext)
        } catch {
            throw ProxyLoginError.decryptionFailed(error.localizedDescription)
        }
        // O texto é ASCII; bytes fora de 7 bits viram `?`.
        let clearText = String(decoding: clear.map { $0 < 128 ? $0 : UInt8(ascii: "?") }, as: UTF8.self)
        let reencrypted = try UVTCrypto.rsaEncryptPKCS1(UVTCrypto.asciiBytes(clearText), with: serverCertificate)
        return ["SET-CERPWD": reencrypted.base64EncodedString()]
    }

    /// Primeiro acesso: a senha SIGAT é cifrada em DES-CBC com chave aleatória (enviada nos headers
    /// `SET-CERPWD-KEY`/`-IV`) e o resultado é cifrado com a chave pública do próprio certificado
    /// do usuário, de modo que só ele consegue recuperá-lo nos acessos seguintes.
    func registerHeaders(sigatPassword: String) throws -> [String: String] {
        let key = try UVTCrypto.generateDESKey()
        let iv = try UVTCrypto.randomBytes(8)
        let desCipher = try UVTCrypto.desCBCEncrypt(UVTCrypto.asciiBytes(sigatPassword), key: key, iv: iv)
        let wrapped = try UVTCrypto.rsaEncryptPKCS1(
            UVTCrypto.asciiBytes(desCipher.base64EncodedString()),
            with: credential.certificate
        )
        return [
            "SET-CERPWD": wrapped.base64EncodedString(),
            "SET-CERPWD-KEY": key.base64EncodedString(),
            "SET-CERPWD-IV": iv.base64EncodedString()
        ]
    }

    /// `OnReceivedOtherResponse`: 200/300 com JSON vira `result`; o resto vira `error` com o status.
    static func finalResponse(from http: UVTHTTPResponse) -> BrowserResponse {
        if http.status == 200 || http.status == 300 {
            guard let json = JSONValue.parse(http.body), json.objectValue != nil else {
                return .failure("Resposta da UVT não é um objeto JSON", status: http.status)
            }
            return .result(json)
        }
        // O IIS responde erros com páginas HTML de ~1,4 MB; o navegador só precisa do começo.
        let message = http.body.isEmpty ? "HTTP \(http.status)" : String(http.body.prefix(maxErrorMessageLength))
        return .failure(message, status: http.status)
    }

    static let maxErrorMessageLength = 4000

    /// Título de uma página HTML de erro, para o log (nunca o corpo inteiro).
    static func pageTitle(in body: String) -> String? {
        guard let open = body.range(of: "<title>", options: .caseInsensitive),
              let close = body.range(of: "</title>", options: .caseInsensitive, range: open.upperBound..<body.endIndex) else { return nil }
        let title = body[open.upperBound..<close.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
        return title.isEmpty ? nil : String(title.prefix(120))
    }

    /// Monta `url?k=v&k=v` sem recodificar os valores, como a UVT espera.
    static func queryURL(base: URL, params: [String: JSONValue]) throws -> URL {
        let query = params.keys.sorted().map { "\($0)=\(params[$0]?.queryText ?? "")" }.joined(separator: "&")
        let separator = base.absoluteString.contains("?") ? "&" : "?"
        let text = base.absoluteString + separator + query
        if let url = URL(string: text) { return url }
        let allowed = CharacterSet.urlQueryAllowed.union(CharacterSet(charactersIn: "%"))
        guard let escaped = text.addingPercentEncoding(withAllowedCharacters: allowed),
              let url = URL(string: escaped) else {
            throw ProxyLoginError.invalidServerResponse
        }
        return url
    }
}
