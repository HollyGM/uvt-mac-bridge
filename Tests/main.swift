import Foundation
import Security
import CommonCrypto

// Testes de protocolo do UVT Mac Bridge. Executados por Tests/run-tests.sh.
// O "servidor UVT" simulado segue o protocolo que o app implementa (ver README).

var failures = 0
var checks = 0

func check(_ condition: @autoclosure () -> Bool, _ name: String, file: StaticString = #file, line: UInt = #line) {
    checks += 1
    if condition() {
        print("  ok   \(name)")
    } else {
        failures += 1
        print("  FAIL \(name)  (linha \(line))")
    }
}

func section(_ title: String) { print("\n\(title)") }

let env = ProcessInfo.processInfo.environment
let dir = URL(fileURLWithPath: env["UVT_TEST_DIR"]!)
let openssl = env["UVT_TEST_OPENSSL"] ?? "openssl"

func read(_ name: String) -> Data { try! Data(contentsOf: dir.appendingPathComponent(name)) }
func readText(_ name: String) -> String { String(decoding: read(name), as: UTF8.self) }

@discardableResult
func run(_ arguments: [String], input: Data? = nil) -> (status: Int32, output: Data) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = [openssl] + arguments
    process.currentDirectoryURL = dir
    let out = Pipe(), inPipe = Pipe()
    process.standardOutput = out
    process.standardError = Pipe()
    process.standardInput = inPipe
    try! process.run()
    if let input { inPipe.fileHandleForWriting.write(input) }
    inPipe.fileHandleForWriting.closeFile()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, data)
}

// Os certificados de teste vão para um Keychain temporário, nunca para o Keychain de login do usuário.
let temporaryKeychain: SecKeychain = {
    var keychain: SecKeychain?
    let password = "test"
    let path = dir.appendingPathComponent("teste.keychain").path
    let status = SecKeychainCreate(path, UInt32(password.utf8.count), password, false, nil, &keychain)
    precondition(status == errSecSuccess, "SecKeychainCreate falhou: \(status)")
    return keychain!
}()

func loadIdentity(_ file: String) -> (identity: SecIdentity, certificate: SecCertificate, privateKey: SecKey) {
    var items: CFArray?
    let options: [String: Any] = [kSecImportExportPassphrase as String: "test", kSecImportExportKeychain as String: temporaryKeychain]
    let status = SecPKCS12Import(read(file) as CFData, options as CFDictionary, &items)
    precondition(status == errSecSuccess, "SecPKCS12Import falhou: \(status)")
    let entry = (items as! [[String: Any]])[0]
    let identity = entry[kSecImportItemIdentity as String] as! SecIdentity
    var cert: SecCertificate?
    SecIdentityCopyCertificate(identity, &cert)
    var key: SecKey?
    SecIdentityCopyPrivateKey(identity, &key)
    return (identity, cert!, key!)
}

func rsaDecrypt(_ key: SecKey, _ data: Data) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let clear = SecKeyCreateDecryptedData(key, .rsaEncryptionPKCS1, data as CFData, &error) else {
        throw error!.takeRetainedValue()
    }
    return clear as Data
}

func desDecrypt(_ cipher: Data, key: Data, iv: Data) -> Data? {
    var out = Data(count: cipher.count + 8)
    var written = 0
    let capacity = out.count
    let status = out.withUnsafeMutableBytes { o in cipher.withUnsafeBytes { c in key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(kCCOptionPKCS7Padding),
                k.baseAddress, 8, v.baseAddress, c.baseAddress, cipher.count, o.baseAddress, capacity, &written)
    } } } }
    return status == kCCSuccess ? out.prefix(written) : nil
}

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

// MARK: - Servidor UVT simulado

final class MockUVT: UVTTransport, @unchecked Sendable {
    let sigat: String
    let serverKey: SecKey
    var stored: (blob: String, key: Data, iv: Data)?
    var actions: [String] = []
    var seenIdentity: [Bool] = []
    var forcedStatus: Int?

    init(sigat: String, serverKey: SecKey) { self.sigat = sigat; self.serverKey = serverKey }

    func get(_ url: URL, headers: [String: String], identity: SecIdentity?, intermediates: [SecCertificate]) async throws -> UVTHTTPResponse {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let action = items.first { $0.name == "action" }?.value ?? ""
        actions.append(action)
        seenIdentity.append(identity != nil)
        if let forcedStatus { return UVTHTTPResponse(status: forcedStatus, body: #"{"erro":"forçado"}"#) }

        switch action {
        case "requestpass":
            guard let stored else { return UVTHTTPResponse(status: 407, body: "") }
            let body = #"{"result":{"password":"\#(stored.blob)","certificado":\#(jsonString(readText("uvt.pem")))}}"#
            return UVTHTTPResponse(status: 302, body: body)
        case "register":
            guard let blob = headers["SET-CERPWD"], let key = headers["SET-CERPWD-KEY"].flatMap({ Data(base64Encoded: $0) }),
                  let iv = headers["SET-CERPWD-IV"].flatMap({ Data(base64Encoded: $0) }) else {
                return UVTHTTPResponse(status: 400, body: "header ausente")
            }
            stored = (blob, key, iv)
            return UVTHTTPResponse(status: 201, body: "")
        case "authenticate":
            guard let stored, let header = headers["SET-CERPWD"], let raw = Data(base64Encoded: header),
                  let inner = try? rsaDecrypt(serverKey, raw),                       // só a chave da UVT abre
                  let desCipher = Data(base64Encoded: String(decoding: inner, as: UTF8.self)),
                  let clear = desDecrypt(desCipher, key: stored.key, iv: stored.iv) else {
                return UVTHTTPResponse(status: 400, body: "inválido")
            }
            return String(decoding: clear, as: UTF8.self) == sigat
                ? UVTHTTPResponse(status: 200, body: #"{"token":"jwt-de-teste","usuario":{"cpf":"12345678901"}}"#)
                : UVTHTTPResponse(status: 400, body: "senha sigat")
        default:
            return UVTHTTPResponse(status: 500, body: "ação desconhecida")
        }
    }

    func postJSON(_ url: URL, body: Data) async throws -> UVTHTTPResponse { UVTHTTPResponse(status: 200, body: "") }
}

func jsonString(_ text: String) -> String {
    String(decoding: try! JSONEncoder().encode(text), as: UTF8.self)
}

final class ScriptedPrompts: UserPrompting, @unchecked Sendable {
    var passwords: [String?]
    var invalidMessages = 0
    var asked = 0
    init(_ passwords: [String?]) { self.passwords = passwords }
    func requestSigatPassword() async -> String? { asked += 1; return passwords.isEmpty ? nil : passwords.removeFirst() }
    func showInvalidSigatPassword() async { invalidMessages += 1 }
}

final class RecordingTransport: UVTTransport, @unchecked Sendable {
    var posts: [(url: URL, body: [String: Any])] = []
    var statuses: [Int]
    var getResponse = UVTHTTPResponse(status: 200, body: "{}")
    var lastGet: URL?
    init(statuses: [Int] = [200]) { self.statuses = statuses }
    func get(_ url: URL, headers: [String: String], identity: SecIdentity?, intermediates: [SecCertificate]) async throws -> UVTHTTPResponse {
        lastGet = url
        return getResponse
    }
    func postJSON(_ url: URL, body: Data) async throws -> UVTHTTPResponse {
        posts.append((url, try JSONSerialization.jsonObject(with: body) as! [String: Any]))
        return UVTHTTPResponse(status: statuses.isEmpty ? 200 : statuses.removeFirst(), body: "falhou")
    }
}

// MARK: - Testes

func testParser() {
    section("Parser do protocolo sefazrnuvt://")
    let parser = URLSchemeParser()
    let json = #"{"method":"proxyRequest","host":"https://api.sefaz.rn.gov.br/usuarios/","token":"tk","url":"https://api.sefaz.rn.gov.br/autbasic/x","params":{"cpf":12345678901,"n":1.5,"ok":true}}"#
    let b64 = Data(json.utf8).base64EncodedString()
    let request = try? parser.parse(url: URL(string: "sefazrnuvt://\(b64)")!)
    check(request?.method == "proxyRequest", "decodifica method")
    check(request?.url == "https://api.sefaz.rn.gov.br/autbasic/x", "decodifica url (campo ausente no protótipo)")
    check(request?.params?["cpf"] == .integer(12345678901), "preserva inteiros longos")
    let withSlash = try? parser.parse(url: URL(string: "sefazrnuvt://\(b64)/")!)
    check(withSlash?.method == "proxyRequest", "aceita barra final acrescentada pelo navegador")
    let urlSafe = b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    check((try? parser.parse(url: URL(string: "sefazrnuvt://\(urlSafe)")!))?.method == "proxyRequest", "aceita Base64 URL-safe sem padding")
    check((try? parser.parse(url: URL(string: "sefazrnuvt://eyJtZXRob2QiOiJ2ZXJzaW9uIn0=")!))?.method == "version", "payload do TEST_VERSION.command")
}

func testResponseEnvelope() {
    section("Envelope de resposta ao navegador")
    let ok = String(decoding: try! BrowserResponse.result(.object(["a": .integer(1)])).jsonData(), as: UTF8.self)
    check(ok.contains(#""error":null"#) && ok.contains(#""type":"result""#), "result serializa error:null explicitamente")
    let err = String(decoding: try! BrowserResponse.failure("Acesso negado. ", status: 403).jsonData(), as: UTF8.self)
    check(err.contains(#""status":403"#) && err.contains(#""type":"error""#), "error carrega data.status")
    check(JSONValue.bool(true).queryText == "True" && JSONValue.null.queryText == "", "queryText: booleanos como True/False e nulo vazio")
}

func testCrypto(user: (identity: SecIdentity, certificate: SecCertificate, privateKey: SecKey)) {
    section("Criptografia (interoperabilidade com OpenSSL)")
    let key = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    let iv = Data([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])
    let plain = Data("Senha!Sigat123".utf8)
    let mine = try! UVTCrypto.desCBCEncrypt(plain, key: key, iv: iv)
    let ref = run(["enc", "-des-cbc", "-provider", "legacy", "-provider", "default", "-K", hex(key), "-iv", hex(iv)], input: plain)
    if ref.status == 0 {
        check(ref.output == mine, "DES-CBC/PKCS7 idêntico ao openssl enc -des-cbc")
    } else {
        print("  skip DES vs openssl (provider legacy indisponível)")
    }
    check(desDecrypt(mine, key: key, iv: iv) == plain, "DES-CBC faz ida e volta")

    for _ in 0..<50 {
        let k = try! UVTCrypto.generateDESKey()
        if !k.allSatisfy({ $0.nonzeroBitCount % 2 == 1 }) { check(false, "chave DES com paridade ímpar"); break }
    }
    check(true, "50 chaves DES geradas com paridade ímpar")

    let cipher = try! UVTCrypto.rsaEncryptPKCS1(Data("segredo".utf8), with: user.certificate)
    check((try? rsaDecrypt(user.privateKey, cipher)) == Data("segredo".utf8), "RSA PKCS#1: cifra com o certificado, decifra com a chave")
    try! cipher.write(to: dir.appendingPathComponent("c.bin"))
    let viaOpenSSL = run(["pkeyutl", "-decrypt", "-inkey", "user.key", "-in", "c.bin"])
    check(String(decoding: viaOpenSSL.output, as: UTF8.self) == "segredo", "openssl pkeyutl -decrypt (padrão PKCS#1) abre o que o app cifrou")

    check((try? UVTCrypto.certificate(fromServerText: readText("uvt.pem"))) != nil, "aceita certificado do servidor em PEM")
    let base64Only = readText("uvt.pem").components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
    check((try? UVTCrypto.certificate(fromServerText: base64Only)) != nil, "aceita certificado do servidor em Base64 puro")
    check((try? UVTCrypto.certificate(fromServerText: "lixo")) == nil, "rejeita certificado inválido")
    check(UVTCrypto.asciiBytes("aç") == Data([0x61, 0x3F]), "ASCII de 7 bits: caractere fora dele vira '?'")
}

func testCertificateInfo(user: (identity: SecIdentity, certificate: SecCertificate, privateKey: SecKey)) {
    section("Metadados de certificado (escolha padrão no seletor)")
    let ca = SecCertificateCreateWithData(nil, pemToDER(readText("ca.pem")) as CFData)!
    check(CertificateService.isSelfSigned(ca) && !CertificateService.isSelfSigned(user.certificate), "distingue autoassinado de emitido por AC")
    let expiry = CertificateService.notAfter(of: user.certificate)
    check(expiry != nil && expiry! > Date() && expiry! < Date().addingTimeInterval(3 * 86_400), "lê a data de validade (\(expiry.map { "\($0)" } ?? "nil"))")
    let usable = CertificateIdentity(id: "a", displayName: "x", derBase64: "", notAfter: Date().addingTimeInterval(86_400), isSelfSigned: false)
    let expired = CertificateIdentity(id: "b", displayName: "x", derBase64: "", notAfter: Date().addingTimeInterval(-86_400), isSelfSigned: false)
    let selfSigned = CertificateIdentity(id: "c", displayName: "x", derBase64: "", notAfter: Date().addingTimeInterval(86_400), isSelfSigned: true)
    check(usable.isLikelyUsable && !expired.isLikelyUsable && !selfSigned.isLikelyUsable, "só sugere certificados válidos e não autoassinados")
}

func testChainBuilder() async {
    section("Cadeia do certificado de cliente (AIA)")
    let leaf = SecCertificateCreateWithData(nil, pemToDER(readText("chainleaf.pem")) as CFData)!
    func name(_ c: SecCertificate) -> String { (SecCertificateCopySubjectSummary(c) as String?) ?? "?" }
    let p7b = read("chain.p7b")

    check(CertificateChainBuilder.caIssuerURLs(of: leaf).map(\.absoluteString) == ["http://repo.test/ac/chain.p7b"], "lê o ponteiro AIA 'CA Issuers' do certificado")
    check(CertificateChainBuilder.certificates(in: p7b).count == 3, "lê certificados de um pacote PKCS#7 (.p7b)")

    let cache = dir.appendingPathComponent("chain-cache")
    let fetched = FetchCounter()
    var builder = CertificateChainBuilder(fetch: { url in fetched.count += 1; return url.host == "repo.test" ? p7b : nil }, cacheDirectory: cache, log: { _ in })
    let chain = builder.intermediates(for: leaf)
    check(chain.map(name) == ["Test Mid 2", "Test Mid 1"], "completa a cadeia pelo AIA, na ordem emissor→raiz e sem a raiz (\(chain.map(name)))")
    check(fetched.count == 1, "baixa o pacote uma única vez")
    let cached = (try? FileManager.default.contentsOfDirectory(atPath: cache.path))?.filter { $0.hasSuffix(".der") }.count ?? 0
    check(cached == 3, "guarda os certificados no cache (\(cached))")

    // Segunda chamada, sem rede: o cache basta
    let offline = FetchCounter()
    builder.fetch = { _ in offline.count += 1; return nil }
    check(builder.intermediates(for: leaf).map(name) == ["Test Mid 2", "Test Mid 1"] && offline.count == 0, "usa o cache e não toca na rede")

    // Sem cache e sem rede: devolve o que houver e avisa
    var logged: [String] = []
    let lock = NSLock()
    let noCache = CertificateChainBuilder(fetch: { _ in nil }, cacheDirectory: nil, log: { lock.lock(); logged.append($0); lock.unlock() })
    let partial = noCache.intermediates(for: leaf)
    check(partial.isEmpty && logged.contains { $0.contains("incompleta") }, "offline e sem cache: não inventa cadeia e registra o aviso")

    // GET HTTP puro (repositórios das ACs usam http://, que o ATS bloqueia no URLSession)
    let httpPort = readText("http.port")
    let viaHTTP = CertificateChainBuilder.plainHTTPGet(URL(string: "http://127.0.0.1:\(httpPort)/file/chain.p7b")!)
    check(viaHTTP == p7b, "baixa o .p7b por HTTP puro, byte a byte")
}

final class FetchCounter: @unchecked Sendable { var count = 0 }

func testLoginFlow(user: (identity: SecIdentity, certificate: SecCertificate, privateKey: SecKey), uvt: (identity: SecIdentity, certificate: SecCertificate, privateKey: SecKey)) async {
    section("Fluxo de login (requestpass → register → authenticate)")
    let base = URL(string: "https://api.sefaz.rn.gov.br/autbasic/signin")!
    let params: [String: JSONValue] = ["cpf": .string("12345678901"), "origem": .string("uvt")]
    let credential = LoginCredential(
        certificate: user.certificate, identity: user.identity, intermediates: [],
        decrypt: { try rsaDecrypt(user.privateKey, $0) }
    )

    // 1) Primeiro acesso: 407 → pede senha → register (201) → requestpass (302) → authenticate (200)
    do {
        let server = MockUVT(sigat: "S3nha!Sigat", serverKey: uvt.privateKey)
        let prompts = ScriptedPrompts(["S3nha!Sigat"])
        let flow = ProxyLoginFlow(transport: server, credential: credential, prompts: prompts, log: { _ in })
        let response = await flow.run(url: base, params: params)
        check(server.actions == ["requestpass", "register", "requestpass", "authenticate"], "primeiro acesso segue a sequência de login (\(server.actions))")
        check(response.type == "result" && response.data?["token"]?.stringValue == "jwt-de-teste", "devolve o JSON da autenticação como result")
        check(prompts.asked == 1 && prompts.invalidMessages == 0, "pede a senha SIGAT uma única vez")
        check(server.seenIdentity.allSatisfy { $0 }, "todas as chamadas levam o certificado de cliente")

        // 2) Acessos seguintes: certificado já registrado, sem pedir senha
        let again = MockUVT(sigat: "S3nha!Sigat", serverKey: uvt.privateKey)
        again.stored = server.stored
        let prompts2 = ScriptedPrompts([])
        let flow2 = ProxyLoginFlow(transport: again, credential: credential, prompts: prompts2, log: { _ in })
        let response2 = await flow2.run(url: base, params: params)
        check(again.actions == ["requestpass", "authenticate"] && response2.type == "result", "certificado já registrado autentica sem pedir senha")
        check(prompts2.asked == 0, "não incomoda o usuário nos acessos seguintes")
    }

    // 3) Senha SIGAT errada no registro: authenticate → 400 → aviso → nova senha → ok
    do {
        let server = MockUVT(sigat: "S3nha!Sigat", serverKey: uvt.privateKey)
        let prompts = ScriptedPrompts(["errada", "S3nha!Sigat"])
        let flow = ProxyLoginFlow(transport: server, credential: credential, prompts: prompts, log: { _ in })
        let response = await flow.run(url: base, params: params)
        check(response.type == "result", "recupera após senha errada")
        check(prompts.invalidMessages == 1 && prompts.asked == 2, "mostra 'Senha do SIGAT inválida' e pergunta de novo")
        check(server.actions.filter { $0 == "register" }.count == 2, "registra novamente com a senha corrigida")
    }

    // 4) Usuário cancela
    do {
        let server = MockUVT(sigat: "x", serverKey: uvt.privateKey)
        let flow = ProxyLoginFlow(transport: server, credential: credential, prompts: ScriptedPrompts([nil]), log: { _ in })
        let response = await flow.run(url: base, params: params)
        check(response.type == "error" && response.error == "Acesso negado. " && response.data?["status"] == .integer(403), "cancelar devolve 403 'Acesso negado.'")
    }

    // 5) Servidor sempre pede registro: não entra em laço infinito
    do {
        let server = MockUVT(sigat: "x", serverKey: uvt.privateKey)
        server.forcedStatus = 407
        let flow = ProxyLoginFlow(transport: server, credential: credential, prompts: ScriptedPrompts(Array(repeating: "a", count: 50)), log: { _ in })
        let response = await flow.run(url: base, params: params)
        check(response.type == "error" && server.actions.count <= ProxyLoginFlow.maxRequests, "limita o número de tentativas (\(server.actions.count) chamadas)")
    }

    // 6) Outros status viram erro com data.status
    do {
        let server = MockUVT(sigat: "x", serverKey: uvt.privateKey)
        server.forcedStatus = 500
        let flow = ProxyLoginFlow(transport: server, credential: credential, prompts: ScriptedPrompts([]), log: { _ in })
        let response = await flow.run(url: base, params: params)
        check(response.type == "error" && response.data?["status"] == .integer(500), "HTTP 500 vira error com status")
    }

    // 6b) Página de erro gigante (IIS) é truncada e o título vai para o log
    do {
        let html = "<html><head><title>403 - Acesso Negado</title></head><body>" + String(repeating: "x", count: 1_400_000) + "</body></html>"
        let big = ProxyLoginFlow.finalResponse(from: UVTHTTPResponse(status: 403, body: html))
        check(big.error?.count == ProxyLoginFlow.maxErrorMessageLength && big.data?["status"] == .integer(403), "mensagem de erro de 1,4 MB é truncada")
        check(ProxyLoginFlow.pageTitle(in: html) == "403 - Acesso Negado", "extrai o título da página de erro para o log")
    }

    // 7) Montagem da query
    do {
        let transport = RecordingTransport()
        let flow = ProxyLoginFlow(transport: transport, credential: credential, prompts: ScriptedPrompts([]), log: { _ in })
        _ = await flow.run(url: base, params: ["b": .string("2"), "a": .integer(1)])
        check(transport.lastGet?.absoluteString == "https://api.sefaz.rn.gov.br/autbasic/signin?a=1&action=requestpass&b=2", "query sem recodificar valores: \(transport.lastGet?.absoluteString ?? "nil")")
    }
}

func testNotifications() async {
    section("Notificação ao navegador (v1/notificacao/view/enviar)")
    let transport = RecordingTransport()
    let client = NotificationClient(transport: transport)
    let host = "https://api.sefaz.rn.gov.br/usuarios/"
    try! await client.send(response: .result(.string("1.0.11")), action: "version", host: host, token: "TOKEN123")
    let post = transport.posts[0]
    check(post.url.absoluteString == host + "v1/notificacao/view/enviar", "endpoint correto")
    check(post.body["Titulo"] as? String == "uvt-ms-action:version" && post.body["Conteudo"] as? String == "uvt-ms-action:version", "Titulo/Conteudo = uvt-ms-action:<ação>")
    check(post.body["Token"] as? String == "TOKEN123" && post.body["UserSystem"] as? Bool == true && post.body["Contexto"] as? String == "", "Token no corpo, UserSystem=true, Contexto vazio")
    let payload = (post.body["Dados"] as? [String: String])?["payload"]
    let decoded = payload.flatMap { Data(base64Encoded: $0) }.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(decoded?["type"] as? String == "result" && decoded?["data"] as? String == "1.0.11" && decoded?.keys.contains("error") == true, "payload é Base64 de {type,error,data}")

    let failing = RecordingTransport(statuses: [500, 200])
    try! await NotificationClient(transport: failing).send(response: .result(.string("x")), action: "proxyRequest", host: host, token: "T")
    let fallback = (failing.posts[1].body["Dados"] as? [String: String])?["payload"] ?? ""
    check(failing.posts.count == 2 && fallback.hasPrefix("{") && fallback.contains(#""type":"error""#), "se a notificação falha, reenvia o erro em JSON puro")

    do {
        try await client.send(response: .result(nil), action: "version", host: "https://evil.example.com/usuarios/", token: "T")
        check(false, "recusa host fora da lista")
    } catch { check(true, "recusa host fora da lista") }
    check(!NotificationClient.isAllowed(host: "https://api.sefaz.rn.gov.br/usuarios"), "exige a barra final (comparação exata)")
    check(NotificationClient.isAllowed(endpoint: URL(string: "https://api.sefaz.rn.gov.br/autbasic/x")!), "aceita endpoint de autenticação SEFAZ")
    check(!NotificationClient.isAllowed(endpoint: URL(string: "https://sefaz.rn.gov.br.evil.com/x")!), "recusa domínio parecido")
    check(!NotificationClient.isAllowed(endpoint: URL(string: "http://api.sefaz.rn.gov.br/x")!), "recusa HTTP sem TLS")

    section("Checagem de versão")
    let versionTransport = RecordingTransport()
    try! await VersionChecker(transport: versionTransport).check(host: host)
    check(versionTransport.lastGet?.absoluteString == "https://api.sefaz.rn.gov.br/autbasic/version?client_id=e7a9be83&client_version=1.0.11", "URL de checagem de versão correta")
    versionTransport.getResponse = UVTHTTPResponse(status: 426, body: "")
    do { try await VersionChecker(transport: versionTransport).check(host: host); check(false, "versão descontinuada falha") } catch { check(true, "versão descontinuada falha") }
}

func testTransport(user: (identity: SecIdentity, certificate: SecCertificate, privateKey: SecKey)) async {
    section("Transporte HTTP real (servidores locais)")
    let httpPort = readText("http.port"), httpsPort = readText("https.port")
    let client = UVTHTTPClient(timeout: 10)

    let r302 = try? await client.get(URL(string: "http://127.0.0.1:\(httpPort)/status302")!)
    check(r302?.status == 302 && r302?.body.contains("password") == true, "302 sem Location chega com o corpo")
    let r302loc = try? await client.get(URL(string: "http://127.0.0.1:\(httpPort)/status302-location")!)
    check(r302loc?.status == 302 && r302loc?.body.contains("redirect") == true, "302 com Location também NÃO é seguido (corpo preservado)")
    let r307 = try? await client.get(URL(string: "http://127.0.0.1:\(httpPort)/status307")!)
    check(r307?.status == 200 && r307?.body.contains("307") == true, "307 é seguido no mesmo host")
    let r400 = try? await client.get(URL(string: "http://127.0.0.1:\(httpPort)/status400")!)
    check(r400?.status == 400 && r400?.body.contains("senha") == true, "4xx volta como resposta, não como exceção")
    let echo = try? await client.get(URL(string: "http://127.0.0.1:\(httpPort)/echo?a=1&action=authenticate")!, headers: ["SET-CERPWD": "VALOR=="], identity: nil, intermediates: [])
    let echoJSON = echo.flatMap { JSONValue.parse($0.body) }
    check(echoJSON?["set_cerpwd"]?.stringValue == "VALOR==" && echoJSON?["query"]?["action"]?.stringValue == "authenticate", "headers e query chegam ao servidor")
    check(echoJSON?["cookie"] == .null || echoJSON?["cookie"] == nil, "não envia cookies")
    let post = try? await client.postJSON(URL(string: "http://127.0.0.1:\(httpPort)/post")!, body: Data(#"{"a":1}"#.utf8))
    let postJSON = post.flatMap { JSONValue.parse($0.body) }
    check(postJSON?["content_type"]?.stringValue == "application/json" && postJSON?["body"]?.stringValue == #"{"a":1}"#, "POST JSON com Content-Type correto")

    // mTLS: servidor exige certificado de cliente assinado pela CA de teste
    let ca = SecCertificateCreateWithData(nil, pemToDER(readText("ca.pem")) as CFData)!
    let mtls = UVTHTTPClient(timeout: 10, trustAnchors: [ca])
    let who = try? await mtls.get(URL(string: "https://127.0.0.1:\(httpsPort)/who")!, headers: [:], identity: user.identity, intermediates: [])
    check(who?.status == 200 && who?.body.contains("USUARIO TESTE:12345678901") == true, "apresenta o certificado de cliente no TLS (mTLS): \(who?.body ?? "sem resposta")")
    let anonymous = try? await mtls.get(URL(string: "https://127.0.0.1:\(httpsPort)/who")!)
    check(anonymous == nil, "sem identidade o servidor mTLS recusa o handshake")
    // Chamadas com certificado de cliente usam o Secure Transport (ver SecureTransportClient)
    let base = "https://127.0.0.1:\(httpsPort)"
    let st302 = try? await mtls.get(URL(string: base + "/status302")!, headers: [:], identity: user.identity, intermediates: [])
    check(st302?.status == 302 && st302?.body.contains("password") == true, "[Secure Transport] 302 devolve o corpo sem seguir")
    let st307 = try? await mtls.get(URL(string: base + "/status307")!, headers: [:], identity: user.identity, intermediates: [])
    check(st307?.status == 200 && st307?.body.contains("307") == true, "[Secure Transport] 307 é seguido no mesmo host")
    let stEcho = try? await mtls.get(URL(string: base + "/echo?a=1&action=authenticate")!, headers: ["SET-CERPWD": "VALOR+/=="], identity: user.identity, intermediates: [])
    let stEchoJSON = stEcho.flatMap { JSONValue.parse($0.body) }
    check(stEchoJSON?["set_cerpwd"]?.stringValue == "VALOR+/==" && stEchoJSON?["query"]?["action"]?.stringValue == "authenticate", "[Secure Transport] headers e query chegam intactos")
    let st400 = try? await mtls.get(URL(string: base + "/status400")!, headers: [:], identity: user.identity, intermediates: [])
    check(st400?.status == 400 && st400?.body.contains("senha") == true, "[Secure Transport] 4xx volta como resposta")

    // Regressão do erro -1206: o IIS da UVT pede o certificado por renegociação, depois da requisição.
    if let renegPort = try? String(contentsOf: dir.appendingPathComponent("reneg.port"), encoding: .utf8) {
        let renegotiated = try? await mtls.get(URL(string: "https://127.0.0.1:\(renegPort)/who")!, headers: [:], identity: user.identity, intermediates: [])
        check(renegotiated?.status == 200 && renegotiated?.body.contains("USUARIO TESTE:12345678901") == true && renegotiated?.body.contains(#""http":"1.1""#) == true,
              "certificado entregue por renegociação TLS 1.2 (h2 recusado, como no IIS): \(renegotiated?.body ?? "sem resposta")")
        let renegAnonymous = try? await mtls.get(URL(string: "https://127.0.0.1:\(renegPort)/who")!)
        check(renegAnonymous?.status == 200 && renegAnonymous?.body.contains(#""cn":null"#) == true, "sem identidade a renegociação segue sem certificado (como o IIS devolveria 403)")
    } else {
        print("  skip renegociação TLS (node indisponível)")
    }

    let untrusted = try? await UVTHTTPClient(timeout: 10).get(URL(string: "https://127.0.0.1:\(httpsPort)/who")!, headers: [:], identity: user.identity, intermediates: [])
    check(untrusted == nil, "servidor com CA desconhecida é recusado por padrão")
}

func pemToDER(_ pem: String) -> Data {
    Data(base64Encoded: pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined())!
}

// MARK: - Execução

let user = loadIdentity("user.p12")
let uvt = loadIdentity("uvt.p12")

testParser()
testResponseEnvelope()
testCrypto(user: user)
testCertificateInfo(user: user)
await testChainBuilder()
await testLoginFlow(user: user, uvt: uvt)
await testNotifications()
await testTransport(user: user)

SecKeychainDelete(temporaryKeychain)
print("\n\(checks - failures)/\(checks) verificações passaram")
exit(failures == 0 ? 0 : 1)
