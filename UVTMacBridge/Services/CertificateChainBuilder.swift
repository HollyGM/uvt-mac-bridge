import Foundation
import Security
import CryptoKit
import Darwin

/// Monta a cadeia de intermediários do certificado de cliente.
///
/// O servidor precisa receber a cadeia completa. O `SecTrust` do macOS só encontra o que já está no
/// Keychain; num e-CPF a cadeia costuma ter três níveis (e-CPF ← AC emissora ← AC da Receita ← raiz)
/// e o macOS para no primeiro.
/// O IIS da UVT recusa o certificado (403) se não consegue montar o caminho até uma raiz que conhece.
/// Aqui a cadeia é completada seguindo o ponteiro AIA "CA Issuers" do próprio certificado.
struct CertificateChainBuilder {
    /// Busca o conteúdo de uma URL (injetável nos testes). `nil` = indisponível.
    var fetch: @Sendable (URL) -> Data? = CertificateChainBuilder.download
    var cacheDirectory: URL? = CertificateChainBuilder.defaultCacheDirectory
    var log: @Sendable (String) -> Void = { AppLogger.shared.info($0) }

    private static let maxRounds = 3
    private static let maxDownloadBytes = 1_000_000

    /// Intermediários (do emissor do certificado até logo abaixo da raiz), sem o próprio certificado
    /// e sem a raiz autoassinada.
    func intermediates(for leaf: SecCertificate) -> [SecCertificate] {
        var pool = loadCache()
        var attempted = Set<URL>()
        var chain = build(leaf: leaf, pool: pool)

        for _ in 0..<Self.maxRounds {
            if Self.isComplete(chain) { break }
            // Os ponteiros AIA do próprio certificado e do último elo da cadeia atual.
            let sources = ([leaf] + [chain.last].compactMap { $0 }).flatMap(Self.caIssuerURLs)
            var seen = Set<URL>()
            let pending = sources.filter { !attempted.contains($0) && seen.insert($0).inserted }
            guard !pending.isEmpty else { break }

            var learned = false
            for url in pending {
                attempted.insert(url)
                guard let data = fetch(url) else {
                    log("AIA indisponível: \(url.host ?? "?")")
                    continue
                }
                for certificate in Self.certificates(in: data) where !pool.contains(where: { Self.sameCertificate($0, certificate) }) {
                    pool.append(certificate)
                    store(certificate)
                    learned = true
                }
            }
            guard learned else { break }
            chain = build(leaf: leaf, pool: pool)
        }

        var result = Array(chain.dropFirst())
        if let last = result.last, CertificateService.isSelfSigned(last) { result.removeLast() }
        if !Self.isComplete(chain) {
            log("Cadeia do certificado incompleta (\(result.count) intermediário(s)); o servidor pode recusar o login")
        }
        return result
    }

    // MARK: - Construção

    private func build(leaf: SecCertificate, pool: [SecCertificate]) -> [SecCertificate] {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(([leaf] + pool) as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return [leaf] }
        SecTrustSetNetworkFetchAllowed(trust, true)
        _ = SecTrustEvaluateWithError(trust, nil)
        return (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? [leaf]
    }

    /// A cadeia chega a uma raiz autoassinada ou o último elo é de uma AC já presente no sistema.
    private static func isComplete(_ chain: [SecCertificate]) -> Bool {
        guard let last = chain.last else { return false }
        return chain.count > 1 && CertificateService.isSelfSigned(last)
    }

    // MARK: - AIA e formatos

    /// URLs "CA Issuers" (1.3.6.1.5.5.7.48.2) do certificado, lidas direto do DER.
    static func caIssuerURLs(of certificate: SecCertificate) -> [URL] {
        let bytes = [UInt8](SecCertificateCopyData(certificate) as Data)
        let oid: [UInt8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]
        var urls: [URL] = []
        var index = 0
        while index + oid.count + 2 < bytes.count {
            // [6] uniformResourceIdentifier logo após o OID do método
            if bytes[index..<index + oid.count].elementsEqual(oid), bytes[index + oid.count] == 0x86 {
                let length = Int(bytes[index + oid.count + 1])
                let start = index + oid.count + 2
                if length < 0x80, start + length <= bytes.count,
                   let url = URL(string: String(decoding: bytes[start..<start + length], as: UTF8.self)),
                   ["http", "https"].contains(url.scheme?.lowercased() ?? "") {
                    urls.append(url)
                }
                index = start + length
            } else {
                index += 1
            }
        }
        return urls
    }

    /// Certificados contidos em PKCS#7 (.p7b), DER ou PEM.
    static func certificates(in data: Data) -> [SecCertificate] {
        for candidate in [SecExternalFormat.formatPKCS7, .formatX509Cert, .formatPEMSequence] {
            var format = candidate
            var type = SecExternalItemType.itemTypeUnknown
            var items: CFArray?
            guard SecItemImport(data as CFData, nil, &format, &type, [], nil, nil, &items) == errSecSuccess,
                  let list = items as? [AnyObject] else { continue }
            let certificates = list.compactMap { item -> SecCertificate? in
                CFGetTypeID(item) == SecCertificateGetTypeID() ? (item as! SecCertificate) : nil
            }
            if !certificates.isEmpty { return certificates }
        }
        return []
    }

    private static func sameCertificate(_ a: SecCertificate, _ b: SecCertificate) -> Bool {
        (SecCertificateCopyData(a) as Data) == (SecCertificateCopyData(b) as Data)
    }

    // MARK: - Cache em disco (certificados são públicos)

    static var defaultCacheDirectory: URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("UVTMacBridge/chain-cache", isDirectory: true)
    }

    private func loadCache() -> [SecCertificate] {
        guard let cacheDirectory,
              let files = try? FileManager.default.contentsOfDirectory(at: cacheDirectory, includingPropertiesForKeys: nil) else { return [] }
        return files.filter { $0.pathExtension == "der" }.compactMap { url in
            (try? Data(contentsOf: url)).flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        }
    }

    private func store(_ certificate: SecCertificate) {
        guard let cacheDirectory else { return }
        let der = SecCertificateCopyData(certificate) as Data
        let name = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined().prefix(32)
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
        try? der.write(to: cacheDirectory.appendingPathComponent("\(name).der"), options: .atomic)
    }

    // MARK: - Download

    @Sendable static func download(_ url: URL) -> Data? {
        // Os repositórios das ACs usam HTTP puro (a integridade vem da assinatura dos certificados).
        // O App Transport Security bloqueia isso no URLSession, então o http:// vai por um GET mínimo.
        if url.scheme?.lowercased() == "http" { return plainHTTPGet(url) }

        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.setValue("UVTMacBridge/1", forHTTPHeaderField: "User-Agent")
        let semaphore = DispatchSemaphore(value: 0)
        var result: Data?
        let task = URLSession(configuration: .ephemeral).dataTask(with: request) { data, response, _ in
            if let http = response as? HTTPURLResponse, http.statusCode == 200, let data, data.count <= maxDownloadBytes {
                result = data
            }
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + 12) == .timedOut { task.cancel() }
        return result
    }

    static func plainHTTPGet(_ url: URL) -> Data? {
        guard let host = url.host,
              let fd = try? connectTCP(host: host, port: UInt16(url.port ?? 80), timeout: 10) else { return nil }
        defer { Darwin.close(fd) }

        var target = url.path.isEmpty ? "/" : url.path
        if let query = url.query { target += "?" + query }
        let request = "GET \(target) HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: UVTMacBridge/1\r\nConnection: close\r\n\r\n"
        let written = request.withCString { Darwin.write(fd, $0, strlen($0)) }
        guard written > 0 else { return nil }

        var response = Data()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while response.count <= maxDownloadBytes + 4096 {
            let count = Darwin.read(fd, &chunk, chunk.count)
            if count <= 0 { break }
            response.append(contentsOf: chunk[0..<count])
        }
        guard let split = response.range(of: Data("\r\n\r\n".utf8)),
              String(decoding: response[..<split.lowerBound], as: UTF8.self).hasPrefix("HTTP/1."),
              String(decoding: response[..<split.lowerBound], as: UTF8.self).split(separator: " ").dropFirst().first == "200" else { return nil }
        let body = response[split.upperBound...]
        return body.count <= maxDownloadBytes ? Data(body) : nil
    }
}
