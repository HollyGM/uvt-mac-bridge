import Foundation
import Security
import Darwin

enum SecureTransportError: LocalizedError {
    case resolve(String)
    case connect(String)
    case timeout
    case tls(OSStatus, String)
    case untrustedServer
    case malformedResponse(String)

    var errorDescription: String? {
        switch self {
        case .resolve(let host): return "Não foi possível resolver o endereço de \(host)"
        case .connect(let detail): return "Falha ao conectar: \(detail)"
        case .timeout: return "Tempo esgotado na conexão com a UVT"
        case .tls(let status, let step):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Falha TLS (\(step)): \(message) [\(status)]"
        case .untrustedServer: return "O certificado do servidor da UVT não é confiável"
        case .malformedResponse(let detail): return "Resposta HTTP inválida: \(detail)"
        }
    }
}

/// Cliente HTTP/1.1 mínimo sobre o Secure Transport, usado nas chamadas autenticadas por certificado.
///
/// Por que não `URLSession`? O servidor `aut.sefaz.rn.gov.br` é um IIS que só pede o certificado de
/// cliente *depois* da requisição, por renegociação TLS 1.2 (e recusa h2 com HTTP_1_1_REQUIRED).
/// O `URLSession` do macOS atual falha nesse cenário com `-1206`, mesmo com credencial válida, ao passo que
/// o Secure Transport (usado pelo `curl` do sistema) renegocia normalmente.
/// A API está marcada como obsoleta pela Apple, mas segue presente e é a que funciona com este servidor.
final class SecureTransportClient: @unchecked Sendable {
    private let timeout: TimeInterval
    private let trustAnchors: [SecCertificate]
    private let maxBodyBytes = 16_000_000
    private let maxRedirects = 5

    init(timeout: TimeInterval = 30, trustAnchors: [SecCertificate] = []) {
        self.timeout = timeout
        self.trustAnchors = trustAnchors
    }

    func get(_ url: URL, headers: [String: String], identity: SecIdentity?, intermediates: [SecCertificate]) async throws -> UVTHTTPResponse {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    continuation.resume(returning: try self.perform(url, headers: headers, identity: identity, intermediates: intermediates))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Requisição

    private func perform(_ original: URL, headers: [String: String], identity: SecIdentity?, intermediates: [SecCertificate]) throws -> UVTHTTPResponse {
        var url = original
        for _ in 0...maxRedirects {
            let connection = try Connection(url: url, timeout: timeout, trustAnchors: trustAnchors,
                                            identity: identity, intermediates: intermediates)
            defer { connection.close() }
            try connection.handshake()
            try connection.send(Self.requestBytes(for: url, headers: headers))
            let response = try connection.readResponse(maxBytes: maxBodyBytes)
            AppLogger.shared.info("TLS \(url.host ?? "?"): HTTP \(response.status), certificado de cliente apresentado: \(connection.presentedCertificate ? "sim" : "não")")

            // Redirecionamentos 301/303/307/308 são seguidos, só dentro do mesmo host.
            // O 302 NÃO é seguido: a UVT devolve o resultado do requestpass nele.
            if [301, 303, 307, 308].contains(response.status),
               let location = response.headers["location"],
               let next = URL(string: location, relativeTo: url)?.absoluteURL,
               next.scheme == url.scheme, next.host == url.host, next.port == url.port {
                url = next
                continue
            }
            return UVTHTTPResponse(status: response.status, body: response.body)
        }
        throw SecureTransportError.malformedResponse("redirecionamentos demais")
    }

    private static func requestBytes(for url: URL, headers: [String: String]) -> Data {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var target = components?.percentEncodedPath ?? "/"
        if target.isEmpty { target = "/" }
        if let query = components?.percentEncodedQuery { target += "?" + query }

        var host = url.host ?? ""
        if let port = url.port, port != 443 { host += ":\(port)" }

        var lines = [
            "GET \(target) HTTP/1.1",
            "Host: \(host)",
            "User-Agent: UVTMacBridge/1",
            "Accept: */*",
            "Connection: close"
        ]
        for (name, value) in headers.sorted(by: { $0.key < $1.key }) {
            lines.append("\(name): \(value.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: ""))")
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    // MARK: - Conexão TLS

    fileprivate struct RawResponse {
        let status: Int
        let headers: [String: String]
        let body: String
    }

    fileprivate final class Connection {
        private var fd: Int32 = -1
        private var context: SSLContext?
        private var timedOut = false
        private let host: String
        private let trustAnchors: [SecCertificate]
        private let identity: SecIdentity?
        private let intermediates: [SecCertificate]
        fileprivate private(set) var presentedCertificate = false

        init(url: URL, timeout: TimeInterval, trustAnchors: [SecCertificate], identity: SecIdentity?, intermediates: [SecCertificate]) throws {
            guard url.scheme?.lowercased() == "https", let host = url.host else {
                throw SecureTransportError.connect("URL precisa ser https")
            }
            self.host = host
            self.trustAnchors = trustAnchors
            self.identity = identity
            self.intermediates = intermediates
            fd = try connectTCP(host: host, port: UInt16(url.port ?? 443), timeout: timeout)
        }

        func close() {
            if let context {
                SSLClose(context)
                self.context = nil
            }
            if fd >= 0 { Darwin.close(fd); fd = -1 }
        }

        deinit { close() }

        // Handshake e renegociação

        func handshake() throws {
            guard let context = SSLCreateContext(nil, .clientSide, .streamType) else {
                throw SecureTransportError.tls(errSecAllocate, "SSLCreateContext")
            }
            self.context = context

            try check(SSLSetIOFuncs(context, stRead, stWrite), "SSLSetIOFuncs")
            try check(SSLSetConnection(context, Unmanaged.passUnretained(self).toOpaque()), "SSLSetConnection")
            try check(SSLSetPeerDomainName(context, host, host.utf8.count), "SSLSetPeerDomainName")
            try check(SSLSetProtocolVersionMin(context, .tlsProtocol12), "SSLSetProtocolVersionMin")
            try check(SSLSetProtocolVersionMax(context, .tlsProtocol12), "SSLSetProtocolVersionMax")
            // Só HTTP/1.1: HTTP/2 não admite renegociação, que o IIS usa para pedir o certificado.
            try check(SSLSetALPNProtocols(context, ["http/1.1"] as CFArray), "SSLSetALPNProtocols")
            try check(SSLSetSessionOption(context, .breakOnServerAuth, true), "breakOnServerAuth")
            try check(SSLSetSessionOption(context, .breakOnCertRequested, true), "breakOnCertRequested")

            try continueHandshake()
        }

        private func continueHandshake() throws {
            guard let context else { return }
            while true {
                let status = SSLHandshake(context)
                if status == noErr { return }
                try handleBreak(status, step: "SSLHandshake")
            }
        }

        /// Trata as pausas que pedimos (`break on …`). Qualquer outro status é erro.
        private func handleBreak(_ status: OSStatus, step: String) throws {
            switch status {
            case errSSLPeerAuthCompleted:
                try evaluateServerTrust()
            case errSSLClientCertRequested:
                try presentClientCertificate()
            default:
                if timedOut { throw SecureTransportError.timeout }
                throw SecureTransportError.tls(status, step)
            }
        }

        private func evaluateServerTrust() throws {
            guard let context else { return }
            var trust: SecTrust?
            try check(SSLCopyPeerTrust(context, &trust), "SSLCopyPeerTrust")
            guard let trust else { throw SecureTransportError.untrustedServer }
            if !trustAnchors.isEmpty {
                SecTrustSetAnchorCertificates(trust, trustAnchors as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, false)
            }
            var error: CFError?
            guard SecTrustEvaluateWithError(trust, &error) else { throw SecureTransportError.untrustedServer }
        }

        private func presentClientCertificate() throws {
            guard let context else { return }
            guard let identity else {
                // Sem credencial: segue sem certificado, como o `performDefaultHandling` faria.
                try check(SSLSetCertificate(context, [] as CFArray), "SSLSetCertificate(vazio)")
                return
            }
            let chain = ([identity] + intermediates) as CFArray
            try check(SSLSetCertificate(context, chain), "SSLSetCertificate")
            presentedCertificate = true
        }

        // E/S de aplicação

        func send(_ data: Data) throws {
            guard let context else { return }
            var offset = 0
            while offset < data.count {
                var written = 0
                let status = data.withUnsafeBytes { raw in
                    SSLWrite(context, raw.baseAddress! + offset, data.count - offset, &written)
                }
                offset += written
                if status == noErr || status == errSSLWouldBlock { continue }
                try handleBreak(status, step: "SSLWrite")
            }
        }

        /// Lê a resposta HTTP/1.1 completa. Renegociações TLS iniciadas pelo servidor durante a leitura
        /// (pedido de certificado) são atendidas aqui.
        func readResponse(maxBytes: Int) throws -> RawResponse {
            guard let context else { throw SecureTransportError.malformedResponse("sem conexão") }
            var buffer = Data()
            var scratch = [UInt8](repeating: 0, count: 64 * 1024)
            var eof = false

            while !eof {
                var processed = 0
                let status = SSLRead(context, &scratch, scratch.count, &processed)
                if processed > 0 { buffer.append(contentsOf: scratch[0..<processed]) }
                if buffer.count > maxBytes { throw SecureTransportError.malformedResponse("resposta grande demais") }

                switch status {
                case noErr, errSSLWouldBlock:
                    break
                case errSSLClosedGraceful, errSSLClosedNoNotify:
                    eof = true
                case errSSLClosedAbort where !buffer.isEmpty:
                    eof = true // IIS costuma fechar sem close_notify depois de enviar tudo
                default:
                    try handleBreak(status, step: "SSLRead")
                }
                if Self.isComplete(buffer) { break }
            }
            return try Self.parse(buffer)
        }

        // Utilitários

        private func check(_ status: OSStatus, _ step: String) throws {
            guard status == noErr else { throw SecureTransportError.tls(status, step) }
        }

        fileprivate func readBytes(into data: UnsafeMutableRawPointer, length: UnsafeMutablePointer<Int>) -> OSStatus {
            let wanted = length.pointee
            var total = 0
            while total < wanted {
                let count = Darwin.read(fd, data + total, wanted - total)
                if count > 0 { total += count; continue }
                length.pointee = total
                if count == 0 { return errSSLClosedGraceful }
                switch errno {
                case EINTR: continue
                case EAGAIN: timedOut = true; return errSecIO
                case ECONNRESET: return errSSLClosedAbort
                default: return errSecIO
                }
            }
            length.pointee = total
            return noErr
        }

        fileprivate func writeBytes(from data: UnsafeRawPointer, length: UnsafeMutablePointer<Int>) -> OSStatus {
            let wanted = length.pointee
            var total = 0
            while total < wanted {
                let count = Darwin.write(fd, data + total, wanted - total)
                if count > 0 { total += count; continue }
                length.pointee = total
                switch errno {
                case EINTR: continue
                case EAGAIN: timedOut = true; return errSecIO
                case EPIPE, ECONNRESET: return errSSLClosedAbort
                default: return errSecIO
                }
            }
            length.pointee = total
            return noErr
        }

        // HTTP/1.1

        private static let separator = Data("\r\n\r\n".utf8)

        private static func isComplete(_ data: Data) -> Bool {
            guard let range = data.range(of: separator) else { return false }
            let head = String(decoding: data[..<range.lowerBound], as: UTF8.self).lowercased()
            let body = data[range.upperBound...]
            if head.contains("transfer-encoding: chunked") {
                return body.suffix(5) == Data("0\r\n\r\n".utf8) || body == Data("0\r\n\r\n".utf8)
            }
            if let line = head.components(separatedBy: "\r\n").first(where: { $0.hasPrefix("content-length:") }),
               let length = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) {
                return body.count >= length
            }
            return false
        }

        private static func parse(_ data: Data) throws -> RawResponse {
            guard let range = data.range(of: separator) else {
                throw SecureTransportError.malformedResponse("cabeçalhos incompletos")
            }
            let head = String(decoding: data[..<range.lowerBound], as: UTF8.self)
            var lines = head.components(separatedBy: "\r\n")
            let statusParts = lines.removeFirst().split(separator: " ")
            guard statusParts.count >= 2, let status = Int(statusParts[1]) else {
                throw SecureTransportError.malformedResponse("linha de status")
            }
            var headers: [String: String] = [:]
            for line in lines {
                guard let colon = line.firstIndex(of: ":") else { continue }
                let name = line[..<colon].lowercased()
                headers[name] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }

            var body = data[range.upperBound...]
            if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
                body = try decodeChunked(body)
            } else if let value = headers["content-length"], let length = Int(value), body.count > length {
                body = body.prefix(length)
            }
            let text = String(data: body, encoding: .utf8) ?? String(data: body, encoding: .isoLatin1) ?? ""
            return RawResponse(status: status, headers: headers, body: text.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        private static func decodeChunked(_ data: Data) throws -> Data {
            var result = Data()
            var rest = data
            while true {
                guard let lineEnd = rest.range(of: Data("\r\n".utf8)) else { break }
                let sizeText = String(decoding: rest[..<lineEnd.lowerBound], as: UTF8.self)
                    .split(separator: ";").first.map(String.init) ?? "0"
                guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16) else {
                    throw SecureTransportError.malformedResponse("tamanho de chunk")
                }
                rest = rest[lineEnd.upperBound...]
                if size == 0 { break }
                guard rest.count >= size else { throw SecureTransportError.malformedResponse("chunk truncado") }
                result.append(rest.prefix(size))
                rest = rest.dropFirst(size + 2)
            }
            return result
        }
    }
}

private func stRead(_ connection: SSLConnectionRef, _ data: UnsafeMutableRawPointer, _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    Unmanaged<SecureTransportClient.Connection>.fromOpaque(connection).takeUnretainedValue().readBytes(into: data, length: length)
}

private func stWrite(_ connection: SSLConnectionRef, _ data: UnsafeRawPointer, _ length: UnsafeMutablePointer<Int>) -> OSStatus {
    Unmanaged<SecureTransportClient.Connection>.fromOpaque(connection).takeUnretainedValue().writeBytes(from: data, length: length)
}

/// Conexão TCP com limite de tempo (connect não bloqueante + poll). Devolve o descritor já em modo bloqueante
/// com timeouts de leitura/escrita.
func connectTCP(host: String, port: UInt16, timeout: TimeInterval) throws -> Int32 {
    var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: IPPROTO_TCP,
                         ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
    var list: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, String(port), &hints, &list) == 0, let first = list else {
        throw SecureTransportError.resolve(host)
    }
    defer { freeaddrinfo(list) }

    var lastError = "sem endereços"
    var cursor: UnsafeMutablePointer<addrinfo>? = first
    while let info = cursor {
        cursor = info.pointee.ai_next
        let sock = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        if sock < 0 { continue }
        var noSigPipe: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        // connect com limite de tempo: não bloqueante + poll
        let flags = fcntl(sock, F_GETFL)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)
        var result = Darwin.connect(sock, info.pointee.ai_addr, info.pointee.ai_addrlen)
        if result != 0 && errno == EINPROGRESS {
            var pollFD = pollfd(fd: sock, events: Int16(POLLOUT), revents: 0)
            if poll(&pollFD, 1, Int32(timeout * 1000)) > 0 {
                var soError: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &length)
                result = soError == 0 ? 0 : -1
                if soError != 0 { errno = soError }
            } else {
                Darwin.close(sock)
                lastError = "tempo esgotado"
                continue
            }
        }
        guard result == 0 else {
            lastError = String(cString: strerror(errno))
            Darwin.close(sock)
            continue
        }
        _ = fcntl(sock, F_SETFL, flags)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        return sock
    }
    throw SecureTransportError.connect(lastError)
}
