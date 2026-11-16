import Foundation
import Security
import CryptoKit

struct CertificateIdentity: Identifiable, Hashable, Sendable {
    let id: String
    let displayName: String
    let derBase64: String
    let notAfter: Date?
    let isSelfSigned: Bool
    var isTokenBacked = false
    var notBefore: Date? = nil

    var isExpired: Bool { notAfter.map { $0 < Date() } ?? false }

    /// Candidato razoável a certificado de uso real (e-CPF/e-CNPJ/OAB): emitido por uma AC e dentro da validade.
    var isLikelyUsable: Bool { !isSelfSigned && !isExpired }

    /// Aviso para mostrar na janela: vencido, ainda não válido ou perto de vencer. `nil` se estiver tudo certo.
    var validityNotice: String? {
        CertificateValidity(notBefore: notBefore, notAfter: notAfter).message
    }
}

/// Situação da validade de um certificado em relação a hoje.
enum CertificateValidity: Equatable {
    case valid
    case expiresSoon(days: Int, on: Date)
    case expired(on: Date)
    case notYetValid(from: Date)

    /// Com quantos dias de antecedência o vencimento é avisado.
    static let warningDays = 30

    init(notBefore: Date?, notAfter: Date?, now: Date = Date(), calendar: Calendar = .current) {
        if let notAfter, now > notAfter {
            self = .expired(on: notAfter)
        } else if let notBefore, now < notBefore {
            self = .notYetValid(from: notBefore)
        } else if let notAfter,
                  let days = calendar.dateComponents([.day], from: calendar.startOfDay(for: now), to: calendar.startOfDay(for: notAfter)).day,
                  days < Self.warningDays {
            self = .expiresSoon(days: days, on: notAfter)
        } else {
            self = .valid
        }
    }

    init(certificate: SecCertificate, now: Date = Date()) {
        self.init(
            notBefore: CertificateService.notBefore(of: certificate),
            notAfter: CertificateService.notAfter(of: certificate),
            now: now
        )
    }

    /// O servidor recusa o certificado nesses casos; melhor parar antes de pedir PIN ou senha.
    var blocksLogin: Bool {
        switch self {
        case .expired, .notYetValid: return true
        case .valid, .expiresSoon: return false
        }
    }

    var message: String? {
        switch self {
        case .valid:
            return nil
        case .expired(let date):
            return "O certificado selecionado venceu em \(Self.format(date)) e não é aceito pela UVT. Renove o certificado ou selecione outro no UVT Mac Bridge."
        case .notYetValid(let date):
            return "O certificado selecionado só passa a valer em \(Self.format(date)). Confira a data e a hora do Mac."
        case .expiresSoon(let days, let date):
            let when: String
            switch days {
            case ..<1: when = "vence hoje (\(Self.format(date)))"
            case 1: when = "vence amanhã (\(Self.format(date)))"
            default: when = "vence em \(Self.format(date)), daqui a \(days) dias"
            }
            return "O certificado selecionado \(when). Providencie a renovação."
        }
    }

    static func format(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "dd/MM/yyyy"
        return formatter.string(from: date)
    }
}

enum CertificateServiceError: LocalizedError {
    case keychain(OSStatus)
    case identityNotFound
    case certificateUnavailable
    case privateKeyUnavailable
    case unsupportedKey
    case crypto(String)

    var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Erro do Keychain: \(message)"
        case .identityNotFound: return "Certificado selecionado não foi encontrado"
        case .certificateUnavailable: return "Não foi possível acessar o certificado"
        case .privateKeyUnavailable: return "Não foi possível acessar a chave privada do certificado"
        case .unsupportedKey: return "A chave privada não suporta a operação criptográfica necessária"
        case .crypto(let message): return "Falha criptográfica: \(message)"
        }
    }
}

final class CertificateService: @unchecked Sendable {
    func listIdentities() throws -> [CertificateIdentity] {
        let identities = try rawIdentities()
        return identities.compactMap { identity in
            guard let certificate = certificate(for: identity) else { return nil }
            let subject = (SecCertificateCopySubjectSummary(certificate) as String?) ?? "Certificado digital"
            let der = SecCertificateCopyData(certificate) as Data
            let digest = SHA256.hash(data: der)
            let id = digest.map { String(format: "%02x", $0) }.joined()
            return CertificateIdentity(
                id: id,
                displayName: subject,
                derBase64: der.base64EncodedString(),
                notAfter: Self.notAfter(of: certificate),
                isSelfSigned: Self.isSelfSigned(certificate),
                isTokenBacked: Self.isTokenBacked(identity),
                notBefore: Self.notBefore(of: certificate)
            )
        }
        // Certificados de uso real primeiro; o resto em ordem alfabética.
        .sorted {
            if $0.isLikelyUsable != $1.isLikelyUsable { return $0.isLikelyUsable }
            return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
        }
    }

    static func notAfter(of certificate: SecCertificate) -> Date? {
        validityDate(of: certificate, key: kSecOIDX509V1ValidityNotAfter)
    }

    static func notBefore(of certificate: SecCertificate) -> Date? {
        validityDate(of: certificate, key: kSecOIDX509V1ValidityNotBefore)
    }

    private static func validityDate(of certificate: SecCertificate, key: CFString) -> Date? {
        guard let values = SecCertificateCopyValues(certificate, [key] as CFArray, nil) as? [CFString: Any],
              let entry = values[key] as? [CFString: Any],
              let seconds = entry[kSecPropertyKeyValue] as? NSNumber else { return nil }
        return Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
    }

    /// Chave em token/cartão (CryptoTokenKit): pede PIN, em vez da senha do Keychain.
    static func isTokenBacked(_ identity: SecIdentity) -> Bool {
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key,
              let attributes = SecKeyCopyAttributes(key) as? [String: Any] else { return false }
        return attributes[kSecAttrTokenID as String] != nil
    }

    static func isSelfSigned(_ certificate: SecCertificate) -> Bool {
        let subject = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?
        let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data?
        return subject != nil && subject == issuer
    }

    func identity(withID id: String) throws -> SecIdentity {
        for identity in try rawIdentities() {
            guard let certificate = certificate(for: identity) else { continue }
            let der = SecCertificateCopyData(certificate) as Data
            let digest = SHA256.hash(data: der)
            let currentID = digest.map { String(format: "%02x", $0) }.joined()
            if currentID == id { return identity }
        }
        throw CertificateServiceError.identityNotFound
    }

    func credential(withID id: String) throws -> (identity: SecIdentity, certificate: SecCertificate) {
        let identity = try identity(withID: id)
        guard let certificate = certificate(for: identity) else { throw CertificateServiceError.certificateUnavailable }
        return (identity, certificate)
    }

    /// Certificados intermediários para enviar junto do certificado de cliente no TLS.
    /// No macOS a cadeia completa só é enviada se o app a entregar explicitamente.
    func intermediates(for certificate: SecCertificate) -> [SecCertificate] {
        CertificateChainBuilder().intermediates(for: certificate)
    }

    func decryptRSA(ciphertext: Data, identity: SecIdentity) throws -> Data {
        var privateKey: SecKey?
        let status = SecIdentityCopyPrivateKey(identity, &privateKey)
        guard status == errSecSuccess, let privateKey else {
            if status != errSecSuccess { throw CertificateServiceError.keychain(status) }
            throw CertificateServiceError.privateKeyUnavailable
        }

        // A UVT cifra com RSA PKCS#1 v1.5. Tentar OAEP aqui só geraria pedidos de PIN extras em tokens A3.
        let algorithm = SecKeyAlgorithm.rsaEncryptionPKCS1
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw CertificateServiceError.unsupportedKey
        }
        var error: Unmanaged<CFError>?
        guard let clear = SecKeyCreateDecryptedData(privateKey, algorithm, ciphertext as CFData, &error) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "erro desconhecido"
            throw CertificateServiceError.crypto(message)
        }
        return clear as Data
    }

    private func rawIdentities() throws -> [SecIdentity] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw CertificateServiceError.keychain(status) }

        guard let result else { return [] }
        if CFGetTypeID(result) == SecIdentityGetTypeID() {
            return [result as! SecIdentity]
        }
        return (result as? [SecIdentity]) ?? []
    }

    private func certificate(for identity: SecIdentity) -> SecCertificate? {
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess else { return nil }
        return certificate
    }
}
