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

    var isExpired: Bool { notAfter.map { $0 < Date() } ?? false }

    /// Candidato razoável a certificado de uso real (e-CPF/e-CNPJ/OAB): emitido por uma AC e dentro da validade.
    var isLikelyUsable: Bool { !isSelfSigned && !isExpired }
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
                isTokenBacked: Self.isTokenBacked(identity)
            )
        }
        // Certificados de uso real primeiro; o resto em ordem alfabética.
        .sorted {
            if $0.isLikelyUsable != $1.isLikelyUsable { return $0.isLikelyUsable }
            return $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
        }
    }

    static func notAfter(of certificate: SecCertificate) -> Date? {
        let keys = [kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [CFString: Any],
              let entry = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any],
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

    func decryptRSA(ciphertext: Data, identityID: String) throws -> Data {
        try decryptRSA(ciphertext: ciphertext, identity: try identity(withID: identityID))
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

    func signSHA256(message: Data, identityID: String) throws -> Data {
        let identity = try identity(withID: identityID)
        var privateKey: SecKey?
        let status = SecIdentityCopyPrivateKey(identity, &privateKey)
        guard status == errSecSuccess, let privateKey else {
            if status != errSecSuccess { throw CertificateServiceError.keychain(status) }
            throw CertificateServiceError.privateKeyUnavailable
        }

        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw CertificateServiceError.unsupportedKey
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, message as CFData, &error) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "erro desconhecido"
            throw CertificateServiceError.crypto(message)
        }
        return signature as Data
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
