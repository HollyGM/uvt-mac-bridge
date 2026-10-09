import Foundation
import Security
import CommonCrypto

enum UVTCryptoError: LocalizedError {
    case invalidCertificate
    case encryptionUnsupported
    case encryption(String)
    case random(OSStatus)
    case des(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidCertificate: return "Certificado devolvido pela UVT é inválido"
        case .encryptionUnsupported: return "A chave pública não suporta RSA PKCS#1"
        case .encryption(let message): return "Falha ao cifrar com RSA: \(message)"
        case .random(let status): return "Falha ao gerar bytes aleatórios (OSStatus \(status))"
        case .des(let status): return "Falha DES (CCCryptorStatus \(status))"
        }
    }
}

/// Primitivas exigidas pelo protocolo da UVT: RSA PKCS#1 v1.5 e DES-CBC.
/// DES é fraco; é mantido apenas porque o servidor da UVT espera exatamente esse formato.
enum UVTCrypto {
    /// Codificação ASCII de 7 bits: caracteres fora dela viram `?`.
    static func asciiBytes(_ text: String) -> Data {
        Data(text.utf16.map { $0 < 128 ? UInt8($0) : UInt8(ascii: "?") })
    }

    /// Equivalente a `new X509Certificate2(Encoding.ASCII.GetBytes(texto))` para PEM ou Base64 de DER.
    static func certificate(fromServerText text: String) throws -> SecCertificate {
        let lines = text
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
        let compact = lines.joined()
        guard let der = Data(base64Encoded: compact),
              let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw UVTCryptoError.invalidCertificate
        }
        return certificate
    }

    /// `RSACryptoServiceProvider.Encrypt(bytes, fOAEP: false)`.
    static func rsaEncryptPKCS1(_ plain: Data, with certificate: SecCertificate) throws -> Data {
        guard let publicKey = SecCertificateCopyKey(certificate) else { throw UVTCryptoError.invalidCertificate }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionPKCS1) else {
            throw UVTCryptoError.encryptionUnsupported
        }
        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, plain as CFData, &error) else {
            throw UVTCryptoError.encryption(error?.takeRetainedValue().localizedDescription ?? "erro desconhecido")
        }
        return cipher as Data
    }

    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { throw UVTCryptoError.random(status) }
        return Data(bytes)
    }

    /// Chave DES de 8 bytes com paridade ímpar.
    static func generateDESKey() throws -> Data {
        var key = try randomBytes(8)
        for index in key.indices {
            let byte = key[index] & 0xFE
            key[index] = byte.nonzeroBitCount.isMultiple(of: 2) ? byte | 0x01 : byte
        }
        return key
    }

    /// DES em modo CBC com preenchimento PKCS#7.
    static func desCBCEncrypt(_ plain: Data, key: Data, iv: Data) throws -> Data {
        precondition(key.count == kCCKeySizeDES && iv.count == kCCBlockSizeDES)
        var output = Data(count: plain.count + kCCBlockSizeDES)
        var written = 0
        let outputCapacity = output.count
        let status = output.withUnsafeMutableBytes { outBytes in
            plain.withUnsafeBytes { inBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmDES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, kCCKeySizeDES,
                            ivBytes.baseAddress,
                            inBytes.baseAddress, plain.count,
                            outBytes.baseAddress, outputCapacity,
                            &written
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw UVTCryptoError.des(status) }
        return output.prefix(written)
    }
}
