import Foundation
import Security

enum ProxyRequestHandler {
    static func handle(request: BrowserRequest, context: HandlerContext) async throws -> BrowserResponse {
        guard let params = request.params?.objectValue else {
            throw HandlerError.missingParameters
        }
        guard let identityID = context.selectedIdentityID else {
            return .failure(HandlerError.certificateNotSelected.localizedDescription, status: 0)
        }
        guard let urlText = request.url, let url = URL(string: urlText) else {
            return .failure("URL de autenticação não informada")
        }
        // O certificado de cliente só é apresentado a servidores SEFAZ/RN, para que uma página
        // maliciosa não o use contra terceiros.
        guard NotificationClient.isAllowed(endpoint: url) else {
            return .failure("Endereço de autenticação recusado pela política de segurança local: \(url.host ?? urlText)")
        }

        let (identity, certificate) = try context.certificateService.credential(withID: identityID)
        // Falha cedo, antes de o macOS pedir senha do Keychain ou PIN para um certificado que a UVT recusaria.
        if CertificateService.isSelfSigned(certificate) {
            return .failure("O certificado selecionado é autoassinado e não é aceito pela UVT. Abra o UVT Mac Bridge e selecione o seu e-CPF/e-CNPJ emitido por uma AC (ICP-Brasil).", status: 0)
        }
        let intermediates = context.certificateService.intermediates(for: certificate)
        // Só o nome, sem o ":CPF" que os certificados e-CPF carregam no CN.
        let subject = (SecCertificateCopySubjectSummary(certificate) as String?) ?? "?"
        AppLogger.shared.info("Certificado: \(subject.split(separator: ":").first.map(String.init) ?? subject); intermediários enviados: \(intermediates.count)")
        let credential = LoginCredential(
            certificate: certificate,
            identity: identity,
            intermediates: intermediates,
            decrypt: { try context.certificateService.decryptRSA(ciphertext: $0, identity: identity) }
        )

        AppLogger.shared.info("proxyRequest: parâmetros \(params.keys.sorted().joined(separator: ", "))")
        let flow = ProxyLoginFlow(
            transport: context.transport,
            credential: credential,
            prompts: context.prompts,
            log: { AppLogger.shared.info($0) }
        )
        return await flow.run(url: url, params: params)
    }
}
