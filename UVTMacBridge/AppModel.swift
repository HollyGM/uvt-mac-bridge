import Foundation
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var status = "Pronto"
    @Published var lastRequest: BrowserRequest?
    @Published var lastError: String?
    @Published var logText = ""
    @Published var identities: [CertificateIdentity] = []
    @Published var selectedIdentityID: String? {
        didSet {
            if let selectedIdentityID {
                UserDefaults.standard.set(selectedIdentityID, forKey: Self.selectedIdentityKey)
            }
        }
    }
    @Published var autoNotify: Bool {
        didSet { UserDefaults.standard.set(autoNotify, forKey: "autoNotify") }
    }

    private static let selectedIdentityKey = "selectedIdentityID"

    private let parser = URLSchemeParser()
    private let certificateService = CertificateService()
    private let transport: UVTTransport = UVTHTTPClient()
    private let prompts: UserPrompting = AppKitPrompts()
    private let logger = AppLogger.shared
    private var queue: Task<Void, Never> = Task {}

    init() {
        autoNotify = UserDefaults.standard.object(forKey: "autoNotify") as? Bool ?? true
        selectedIdentityID = UserDefaults.standard.string(forKey: Self.selectedIdentityKey)
        logger.onEntry = { [weak self] entry in
            Task { @MainActor in
                guard let self else { return }
                self.logText += entry + "\n"
            }
        }
    }

    func refreshCertificates() {
        do {
            identities = try certificateService.listIdentities()
            // Mantém a escolha anterior; sem ela, só sugere um certificado que pareça de uso real
            // (não autoassinado e dentro da validade) em vez do primeiro da lista alfabética.
            let current = identities.first(where: { $0.id == selectedIdentityID })
            if current?.isLikelyUsable != true, let usable = identities.first(where: \.isLikelyUsable) {
                // Autoassinado ou vencido nunca é aceito pela UVT; troca para um certificado de uso real.
                if current != nil { logger.info("Certificado selecionado não serve para a UVT (autoassinado ou vencido); trocando para um certificado emitido por AC") }
                selectedIdentityID = usable.id
            } else if current == nil {
                selectedIdentityID = nil
            }
            logger.info("Certificados disponíveis: \(identities.count)")
        } catch {
            lastError = error.localizedDescription
            logger.error("Falha ao consultar Keychain: \(error.localizedDescription)")
        }
    }

    /// Requisições chegam em sequência (ex.: duplo clique no navegador); cada uma só começa
    /// quando a anterior termina, para que diálogos de senha não se sobreponham.
    func handleIncomingURL(_ url: URL) async {
        let previous = queue
        let current = Task { @MainActor in
            await previous.value
            await self.process(url)
        }
        queue = current
        await current.value
    }

    private func process(_ url: URL) async {
        lastError = nil
        status = "Processando requisição"
        logger.info("URL recebida pelo protocolo sefazrnuvt")

        do {
            let request = try parser.parse(url: url)
            lastRequest = request
            logger.info("Método: \(request.method)")
            if let host = request.host { logger.info("Host: \(host)") }

            guard autoNotify else {
                logger.info("Envio automático desativado: requisição apenas registrada, nenhuma conexão foi feita")
                if let params = request.params?.objectValue {
                    logger.info("params: \(params.keys.sorted().joined(separator: ", "))")
                }
                status = "Registrado (sem envio)"
                return
            }

            guard let host = request.host, let token = request.token, !token.isEmpty else {
                throw AppModelError.missingHostOrToken
            }
            let notifier = NotificationClient(transport: transport)
            guard NotificationClient.isAllowed(host: host) else {
                throw NotificationClientError.hostNotAllowed(host)
            }

            // A versão é checada antes de qualquer método e, se falhar, nada é enviado ao navegador.
            status = "Verificando versão"
            try await VersionChecker(transport: transport).check(host: host)

            let context = HandlerContext(
                certificateService: certificateService,
                selectedIdentityID: selectedIdentityID,
                transport: transport,
                prompts: prompts
            )

            // A página espera receber a resposta "version" antes do resultado de todo proxyRequest.
            if request.method == "proxyRequest" {
                status = "Enviando versão"
                do {
                    try await notifier.send(response: VersionHandler.handle(), action: "version", host: host, token: token)
                } catch {
                    // Falha na notificação de versão não impede o login.
                    logger.error("Notificação de versão falhou (seguindo mesmo assim): \(error.localizedDescription)")
                }
            }

            status = "Executando \(request.method)"
            let response: BrowserResponse
            do {
                response = try await RequestDispatcher.dispatch(request: request, context: context)
            } catch {
                logger.error(error.localizedDescription)
                response = .failure(error.localizedDescription)
            }
            logger.info("Resposta local: \(response.type)")

            status = "Enviando resposta à UVT"
            try await notifier.send(response: response, action: request.method, host: host, token: token)
            logger.info("Resposta enviada ao endpoint de notificação")

            status = response.type == "result" ? "Concluído" : "Concluído com erro"
            if response.type == "error" { lastError = response.error }
        } catch {
            lastError = error.localizedDescription
            status = "Falha"
            logger.error(error.localizedDescription)
        }
    }
}

private enum AppModelError: LocalizedError {
    case missingHostOrToken

    var errorDescription: String? {
        "A requisição não trouxe host/token; não há para onde enviar a resposta"
    }
}
