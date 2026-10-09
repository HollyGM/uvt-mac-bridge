import Foundation

struct HandlerContext: Sendable {
    let certificateService: CertificateService
    let selectedIdentityID: String?
    let transport: UVTTransport
    let prompts: UserPrompting
}

enum HandlerError: LocalizedError {
    case unsupportedMethod(String)
    case missingParameters
    case certificateNotSelected
    case notImplemented(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedMethod(let method): return "Método UVT ainda não suportado: \(method)"
        case .missingParameters: return "Missing Parameters"
        case .certificateNotSelected: return "Certificado não selecionado. "
        case .notImplemented(let detail): return detail
        }
    }
}

enum RequestDispatcher {
    static func dispatch(request: BrowserRequest, context: HandlerContext) async throws -> BrowserResponse {
        switch request.method.lowercased() {
        case "version":
            return VersionHandler.handle()
        case "proxyrequest":
            return try await ProxyRequestHandler.handle(request: request, context: context)
        case "sign":
            throw HandlerError.notImplemented("Assinatura XML (sign) ainda não é suportada")
        case "signpdf":
            throw HandlerError.notImplemented("Assinatura PDF (signPdf) não é suportada")
        default:
            throw HandlerError.unsupportedMethod(request.method)
        }
    }
}
