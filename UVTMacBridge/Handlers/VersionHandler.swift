import Foundation

enum VersionHandler {
    // Versão do Módulo de Segurança UVT com a qual este app é compatível.
    static let compatibilityVersion = "1.0.11"

    static func handle() -> BrowserResponse {
        BrowserResponse.result(.string(compatibilityVersion))
    }
}
