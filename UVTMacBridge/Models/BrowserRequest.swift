import Foundation

struct BrowserRequest: Decodable, Sendable {
    let host: String?
    let token: String?
    let method: String
    let latestInstallerUrl: String?
    /// Endpoint de autenticação chamado pelo `proxyRequest` (e de recuperação do XML no `sign`).
    let url: String?
    let ticket: String?
    let params: JSONValue?
}
