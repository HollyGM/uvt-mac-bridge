import Foundation

enum VersionCheckError: LocalizedError {
    case invalidHost
    case unavailable(Int)
    case discontinued(Int)
    case transport(String)

    var errorDescription: String? {
        switch self {
        case .invalidHost:
            return "Host da UVT inválido para checagem de versão"
        case .unavailable(let status):
            return "Ocorreu um erro durante a tentativa de verificar a versão do Módulo de Segurança (HTTP \(status)). Tente novamente mais tarde."
        case .discontinued(let status):
            return "A versão do Módulo de Segurança em uso foi descontinuada: \(VersionHandler.compatibilityVersion) (HTTP \(status)). Atualize o Módulo de Segurança da UVT."
        case .transport(let detail):
            return "Não foi possível verificar a versão do Módulo de Segurança: \(detail)"
        }
    }
}

/// Checagem de versão feita antes de qualquer método:
/// `GET <esquema>://<host>/autbasic/version?client_id=e7a9be83&client_version=1.0.11`.
/// Em caso de falha nada é respondido ao navegador.
struct VersionChecker: Sendable {
    static let clientID = "e7a9be83"

    let transport: UVTTransport

    func check(host: String) async throws {
        guard let hostURL = URL(string: host), let scheme = hostURL.scheme, let name = hostURL.host,
              let url = URL(string: "\(scheme)://\(name)/autbasic/version?client_id=\(Self.clientID)&client_version=\(VersionHandler.compatibilityVersion)") else {
            throw VersionCheckError.invalidHost
        }

        let response: UVTHTTPResponse
        do {
            response = try await transport.get(url)
        } catch {
            throw VersionCheckError.transport(error.localizedDescription)
        }

        guard response.status == 200 || response.status == 300 else {
            // 412 é tratado como erro genérico; qualquer outro código, como versão descontinuada.
            throw response.status == 412
                ? VersionCheckError.unavailable(response.status)
                : VersionCheckError.discontinued(response.status)
        }
    }
}
