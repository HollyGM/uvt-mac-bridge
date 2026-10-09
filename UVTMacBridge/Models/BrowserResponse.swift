import Foundation

/// Envelope devolvido ao navegador: `{"type":"result|error","error":<texto|null>,"data":<json|null>}`.
/// `error` e `data` são sempre serializados, mesmo nulos: a página espera as três chaves.
struct BrowserResponse: Encodable, Sendable {
    let type: String
    let error: String?
    let data: JSONValue?

    private enum CodingKeys: String, CodingKey {
        case type, error, data
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        if let error { try container.encode(error, forKey: .error) } else { try container.encodeNil(forKey: .error) }
        if let data { try container.encode(data, forKey: .data) } else { try container.encodeNil(forKey: .data) }
    }

    func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    static func result(_ data: JSONValue?) -> BrowserResponse {
        BrowserResponse(type: "result", error: nil, data: data)
    }

    static func failure(_ message: String, status: Int? = nil) -> BrowserResponse {
        let data = status.map { JSONValue.object(["status": .integer(Int64($0))]) }
        return BrowserResponse(type: "error", error: message, data: data)
    }
}
