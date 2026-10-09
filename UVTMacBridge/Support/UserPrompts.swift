import AppKit

/// Interações com o usuário exigidas pelo fluxo de autenticação. Protocolo para permitir testes.
protocol UserPrompting: Sendable {
    /// Pede a senha do SIGAT (primeiro acesso de cada certificado). `nil` se o usuário cancelar.
    func requestSigatPassword() async -> String?
    func showInvalidSigatPassword() async
}

struct AppKitPrompts: UserPrompting {
    func requestSigatPassword() async -> String? {
        await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Primeiro acesso: registrar certificado digital"
            alert.informativeText = "Informe sua senha do SIGAT para registrar este certificado.\n\nA senha do SIGAT é solicitada no primeiro acesso de cada certificado."
            alert.addButton(withTitle: "Registrar")
            alert.addButton(withTitle: "Cancelar")

            let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
            field.placeholderString = "Senha do SIGAT"
            alert.accessoryView = field
            alert.window.initialFirstResponder = field

            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            return field.stringValue
        }
    }

    func showInvalidSigatPassword() async {
        await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "ATENÇÃO"
            alert.informativeText = "Senha do SIGAT inválida. Por favor, tente novamente!"
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}
