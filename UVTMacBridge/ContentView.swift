import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    private func label(for identity: CertificateIdentity) -> String {
        var text = identity.displayName
        if identity.isExpired {
            text += " — VENCIDO"
        } else if let date = identity.notAfter {
            text += " — vence \(date.formatted(date: .numeric, time: .omitted))"
        }
        if identity.isTokenBacked { text += " · token A3" }
        if identity.isSelfSigned { text += " · autoassinado, não serve para a UVT" }
        return text
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("UVT Mac Bridge")
                        .font(.title2.bold())
                    Text("Cliente não oficial, compatível com o Módulo de Segurança UVT 1.0.11")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Circle()
                    .fill(model.lastError == nil ? .green : .orange)
                    .frame(width: 10, height: 10)
            }

            GroupBox("Estado") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 7) {
                    GridRow {
                        Text("Status")
                            .foregroundStyle(.secondary)
                        Text(model.status)
                    }
                    GridRow {
                        Text("Método")
                            .foregroundStyle(.secondary)
                        Text(model.lastRequest?.method ?? "—")
                    }
                    GridRow {
                        Text("Host")
                            .foregroundStyle(.secondary)
                        Text(model.lastRequest?.host ?? "—")
                            .textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("Certificado") {
                VStack(alignment: .leading, spacing: 8) {
                    Picker("Identidade", selection: $model.selectedIdentityID) {
                        Text("Selecione um certificado").tag(String?.none)
                        ForEach(model.identities) { identity in
                            Text(label(for: identity)).tag(String?.some(identity.id))
                        }
                    }
                    .labelsHidden()

                    HStack {
                        Button("Atualizar certificados") {
                            model.refreshCertificates()
                        }
                        Spacer()
                        Text("Encontrados: \(model.identities.count)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)
            }

            GroupBox("Compatibilidade") {
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("Processar e responder à UVT", isOn: $model.autoNotify)
                    Text("Desativado, o app só registra a requisição no log e não faz nenhuma conexão. Ativado, só fala com os hosts oficiais da SEFAZ/RN e da SET/RN.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }

            if let error = model.lastError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }

            Text("Log salvo em ~/Library/Logs/UVTMacBridge/uvt-mac-bridge.log")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            GroupBox("Log") {
                ScrollView {
                    Text(model.logText.isEmpty ? "Aguardando chamada sefazrnuvt://…" : model.logText)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(6)
                }
                .frame(height: 180)
            }
        }
        .padding(18)
        .frame(width: 650)
        .task {
            model.refreshCertificates()
        }
    }
}
