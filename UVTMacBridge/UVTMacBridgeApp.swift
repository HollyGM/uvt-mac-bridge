import SwiftUI

@main
struct UVTMacBridgeApp: App {
    @StateObject private var appModel = AppModel()

    var body: some Scene {
        // `Window` (em vez de `WindowGroup`) evita abrir uma janela nova a cada sefazrnuvt://.
        Window("UVT Mac Bridge", id: "main") {
            ContentView()
                .environmentObject(appModel)
                .onOpenURL { url in
                    Task {
                        await appModel.handleIncomingURL(url)
                    }
                }
        }
        .windowResizability(.contentSize)
    }
}
