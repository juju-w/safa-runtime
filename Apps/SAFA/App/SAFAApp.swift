import SwiftUI

@main
struct SAFAApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

private struct ContentView: View {
    @StateObject private var registration = BrokerRegistration()
    @State private var message = "SAFA stores private setup outside Agent-visible input."

    var body: some View {
        TabView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Secure Agent Access")
                    .font(.title)
                Text(message)
                Button("Enable local broker") {
                    do {
                        try registration.register()
                        message = "Broker registration requested."
                    } catch {
                        message = "Open System Settings → Login Items to approve SAFA."
                    }
                }
                Spacer()
            }
            .padding(24)
            .tabItem { Label("Runtime", systemImage: "lock.shield") }

            ResourceOnboardingView()
                .tabItem { Label("Resources", systemImage: "server.rack") }
        }
        .frame(minWidth: 640, minHeight: 620)
    }
}
