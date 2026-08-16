import SAFADomain
import SAFAProtocol
import SwiftUI

struct ResourceOnboardingView: View {
    @State private var alias = ""
    @State private var displayName = ""
    @State private var host = ""
    @State private var port = "22"
    @State private var username = ""
    @State private var securityDomain = "default"
    @State private var hostKeyAlgorithm = "ssh-ed25519"
    @State private var hostPublicKey = ""
    @State private var hostFingerprint = ""
    @State private var password = ""
    @State private var verifiedFingerprint = false
    @State private var status = "Private values remain inside this signed app and broker."
    @State private var saving = false

    var body: some View {
        Form {
            Section("Logical identity") {
                TextField("Alias, for example nas.home", text: $alias)
                TextField("Display name (optional)", text: $displayName)
                TextField("Security domain", text: $securityDomain)
            }
            Section("Private SSH connection") {
                TextField("Host or IP", text: $host)
                TextField("Port", text: $port)
                TextField("Username", text: $username)
                SecureField("Login password", text: $password)
            }
            Section("Pinned host identity") {
                TextField("Host key algorithm", text: $hostKeyAlgorithm)
                TextField("Host public key (base64 payload)", text: $hostPublicKey)
                TextField("Verified SHA256 fingerprint", text: $hostFingerprint)
                Toggle(
                    "I verified this fingerprint through a trusted channel",
                    isOn: $verifiedFingerprint)
            }
            Section {
                Button(saving ? "Saving…" : "Save private resource") {
                    Task { await save() }
                }
                .disabled(!canSave || saving)
                Text(status).font(.caption)
            }
        }
        .formStyle(.grouped)
    }

    private var canSave: Bool {
        !alias.isEmpty && !host.isEmpty && UInt16(port) != nil && !username.isEmpty
            && !password.isEmpty && !hostPublicKey.isEmpty && !hostFingerprint.isEmpty
            && verifiedFingerprint
    }

    @MainActor
    private func save() async {
        saving = true
        defer { saving = false }
        do {
            guard let decodedKey = Data(base64Encoded: hostPublicKey) else {
                status = "Host public key must be a valid base64 payload."
                return
            }
            try await TrustedBrokerClient().add(
                alias: ResourceAlias(alias),
                payload: ProtectedResourceSetupPayload(
                    displayName: displayName.isEmpty ? nil : displayName,
                    host: host,
                    port: UInt16(port)!,
                    username: username,
                    securityDomain: securityDomain,
                    hostKeyAlgorithm: hostKeyAlgorithm,
                    hostPublicKey: decodedKey,
                    hostFingerprint: hostFingerprint,
                    password: Data(password.utf8)
                )
            )
            password = ""
            status = "Resource saved. The password was not written to the Agent transcript."
        } catch {
            status = "Save failed. Confirm the signed broker is enabled and try again."
        }
    }
}
