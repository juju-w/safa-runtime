import Foundation
import Testing

@testable import SAFABroker

@Suite("Broker runtime bundle paths")
struct BrokerRuntimePathTests {
    @Test("a bundled broker resolves AskPass beside its helper app")
    func bundledAskPassPath() {
        let bundle = URL(
            fileURLWithPath:
                "/Runtime/SAFA.app/Contents/Library/Helpers/SAFABrokerAgent.app",
            isDirectory: true
        )
        let executable = bundle.appendingPathComponent("Contents/MacOS/safa-broker")

        #expect(
            BrokerRuntimePaths.askPassExecutable(
                bundleURL: bundle,
                executableURL: executable
            ).path == "/Runtime/SAFA.app/Contents/Library/Helpers/safa-askpass"
        )
    }

    @Test("a standalone development broker resolves AskPass beside its executable")
    func standaloneAskPassPath() {
        let bundle = URL(fileURLWithPath: "/Workspace/.build/debug", isDirectory: true)
        let executable = bundle.appendingPathComponent("safa-broker")

        #expect(
            BrokerRuntimePaths.askPassExecutable(
                bundleURL: bundle,
                executableURL: executable
            ).path == "/Workspace/.build/debug/safa-askpass"
        )
    }
}
