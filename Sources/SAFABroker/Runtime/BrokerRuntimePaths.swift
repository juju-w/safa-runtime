import Foundation

enum BrokerRuntimePaths {
    static func askPassExecutable(bundleURL: URL, executableURL: URL?) -> URL {
        if bundleURL.pathExtension == "app" {
            return
                bundleURL
                .deletingLastPathComponent()
                .appendingPathComponent("safa-askpass", isDirectory: false)
        }
        return (executableURL?.deletingLastPathComponent() ?? bundleURL)
            .appendingPathComponent("safa-askpass", isDirectory: false)
    }
}
