import Darwin
import Foundation

enum BrokerProcessEnvironment {
    static let cleanReexecMarker = "SAFA_BROKER_CLEAN_REEXEC_PID"

    private static let fixedPath = "/usr/bin:/bin:/usr/sbin:/sbin"

    static func sanitized(
        inherited: [String: String],
        homeDirectory: String,
        username: String,
        temporaryDirectory: String
    ) -> [String: String] {
        var result = [
            "HOME": homeDirectory,
            "LOGNAME": username,
            "PATH": fixedPath,
            "TMPDIR": temporaryDirectory,
            "USER": username,
        ]
        if let socket = inherited["SSH_AUTH_SOCK"],
            socket.utf8.count <= Int(PATH_MAX),
            socket.hasPrefix("/")
        {
            result["SSH_AUTH_SOCK"] = socket
        }
        return result
    }

    static func reexecEnvironment(
        inherited: [String: String],
        homeDirectory: String,
        username: String,
        temporaryDirectory: String,
        processIdentifier: Int32
    ) -> [String: String] {
        var environment = sanitized(
            inherited: inherited,
            homeDirectory: homeDirectory,
            username: username,
            temporaryDirectory: temporaryDirectory
        )
        environment[cleanReexecMarker] = String(processIdentifier)
        return environment
    }

    static func requiresCleanReexec(
        inherited: [String: String],
        processIdentifier: Int32
    ) -> Bool {
        inherited[cleanReexecMarker] != String(processIdentifier)
    }

    static func reexecIfNeeded() {
        let inherited = ProcessInfo.processInfo.environment
        let processIdentifier = getpid()
        guard
            requiresCleanReexec(
                inherited: inherited,
                processIdentifier: processIdentifier
            )
        else {
            return
        }
        guard let executablePath = Bundle.main.executableURL?.path else {
            Foundation.exit(45)
        }

        let environment = reexecEnvironment(
            inherited: inherited,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser.path,
            username: NSUserName(),
            temporaryDirectory: NSTemporaryDirectory(),
            processIdentifier: processIdentifier
        )
        replaceProcessImage(
            executablePath: executablePath,
            arguments: CommandLine.arguments,
            environment: environment
        )
    }

    static func apply() {
        let inherited = ProcessInfo.processInfo.environment
        let environment = sanitized(
            inherited: inherited,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser.path,
            username: NSUserName(),
            temporaryDirectory: NSTemporaryDirectory()
        )
        for key in inherited.keys {
            unsetenv(key)
        }
        for (key, value) in environment {
            setenv(key, value, 1)
        }
    }

    private static func replaceProcessImage(
        executablePath: String,
        arguments: [String],
        environment: [String: String]
    ) -> Never {
        let effectiveArguments = arguments.isEmpty ? [executablePath] : arguments
        var argumentPointers = effectiveArguments.map { strdup($0) }
        var environmentPointers =
            environment
            .sorted { $0.key < $1.key }
            .map { strdup("\($0.key)=\($0.value)") }

        guard
            argumentPointers.allSatisfy({ $0 != nil }),
            environmentPointers.allSatisfy({ $0 != nil })
        else {
            argumentPointers.forEach { free($0) }
            environmentPointers.forEach { free($0) }
            Foundation.exit(45)
        }

        argumentPointers.append(nil)
        environmentPointers.append(nil)
        defer {
            argumentPointers.forEach { free($0) }
            environmentPointers.forEach { free($0) }
        }

        executablePath.withCString { path in
            argumentPointers.withUnsafeMutableBufferPointer { argumentsBuffer in
                environmentPointers.withUnsafeMutableBufferPointer { environmentBuffer in
                    _ = Darwin.execve(
                        path,
                        argumentsBuffer.baseAddress,
                        environmentBuffer.baseAddress
                    )
                }
            }
        }
        Foundation.exit(45)
    }
}
