import Darwin
import Foundation

enum BrokerProcessEnvironment {
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
}
