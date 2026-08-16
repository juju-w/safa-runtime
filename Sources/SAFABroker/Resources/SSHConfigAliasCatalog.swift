import Darwin
import Foundation
import SAFADomain

protocol SSHConfigAliasChecking: Sendable {
    func contains(alias: ResourceAlias) async -> Bool
}

struct OpenSSHConfigAliasChecker: SSHConfigAliasChecking {
    private let configURL: URL

    init(
        configURL: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/config")
    ) {
        self.configURL = configURL
    }

    func contains(alias: ResourceAlias) async -> Bool {
        let configURL = configURL
        let value = alias.rawValue
        return await Task.detached(priority: .utility) {
            var scanner = SSHConfigAliasScanner(alias: value)
            return scanner.scan(configURL)
        }.value
    }
}

private struct SSHConfigAliasScanner {
    private static let maximumFiles = 128
    private static let maximumDepth = 8
    private static let maximumFileBytes = 2 * 1_048_576

    let alias: String
    private var visited: Set<String> = []

    init(alias: String) {
        self.alias = alias
    }

    mutating func scan(_ url: URL, depth: Int = 0) -> Bool {
        guard depth <= Self.maximumDepth, visited.count < Self.maximumFiles else { return false }
        let canonical = url.standardizedFileURL.resolvingSymlinksInPath().path
        guard visited.insert(canonical).inserted,
            let attributes = try? FileManager.default.attributesOfItem(atPath: canonical),
            let byteCount = attributes[.size] as? NSNumber,
            byteCount.intValue <= Self.maximumFileBytes,
            let text = try? String(contentsOfFile: canonical, encoding: .utf8)
        else {
            return false
        }

        let baseDirectory = url.deletingLastPathComponent()
        for rawLine in text.split(whereSeparator: \Character.isNewline) {
            let content = rawLine.split(separator: "#", maxSplits: 1).first ?? rawLine[...]
            let fields = content.split(whereSeparator: \Character.isWhitespace).map(String.init)
            guard let keyword = fields.first?.lowercased() else { continue }
            if keyword == "host",
                fields.dropFirst().contains(where: { $0 == alias })
            {
                return true
            }
            if keyword == "include" {
                for pattern in fields.dropFirst() {
                    for included in Self.expand(pattern, relativeTo: baseDirectory)
                    where scan(included, depth: depth + 1) {
                        return true
                    }
                }
            }
        }
        return false
    }

    private static func expand(_ pattern: String, relativeTo baseDirectory: URL) -> [URL] {
        let expanded = NSString(string: pattern).expandingTildeInPath
        let absolute: String
        if expanded.hasPrefix("/") {
            absolute = expanded
        } else {
            absolute = baseDirectory.appendingPathComponent(expanded).path
        }
        guard absolute.contains("*") || absolute.contains("?") || absolute.contains("[") else {
            return [URL(fileURLWithPath: absolute)]
        }

        let url = URL(fileURLWithPath: absolute)
        let directory = url.deletingLastPathComponent()
        let filenamePattern = url.lastPathComponent
        guard
            let names = try? FileManager.default.contentsOfDirectory(
                atPath: directory.path
            )
        else {
            return []
        }
        return
            names
            .filter { matches($0, pattern: filenamePattern) }
            .sorted()
            .map { directory.appendingPathComponent($0) }
    }

    private static func matches(_ value: String, pattern: String) -> Bool {
        pattern.withCString { patternPointer in
            value.withCString { valuePointer in
                fnmatch(patternPointer, valuePointer, 0) == 0
            }
        }
    }
}
