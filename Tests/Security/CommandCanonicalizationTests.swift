import Foundation
import SAFADomain
import SAFAPolicy
import Testing

@Suite("Command canonicalization")
struct CommandCanonicalizationTests {
    private let canonicalizer = CommandCanonicalizer()

    @Test("POSIX rendering preserves every argument without shell interpretation")
    func posixRoundTrip() throws {
        let arguments = [
            "printf",
            "",
            "plain",
            "contains spaces",
            "single'quote",
            "$HOME",
            "$(id)",
            "semi;colon",
            "line\nbreak",
            "wild*card",
        ]
        let canonical = try canonicalizer.canonicalize(
            try CommandSpec.exec(arguments: arguments)
        )

        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            "-c",
            "set -- \(canonical.posixProgram); for value do printf '%s\\0' \"$value\"; done",
        ]
        process.standardOutput = output
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()

        #expect(process.terminationStatus == 0)
        let encodedValues = output.fileHandleForReading.readDataToEndOfFile()
        let values = encodedValues.split(separator: 0, omittingEmptySubsequences: false).dropLast()
            .map { String(decoding: $0, as: UTF8.self) }
        #expect(values == arguments)
    }

    @Test("fingerprints bind mode and every execution-affecting field")
    func fingerprintBinding() throws {
        let baseline = try canonicalizer.canonicalize(
            try CommandSpec.exec(arguments: ["printf", "%s", "hello world"])
        )
        let same = try canonicalizer.canonicalize(
            try CommandSpec.exec(arguments: ["printf", "%s", "hello world"])
        )
        let variants = try [
            canonicalizer.canonicalize(
                CommandSpec.exec(arguments: ["printf", "%s", "hello  world"])
            ),
            canonicalizer.canonicalize(
                CommandSpec.exec(
                    arguments: ["printf", "%s", "hello world"],
                    stdinMode: .boundedAgentData
                )
            ),
            canonicalizer.canonicalize(
                CommandSpec.exec(arguments: ["printf", "%s", "hello world"], tty: true)
            ),
            canonicalizer.canonicalize(
                CommandSpec.exec(
                    arguments: ["printf", "%s", "hello world"],
                    workingDirectory: "/tmp"
                )
            ),
            canonicalizer.canonicalize(
                CommandSpec.exec(
                    arguments: ["printf", "%s", "hello world"],
                    timeoutSeconds: 59
                )
            ),
            canonicalizer.canonicalize(
                CommandSpec.exec(
                    arguments: ["printf", "%s", "hello world"],
                    outputLimitBytes: 4_096
                )
            ),
            canonicalizer.canonicalize(
                CommandSpec.shell(program: "printf '%s' 'hello world'")
            ),
        ]

        #expect(baseline.fingerprint == same.fingerprint)
        #expect(
            baseline.fingerprint
                == "sha256:09e9f1165789ac2c209a12d6ee1fa50d66c692076e21df1ed839af0966019f44"
        )
        #expect(Set(variants.map(\.fingerprint)).count == variants.count)
        #expect(variants.allSatisfy { $0.fingerprint != baseline.fingerprint })
    }

    @Test("shell source remains exact and whitespace changes its fingerprint")
    func opaqueShellSource() throws {
        let first = try canonicalizer.canonicalize(
            try CommandSpec.shell(program: "journalctl -u api | tail -n 20")
        )
        let second = try canonicalizer.canonicalize(
            try CommandSpec.shell(program: "journalctl -u api  | tail -n 20")
        )

        #expect(first.posixProgram == "journalctl -u api | tail -n 20")
        #expect(first.fingerprint != second.fingerprint)
    }

    @Test("unsupported NUL and oversized argument vectors fail closed")
    func invalidInput() throws {
        #expect(throws: CommandCanonicalizationError.self) {
            try canonicalizer.canonicalize(
                CommandSpec.exec(arguments: ["printf", "bad\0value"])
            )
        }
        #expect(throws: CommandCanonicalizationError.self) {
            try canonicalizer.canonicalize(
                CommandSpec.exec(
                    arguments: ["printf"]
                        + Array(repeating: String(repeating: "x", count: 1_024), count: 65)
                )
            )
        }
    }
}
