import Darwin
import Foundation

public struct ProcessInvocation: Sendable {
    public let executableURL: URL
    public let arguments: [String]
    public let environment: [String: String]
    public let standardInput: Data?
    public let timeoutSeconds: UInt
    public let outputLimitBytes: UInt
    public let didLaunch: (@Sendable (Int32) -> Void)?

    public init(
        executableURL: URL,
        arguments: [String],
        environment: [String: String] = [:],
        standardInput: Data? = nil,
        timeoutSeconds: UInt,
        outputLimitBytes: UInt,
        didLaunch: (@Sendable (Int32) -> Void)? = nil
    ) {
        self.executableURL = executableURL
        self.arguments = arguments
        self.environment = environment
        self.standardInput = standardInput
        self.timeoutSeconds = timeoutSeconds
        self.outputLimitBytes = outputLimitBytes
        self.didLaunch = didLaunch
    }

    public func withLaunchHandler(
        _ handler: @escaping @Sendable (Int32) -> Void
    ) -> ProcessInvocation {
        ProcessInvocation(
            executableURL: executableURL,
            arguments: arguments,
            environment: environment,
            standardInput: standardInput,
            timeoutSeconds: timeoutSeconds,
            outputLimitBytes: outputLimitBytes,
            didLaunch: handler
        )
    }
}

public struct ProcessExecutionResult: Equatable, Sendable {
    public let termination: ProcessTermination
    public let exitCode: Int32?
    public let stdout: Data
    public let stderr: Data
    public let startedAt: Date
    public let finishedAt: Date
    public let stdoutTruncated: Bool
    public let stderrTruncated: Bool
    public let stdoutTotalBytes: Int
    public let stderrTotalBytes: Int

    public init(
        termination: ProcessTermination,
        exitCode: Int32?,
        stdout: Data,
        stderr: Data,
        startedAt: Date,
        finishedAt: Date,
        stdoutTruncated: Bool,
        stderrTruncated: Bool,
        stdoutTotalBytes: Int? = nil,
        stderrTotalBytes: Int? = nil
    ) {
        self.termination = termination
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.stdoutTruncated = stdoutTruncated
        self.stderrTruncated = stderrTruncated
        self.stdoutTotalBytes = stdoutTotalBytes ?? stdout.count
        self.stderrTotalBytes = stderrTotalBytes ?? stderr.count
    }
}

public enum ProcessTermination: String, Equatable, Sendable {
    case exit
    case signal
    case timeout
    case cancelled
}

public enum ProcessRunnerError: Error, Equatable, Sendable {
    case launchFailed
}

public protocol ProcessRunning: Sendable {
    func run(_ invocation: ProcessInvocation) async throws -> ProcessExecutionResult
}

private final class BoundedPipeReader: @unchecked Sendable {
    private let handle: FileHandle
    private let limit: Int
    private(set) var data = Data()
    private(set) var truncated = false
    private(set) var totalBytes = 0

    init(handle: FileHandle, limit: UInt) {
        self.handle = handle
        self.limit = Int(min(limit, UInt(Int.max)))
    }

    func drain() {
        while true {
            let chunk: Data
            do {
                chunk = try handle.read(upToCount: 65_536) ?? Data()
            } catch {
                return
            }
            guard !chunk.isEmpty else { return }
            totalBytes += chunk.count
            let remaining = max(0, limit - data.count)
            if remaining > 0 {
                data.append(chunk.prefix(remaining))
            }
            if chunk.count > remaining { truncated = true }
        }
    }
}

public struct ProcessRunner: ProcessRunning {
    public init() {}

    public func run(_ invocation: ProcessInvocation) async throws -> ProcessExecutionResult {
        let worker = Task.detached(priority: .userInitiated) {
            try Self.runSynchronously(invocation)
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    private static func runSynchronously(
        _ invocation: ProcessInvocation
    ) throws -> ProcessExecutionResult {
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        let stdinPipe = Pipe()
        process.executableURL = invocation.executableURL
        process.arguments = invocation.arguments
        process.environment = invocation.environment
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        process.standardInput = stdinPipe

        let stdout = BoundedPipeReader(
            handle: stdoutPipe.fileHandleForReading,
            limit: invocation.outputLimitBytes
        )
        let stderr = BoundedPipeReader(
            handle: stderrPipe.fileHandleForReading,
            limit: invocation.outputLimitBytes
        )
        let readers = DispatchGroup()
        readers.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stdout.drain()
            readers.leave()
        }
        readers.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stderr.drain()
            readers.leave()
        }

        let startedAt = Date()
        do {
            try process.run()
            invocation.didLaunch?(process.processIdentifier)
        } catch {
            stdinPipe.fileHandleForWriting.closeFile()
            stdoutPipe.fileHandleForWriting.closeFile()
            stderrPipe.fileHandleForWriting.closeFile()
            readers.wait()
            throw ProcessRunnerError.launchFailed
        }

        if let input = invocation.standardInput {
            try? stdinPipe.fileHandleForWriting.write(contentsOf: input)
        }
        stdinPipe.fileHandleForWriting.closeFile()

        let deadline = startedAt.addingTimeInterval(TimeInterval(invocation.timeoutSeconds))
        var forcedTermination: ProcessTermination?
        while process.isRunning {
            if Task<Never, Never>.isCancelled {
                forcedTermination = .cancelled
                process.terminate()
                break
            }
            if Date() >= deadline {
                forcedTermination = .timeout
                process.terminate()
                break
            }
            usleep(20_000)
        }
        if process.isRunning {
            usleep(100_000)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
        process.waitUntilExit()
        readers.wait()

        let termination =
            forcedTermination
            ?? (process.terminationReason == .exit ? .exit : .signal)
        return ProcessExecutionResult(
            termination: termination,
            exitCode: termination == .exit ? process.terminationStatus : nil,
            stdout: stdout.data,
            stderr: stderr.data,
            startedAt: startedAt,
            finishedAt: Date(),
            stdoutTruncated: stdout.truncated,
            stderrTruncated: stderr.truncated,
            stdoutTotalBytes: stdout.totalBytes,
            stderrTotalBytes: stderr.totalBytes
        )
    }
}
