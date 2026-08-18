import Darwin
import Foundation

enum TrustedSetupConsoleError: Error, Equatable, Sendable {
    case inputUnavailable
    case invalidText
    case valueTooLong
}

protocol TrustedSetupConsole: Sendable {
    func write(_ text: String) throws
    func readSecret(prompt: String) throws -> Data
}

/// Reads only from the controlling terminal. It never consumes stdin, so an
/// Agent pipe cannot supply protected setup values. The separately signed
/// helper authenticates the device owner before invoking this adapter.
final class TTYTrustedSetupConsole: TrustedSetupConsole, @unchecked Sendable {
    private static let maximumLineBytes = 16 * 1_024
    private let lock = NSLock()

    init() throws {
        let descriptor = Darwin.open("/dev/tty", O_RDWR | O_CLOEXEC)
        guard descriptor >= 0, isatty(descriptor) == 1 else {
            if descriptor >= 0 { Darwin.close(descriptor) }
            throw TrustedSetupConsoleError.inputUnavailable
        }
        Darwin.close(descriptor)
    }

    func write(_ text: String) throws {
        try lock.withLock {
            try withTTY { descriptor in
                try writeAll(Data(text.utf8), to: descriptor)
            }
        }
    }

    func readSecret(prompt: String) throws -> Data {
        try lock.withLock {
            try withTTY { descriptor in
                var settings = termios()
                guard tcgetattr(descriptor, &settings) == 0 else {
                    throw TrustedSetupConsoleError.inputUnavailable
                }
                let original = settings
                settings.c_lflag &= ~tcflag_t(ECHO)
                guard tcsetattr(descriptor, TCSAFLUSH, &settings) == 0 else {
                    throw TrustedSetupConsoleError.inputUnavailable
                }
                defer {
                    var restored = original
                    _ = tcsetattr(descriptor, TCSAFLUSH, &restored)
                    try? writeAll(Data("\n".utf8), to: descriptor)
                }
                try writeAll(Data(prompt.utf8), to: descriptor)
                let value = try readLineData(from: descriptor)
                guard !value.contains(0), value.count <= Self.maximumLineBytes else {
                    throw TrustedSetupConsoleError.invalidText
                }
                return value
            }
        }
    }

    private func withTTY<Value>(_ operation: (Int32) throws -> Value) throws -> Value {
        let descriptor = Darwin.open("/dev/tty", O_RDWR | O_CLOEXEC)
        guard descriptor >= 0, isatty(descriptor) == 1 else {
            if descriptor >= 0 { Darwin.close(descriptor) }
            throw TrustedSetupConsoleError.inputUnavailable
        }
        defer { Darwin.close(descriptor) }
        return try operation(descriptor)
    }

    private func readLineData(from descriptor: Int32) throws -> Data {
        var result = Data()
        var byte: UInt8 = 0
        while result.count <= Self.maximumLineBytes {
            let count = Darwin.read(descriptor, &byte, 1)
            if count == 0 { throw TrustedSetupConsoleError.inputUnavailable }
            if count < 0 {
                if errno == EINTR { continue }
                throw TrustedSetupConsoleError.inputUnavailable
            }
            if byte == 0x0A || byte == 0x0D { return result }
            result.append(byte)
        }
        throw TrustedSetupConsoleError.valueTooLong
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard var baseAddress = rawBuffer.baseAddress else { return }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, baseAddress, remaining)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw TrustedSetupConsoleError.inputUnavailable
                }
                guard written > 0 else { throw TrustedSetupConsoleError.inputUnavailable }
                remaining -= written
                baseAddress = baseAddress.advanced(by: written)
            }
        }
    }
}
