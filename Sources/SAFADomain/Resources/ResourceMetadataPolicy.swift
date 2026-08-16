import Foundation

public enum ResourceMetadataPolicyError: Error, Equatable, Sendable {
    case sensitiveOrInvalidValue(String)
}

/// Validates encrypted inventory input and controls which protected metadata
/// may cross the authorized Agent-facing projection.
public enum ResourceMetadataPolicy {
    public static func validateForPersistence(_ entries: [ResourceMetadataEntry]) throws {
        for entry in entries {
            guard isPersistable(entry) else {
                throw ResourceMetadataPolicyError.sensitiveOrInvalidValue(entry.key.rawValue)
            }
        }
    }

    /// Unknown keys stay encrypted for forward compatibility but do not become
    /// Agent-visible merely because device-owner authentication succeeded.
    public static func authorizedEntries(from entries: [ResourceMetadataEntry])
        -> [ResourceMetadataEntry]
    {
        entries.filter { entry in
            guard !isReservedSensitiveKey(entry.key), isSafeStoredValue(entry.value) else {
                return false
            }
            if ResourceSummaryDisclosure.allowedMetadataKeys.contains(entry.key) {
                return ResourceSummaryDisclosure.isApprovedPublicEntry(entry)
            }
            return ResourceProtectedMetadataDisclosure.isApprovedEntry(entry)
        }
    }

    private static func isPersistable(_ entry: ResourceMetadataEntry) -> Bool {
        guard !isReservedSensitiveKey(entry.key), isSafeStoredValue(entry.value) else {
            return false
        }
        if ResourceSummaryDisclosure.allowedMetadataKeys.contains(entry.key) {
            return ResourceSummaryDisclosure.isApprovedPublicEntry(entry)
        }
        if ResourceProtectedMetadataDisclosure.allowedMetadataKeys.contains(entry.key) {
            return ResourceProtectedMetadataDisclosure.isApprovedEntry(entry)
        }
        return true
    }

    private static func isReservedSensitiveKey(_ key: ResourceMetadataKey) -> Bool {
        let components = key.rawValue.split(whereSeparator: { $0 == "." || $0 == "-" })
            .map(String.init)
        guard components.first != "ssh" else { return true }

        let reserved: Set<String> = [
            "accesskey", "apikey", "auth", "authentication", "authorization", "authheader",
            "cert", "certificate", "certificates", "connectionstring", "credential",
            "credentials", "dsn", "fingerprint", "identity", "jwk", "jwks", "key",
            "keychain", "keypair", "keypairs", "keys", "locator", "passcode", "passcodes",
            "passphrase", "passphrases", "passwd", "password", "passwords", "pem", "pin",
            "pincode", "pincodes", "pins", "privatekey", "publickey", "secret", "secretkey",
            "secrets", "token", "tokens",
        ]
        return components.contains(where: reserved.contains)
            || components.indices.dropLast().contains { index in
                components[index] == "connection"
                    && components[components.index(after: index)] == "string"
            }
    }

    private static func isSafeStoredValue(_ value: ResourceMetadataValue) -> Bool {
        switch value {
        case .text(let value):
            return isSafeText(value)
        case .textList(let values):
            return values.count <= 64
                && values.allSatisfy(isSafeText)
                && !containsObviousSecret(values.joined(separator: " "))
        case .integer, .boolean, .byteCount:
            return true
        }
    }

    private static func isSafeText(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 256
            && value.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            }
            && !containsObviousSecret(value)
    }

    /// Cheap defense in depth for common textual mistakes. This deliberately
    /// does not parse arbitrary ASN.1 or cryptographic containers; disclosure
    /// safety comes from the exact key/type allowlist above.
    private static func containsObviousSecret(_ value: String) -> Bool {
        let lowered = value.lowercased()
        let privateMaterialMarkers = [
            "-----begin ", "private-lines:", "private-mac:", "putty-user-key-file-",
        ]
        return privateMaterialMarkers.contains(where: lowered.contains)
            || containsOpenSSHKey(value)
            || containsAuthorizationCredential(value)
            || containsCompactJOSECredential(value)
            || containsCredentialBearingURI(value)
            || containsJSONDocument(value)
    }

    private static func containsOpenSSHKey(_ value: String) -> Bool {
        let fields = value.split(whereSeparator: \.isWhitespace)
        return fields.indices.dropLast().contains { index in
            let algorithm = fields[index].lowercased()
            let payload = fields[fields.index(after: index)]
            return
                (algorithm.hasPrefix("ssh-")
                || algorithm.hasPrefix("ecdsa-sha2-")
                || algorithm.hasPrefix("sk-ssh-")
                || algorithm.hasPrefix("sk-ecdsa-sha2-"))
                && payload.hasPrefix("AAAA")
        }
    }

    private static func containsAuthorizationCredential(_ value: String) -> Bool {
        let patterns = [
            #"(?i)(?:authorization\s*:\s*)?basic\s+[a-z0-9+/=]{8,}"#,
            #"(?i)authorization\s*:\s*bearer\s+\S+"#,
            #"(?i)\bbearer\s+[a-z0-9]+[-._~+/=][a-z0-9._~+/=-]{10,}"#,
        ]
        return patterns.contains { value.range(of: $0, options: .regularExpression) != nil }
    }

    private static func containsCompactJOSECredential(_ value: String) -> Bool {
        value.split(whereSeparator: \.isWhitespace).contains { field in
            let candidate = field.trimmingCharacters(
                in: CharacterSet(charactersIn: "\"'(),;[]{}")
            )
            let segments = candidate.split(separator: ".", omittingEmptySubsequences: false)
            guard segments.count == 3 || segments.count == 5,
                segments.allSatisfy({ segment in
                    !segment.isEmpty
                        && segment.allSatisfy {
                            $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "="
                        }
                }),
                let headerData = decodeBase64URL(segments[0]),
                let header = try? JSONSerialization.jsonObject(with: headerData)
                    as? [String: Any],
                header["alg"] is String
            else { return false }
            return segments.count == 3 || header["enc"] is String
        }
    }

    private static func decodeBase64URL(_ value: Substring) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    private static func containsCredentialBearingURI(_ value: String) -> Bool {
        let pattern = #"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+"#
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return true }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.matches(in: value, range: range).contains { match in
            guard let matchRange = Range(match.range, in: value),
                let components = URLComponents(string: String(value[matchRange]))
            else { return true }
            return components.user != nil || components.password != nil
        }
    }

    private static func containsJSONDocument(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{") || trimmed.hasPrefix("[") else { return false }
        return (try? JSONSerialization.jsonObject(with: Data(trimmed.utf8))) != nil
    }
}

enum ResourceProtectedMetadataDisclosure {
    static let allowedMetadataKeys: Set<ResourceMetadataKey> = Set(
        [
            "host.os.version",
            "host.kernel.release",
            "host.cpu.model",
            "host.cpu.logical-count",
            "host.memory.total-bytes",
            "host.storage.total-bytes",
            "host.storage.available-bytes",
            "host.docker.version",
        ].compactMap(ResourceMetadataKey.init(rawValue:))
    )

    static func isApprovedEntry(_ entry: ResourceMetadataEntry) -> Bool {
        switch (entry.key.rawValue, entry.value) {
        case ("host.os.version", .text(let value)),
            ("host.kernel.release", .text(let value)),
            ("host.cpu.model", .text(let value)),
            ("host.docker.version", .text(let value)):
            return !value.isEmpty && value.utf8.count <= 256
        case ("host.cpu.logical-count", .integer(let value)):
            return (1...65_536).contains(value)
        case ("host.memory.total-bytes", .byteCount),
            ("host.storage.total-bytes", .byteCount),
            ("host.storage.available-bytes", .byteCount):
            return true
        default:
            return false
        }
    }
}
