import CryptoKit
import Foundation
import SAFADomain

public actor AuditService {
    private var events: [AuditEvent] = []

    public init() {}

    public func recordRequest(
        alias: ResourceAlias,
        fingerprint: String,
        now: Date = Date()
    ) {
        append(
            kind: .request, alias: alias, fingerprint: fingerprint, outcome: "submitted", now: now)
    }

    public func recordDecision(
        alias: ResourceAlias,
        fingerprint: String,
        decision: String,
        now: Date = Date()
    ) {
        append(kind: .decision, alias: alias, fingerprint: fingerprint, outcome: decision, now: now)
    }

    public func recordExecution(
        alias: ResourceAlias,
        fingerprint: String,
        outcome: String,
        now: Date = Date()
    ) {
        append(kind: .execution, alias: alias, fingerprint: fingerprint, outcome: outcome, now: now)
    }

    private func append(
        kind: AuditEventKind,
        alias: ResourceAlias,
        fingerprint: String,
        outcome: String,
        now: Date
    ) {
        let previous = events.last?.digest
        let sequence = UInt64(events.count + 1)
        let material =
            "\(sequence)|\(kind.rawValue)|\(alias.rawValue)|\(fingerprint)|\(outcome)|\(previous ?? "")"
        let digest = SHA256.hash(data: Data(material.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        events.append(
            AuditEvent(
                sequence: sequence,
                id: UUID(),
                kind: kind,
                timestamp: now,
                actor: "agent",
                resourceAlias: alias,
                summary: ["fingerprint": fingerprint, "outcome": outcome],
                previousDigest: previous,
                digest: digest
            )
        )
    }

    public func exportSanitized() -> String {
        events.map {
            "\($0.sequence) \($0.kind.rawValue) \($0.resourceAlias?.rawValue ?? "unknown") \($0.summary["fingerprint"] ?? "") \($0.summary["outcome"] ?? "")"
        }.joined(separator: "\n")
    }
}
