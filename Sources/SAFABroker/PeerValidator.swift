import Darwin
import Foundation
import SAFADomain
import SAFAProtocol
import Security

public enum PeerRole: String, Sendable {
    case agent
    case trustedApp
    case askPass
}

public struct PeerIdentityEvidence: Equatable, Sendable {
    public let effectiveUserID: UInt32
    public let auditSessionID: UInt32
    public let signingIdentifier: String?
    public let teamIdentifier: String?

    public init(
        effectiveUserID: UInt32,
        auditSessionID: UInt32,
        signingIdentifier: String?,
        teamIdentifier: String?
    ) {
        self.effectiveUserID = effectiveUserID
        self.auditSessionID = auditSessionID
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
    }
}

public struct PeerValidationPolicy: Sendable {
    public let brokerUserID: UInt32
    public let auditSessionID: UInt32
    public let teamIdentifier: String
    public let agentSigningIdentifiers: Set<String>
    public let trustedAppSigningIdentifier: String
    public let askPassSigningIdentifier: String

    public init(
        brokerUserID: UInt32,
        auditSessionID: UInt32,
        teamIdentifier: String,
        agentSigningIdentifiers: Set<String>,
        trustedAppSigningIdentifier: String,
        askPassSigningIdentifier: String = "dev.safa.askpass"
    ) {
        self.brokerUserID = brokerUserID
        self.auditSessionID = auditSessionID
        self.teamIdentifier = teamIdentifier
        self.agentSigningIdentifiers = agentSigningIdentifiers
        self.trustedAppSigningIdentifier = trustedAppSigningIdentifier
        self.askPassSigningIdentifier = askPassSigningIdentifier
    }
}

public enum PeerValidationError: Error, Equatable, Sendable {
    case unsigned
    case wrongUser
    case wrongAuditSession
    case wrongTeam
    case unauthorizedComponent
}

public struct PeerValidator: Sendable {
    private let policy: PeerValidationPolicy

    public init(policy: PeerValidationPolicy) {
        self.policy = policy
    }

    public func validate(
        _ evidence: PeerIdentityEvidence,
        as role: PeerRole
    ) throws -> CallerIdentity {
        guard
            let signingIdentifier = evidence.signingIdentifier,
            let teamIdentifier = evidence.teamIdentifier
        else {
            throw PeerValidationError.unsigned
        }
        guard evidence.effectiveUserID == policy.brokerUserID else {
            throw PeerValidationError.wrongUser
        }
        guard evidence.auditSessionID == policy.auditSessionID else {
            throw PeerValidationError.wrongAuditSession
        }
        guard teamIdentifier == policy.teamIdentifier else {
            throw PeerValidationError.wrongTeam
        }

        switch role {
        case .agent:
            guard policy.agentSigningIdentifiers.contains(signingIdentifier) else {
                throw PeerValidationError.unauthorizedComponent
            }
        case .trustedApp:
            guard signingIdentifier == policy.trustedAppSigningIdentifier else {
                throw PeerValidationError.unauthorizedComponent
            }
        case .askPass:
            guard signingIdentifier == policy.askPassSigningIdentifier else {
                throw PeerValidationError.unauthorizedComponent
            }
        }

        return CallerIdentity(
            signingIdentifier: signingIdentifier,
            teamIdentifier: teamIdentifier,
            effectiveUserID: evidence.effectiveUserID,
            auditSessionID: evidence.auditSessionID
        )
    }

    public func codeSigningRequirement(for role: PeerRole) throws -> String {
        let identifiers: Set<String>
        switch role {
        case .agent: identifiers = policy.agentSigningIdentifiers
        case .trustedApp: identifiers = [policy.trustedAppSigningIdentifier]
        case .askPass: identifiers = [policy.askPassSigningIdentifier]
        }
        return try CodeSigningRequirement.requirement(
            teamIdentifier: policy.teamIdentifier,
            signingIdentifiers: identifiers
        )
    }
}

public enum XPCPeerIdentityReader {
    public static func evidence(for connection: NSXPCConnection) -> PeerIdentityEvidence {
        let signing = signingInformation(processIdentifier: connection.processIdentifier)
        return PeerIdentityEvidence(
            effectiveUserID: connection.effectiveUserIdentifier,
            auditSessionID: UInt32(bitPattern: connection.auditSessionIdentifier),
            signingIdentifier: signing.identifier,
            teamIdentifier: signing.team
        )
    }

    private static func signingInformation(
        processIdentifier: pid_t
    ) -> (identifier: String?, team: String?) {
        let attributes = [kSecGuestAttributePid as String: processIdentifier] as CFDictionary
        var guest: SecCode?
        guard
            SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
            let guest
        else {
            return (nil, nil)
        }

        var staticCode: SecStaticCode?
        guard
            SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess,
            let staticCode
        else {
            return (nil, nil)
        }

        var information: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &information
            )
                == errSecSuccess,
            let dictionary = information as? [String: Any]
        else {
            return (nil, nil)
        }
        return (
            dictionary[kSecCodeInfoIdentifier as String] as? String,
            dictionary[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }
}
