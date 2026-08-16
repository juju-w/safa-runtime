import Foundation
import Security

public enum CodeSigningRequirementError: Error, Equatable, Sendable {
    case unsignedRuntime
}

public enum CodeSigningRequirement {
    public static func currentTeamIdentifier() throws -> String {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            throw CodeSigningRequirementError.unsignedRuntime
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw CodeSigningRequirementError.unsignedRuntime
        }
        var information: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &information
            ) == errSecSuccess,
            let dictionary = information as? [String: Any],
            let team = dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
            !team.isEmpty
        else {
            throw CodeSigningRequirementError.unsignedRuntime
        }
        return team
    }

    public static func requirement(
        teamIdentifier: String,
        signingIdentifiers: Set<String>
    ) throws -> String {
        guard
            teamIdentifier.range(of: "^[A-Z0-9]{5,16}$", options: .regularExpression) != nil,
            !signingIdentifiers.isEmpty,
            signingIdentifiers.allSatisfy({
                $0.range(of: "^[A-Za-z0-9.-]{1,255}$", options: .regularExpression) != nil
            })
        else {
            throw CodeSigningRequirementError.unsignedRuntime
        }
        let identifiers = signingIdentifiers.sorted()
            .map { "identifier \"\($0)\"" }
            .joined(separator: " or ")
        return
            "anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\" and (\(identifiers))"
    }
}
