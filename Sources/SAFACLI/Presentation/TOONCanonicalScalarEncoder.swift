struct TOONCanonicalScalarEncoder: Sendable {
    func encodePrimitiveRow(_ values: [TOONValue]) throws -> String {
        try values.map { try encodePrimitive($0) }.joined(separator: ",")
    }

    func encodePrimitive(_ value: TOONValue) throws -> String {
        switch value {
        case let .string(value): encodeString(value)
        case let .integer(value): String(value)
        case let .number(value): encodeNumber(value)
        case let .boolean(value): value ? "true" : "false"
        case .null: "null"
        case .object, .array: throw TOONEncodingError.invalidPresentationShape
        }
    }

    func encodeKey(_ key: String) -> String {
        isUnquotedKey(key) ? key : "\"" + escape(key) + "\""
    }

    private func encodeNumber(_ value: Double) -> String {
        guard value.isFinite else { return "null" }
        if value == 0 { return "0" }

        let magnitude = abs(value)
        let shortest = String(value).lowercased()
        if magnitude >= 0.000001, magnitude < 1e21 {
            return expandExponent(shortest)
        }
        return normalizeExponent(shortest)
    }

    private func expandExponent(_ value: String) -> String {
        guard let exponentIndex = value.firstIndex(of: "e") else {
            return trimFraction(value)
        }

        let mantissa = String(value[..<exponentIndex])
        let exponentText = String(value[value.index(after: exponentIndex)...])
        guard let exponent = Int(exponentText) else { return value }

        let negative = mantissa.hasPrefix("-")
        let unsignedMantissa = negative ? String(mantissa.dropFirst()) : mantissa
        let components = unsignedMantissa.split(separator: ".", omittingEmptySubsequences: false)
        let integerDigits = String(components[0])
        let fractionalDigits = components.count == 2 ? String(components[1]) : ""
        let digits = integerDigits + fractionalDigits
        let decimalIndex = integerDigits.count + exponent

        let expanded: String
        if decimalIndex <= 0 {
            expanded = "0." + String(repeating: "0", count: -decimalIndex) + digits
        } else if decimalIndex >= digits.count {
            expanded = digits + String(repeating: "0", count: decimalIndex - digits.count)
        } else {
            let split = digits.index(digits.startIndex, offsetBy: decimalIndex)
            expanded = String(digits[..<split]) + "." + String(digits[split...])
        }

        let normalized = trimFraction(expanded)
        return negative ? "-" + normalized : normalized
    }

    private func normalizeExponent(_ value: String) -> String {
        guard let exponentIndex = value.firstIndex(of: "e") else {
            return trimFraction(value)
        }
        let mantissa = trimFraction(String(value[..<exponentIndex]))
        let exponentText = String(value[value.index(after: exponentIndex)...])
        guard let exponent = Int(exponentText) else { return value }
        return mantissa + "e" + (exponent >= 0 ? "+" : "") + String(exponent)
    }

    private func trimFraction(_ value: String) -> String {
        guard value.contains(".") else { return value }
        var result = value
        while result.last == "0" { result.removeLast() }
        if result.last == "." { result.removeLast() }
        return result
    }

    private func encodeString(_ value: String) -> String {
        requiresQuotes(value) ? "\"" + escape(value) + "\"" : value
    }

    private func requiresQuotes(_ value: String) -> Bool {
        guard !value.isEmpty else { return true }
        guard let first = value.unicodeScalars.first, let last = value.unicodeScalars.last else {
            return true
        }
        if first.value == 0x20 || first.value == 0x09 || last.value == 0x20 || last.value == 0x09 {
            return true
        }
        if value == "true" || value == "false" || value == "null" || isNumericLike(value) {
            return true
        }
        if first == "-" || first == "#" { return true }

        return value.unicodeScalars.contains { scalar in
            scalar.value <= 0x1F
                || scalar == ":"
                || scalar == "\""
                || scalar == "\\"
                || scalar == "["
                || scalar == "]"
                || scalar == "{"
                || scalar == "}"
                || scalar == ","
        }
    }

    private func isNumericLike(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty else { return false }
        var index = 0

        if bytes[index] == 0x2B || bytes[index] == 0x2D {
            index += 1
            guard index < bytes.count else { return false }
        }
        guard consumeDigits(bytes, index: &index) else { return false }

        if index < bytes.count, bytes[index] == 0x2E {
            index += 1
            guard consumeDigits(bytes, index: &index) else { return false }
        }

        if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
            index += 1
            guard index < bytes.count else { return false }
            if bytes[index] == 0x2B || bytes[index] == 0x2D {
                index += 1
                guard index < bytes.count else { return false }
            }
            guard consumeDigits(bytes, index: &index) else { return false }
        }
        return index == bytes.count
    }

    private func consumeDigits(_ bytes: [UInt8], index: inout Int) -> Bool {
        let start = index
        while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 {
            index += 1
        }
        return index > start
    }

    private func isUnquotedKey(_ key: String) -> Bool {
        let bytes = Array(key.utf8)
        guard let first = bytes.first, isASCIIAlpha(first) || first == 0x5F else { return false }
        return bytes.dropFirst().allSatisfy {
            isASCIIAlpha($0) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F || $0 == 0x2E
        }
    }

    private func isASCIIAlpha(_ value: UInt8) -> Bool {
        (value >= 0x41 && value <= 0x5A) || (value >= 0x61 && value <= 0x7A)
    }

    private func escape(_ value: String) -> String {
        var result = ""
        result.reserveCapacity(value.utf8.count)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x5C: result += "\\\\"
            case 0x22: result += "\\\""
            case 0x0A: result += "\\n"
            case 0x0D: result += "\\r"
            case 0x09: result += "\\t"
            case 0x00...0x1F:
                let hex = String(scalar.value, radix: 16, uppercase: false)
                result += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default:
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
}
