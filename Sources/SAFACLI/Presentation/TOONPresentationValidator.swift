struct TOONPresentationValidator: Sendable {
    let maximumDepth: Int
    let maximumCollectionCount: Int
    let maximumOutputBytes: Int

    func validate(_ value: TOONValue, depth: Int = 0) throws {
        guard depth <= maximumDepth else {
            throw TOONEncodingError.maximumDepthExceeded(maximumDepth)
        }

        switch value {
        case let .string(value):
            try validateText(value)
        case .integer, .number, .boolean, .null:
            break
        case let .array(values):
            try validateCollectionCount(values.count)
            for value in values {
                try validate(value, depth: depth + 1)
            }
        case let .object(fields):
            try validateCollectionCount(fields.count)
            var keys = Set<String>()
            for field in fields {
                guard keys.insert(field.key).inserted else {
                    throw TOONEncodingError.duplicateKey(field.key)
                }
                try validateText(field.key)
                try validate(field.value, depth: depth + 1)
            }
        }
    }

    private func validateCollectionCount(_ count: Int) throws {
        guard count <= maximumCollectionCount else {
            throw TOONEncodingError.collectionLimitExceeded(maximumCollectionCount)
        }
    }

    private func validateText(_ value: String) throws {
        guard value.utf8.count <= maximumOutputBytes else {
            throw TOONEncodingError.outputLimitExceeded(maximumOutputBytes)
        }
    }
}
