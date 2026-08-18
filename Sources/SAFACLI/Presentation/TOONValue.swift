struct TOONField: Equatable, Sendable {
    let key: String
    let value: TOONValue
}

indirect enum TOONValue: Equatable, Sendable {
    case string(String)
    case integer(Int64)
    case number(Double)
    case boolean(Bool)
    case object([TOONField])
    case array([TOONValue])
    case null
}

enum TOONEncodingError: Error, Equatable, Sendable {
    case duplicateKey(String)
    case maximumDepthExceeded(Int)
    case collectionLimitExceeded(Int)
    case outputLimitExceeded(Int)
    case invalidPresentationShape
}

extension TOONValue {
    var isPrimitive: Bool {
        switch self {
        case .string, .integer, .number, .boolean, .null: true
        case .object, .array: false
        }
    }
}
