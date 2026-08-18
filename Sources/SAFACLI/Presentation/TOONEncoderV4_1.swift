/// Deterministic TOON 4.1 presentation encoder for SAFA's ordered Agent CLI DTOs.
///
/// This is deliberately not a general TOON library. It has no decoder and is not used for IPC,
/// persistence, policy, or credential handling. The supported value model is exactly the JSON data
/// model that explicit SAFA v2 presentation DTOs can produce.
struct TOONEncoderV4_1: Sendable {
    static let specificationVersion = "4.1"
    static let specificationCommit = "62f16b369408180f1faf1cba7da1b46d1f336f12"

    private let maximumOutputBytes: Int
    private let scalarEncoder = TOONCanonicalScalarEncoder()
    private let shapeAnalyzer = TOONShapeAnalyzer()
    private let validator: TOONPresentationValidator

    init(
        maximumDepth: Int = 64,
        maximumCollectionCount: Int = 10_000,
        maximumOutputBytes: Int = 2_097_152
    ) {
        self.maximumOutputBytes = maximumOutputBytes
        validator = TOONPresentationValidator(
            maximumDepth: maximumDepth,
            maximumCollectionCount: maximumCollectionCount,
            maximumOutputBytes: maximumOutputBytes
        )
    }

    func encode(_ value: TOONValue) throws -> String {
        try validator.validate(value)
        let output = try encodeRoot(value).joined(separator: "\n")
        guard output.utf8.count <= maximumOutputBytes else {
            throw TOONEncodingError.outputLimitExceeded(maximumOutputBytes)
        }
        return output
    }

    private func encodeRoot(_ value: TOONValue) throws -> [String] {
        switch value {
        case .string, .integer, .number, .boolean, .null:
            return [try scalarEncoder.encodePrimitive(value)]
        case let .object(fields):
            if let shape = shapeAnalyzer.keyedShape(fields) {
                return try encodeKeyedObject(fields, shape: shape, key: nil, depth: 0)
            }
            return try encodeObjectFields(fields, depth: 0)
        case let .array(values):
            return try encodeRootArray(values)
        }
    }

    private func encodeRootArray(_ values: [TOONValue]) throws -> [String] {
        if values.isEmpty { return ["[]"] }
        if values.allSatisfy(\.isPrimitive) {
            return [
                arrayHeader(count: values.count) + ": "
                    + (try scalarEncoder.encodePrimitiveRow(values))
            ]
        }
        if let shape = shapeAnalyzer.tabularShape(values) {
            return try encodeTabularArray(values, shape: shape, key: nil, depth: 0)
        }

        var lines = [arrayHeader(count: values.count) + ":"]
        for value in values {
            lines.append(contentsOf: try encodeListItem(value, depth: 1))
        }
        return lines
    }

    private func encodeObjectFields(_ fields: [TOONField], depth: Int) throws -> [String] {
        var lines: [String] = []
        for field in fields {
            lines.append(contentsOf: try encodeField(field, depth: depth))
        }
        return lines
    }

    private func encodeField(_ field: TOONField, depth: Int) throws -> [String] {
        let prefix = indentation(depth) + scalarEncoder.encodeKey(field.key)
        switch field.value {
        case .string, .integer, .number, .boolean, .null:
            return [prefix + ": " + (try scalarEncoder.encodePrimitive(field.value))]
        case let .object(fields):
            if let shape = shapeAnalyzer.keyedShape(fields) {
                return try encodeKeyedObject(fields, shape: shape, key: field.key, depth: depth)
            }
            return [prefix + ":"] + (try encodeObjectFields(fields, depth: depth + 1))
        case let .array(values):
            return try encodeArrayField(values, key: field.key, prefix: prefix, depth: depth)
        }
    }

    private func encodeArrayField(
        _ values: [TOONValue],
        key: String,
        prefix: String,
        depth: Int
    ) throws -> [String] {
        if values.isEmpty { return [prefix + ": []"] }
        if values.allSatisfy(\.isPrimitive) {
            return [
                prefix + arrayHeader(count: values.count) + ": "
                    + (try scalarEncoder.encodePrimitiveRow(values))
            ]
        }
        if let shape = shapeAnalyzer.tabularShape(values) {
            return try encodeTabularArray(values, shape: shape, key: key, depth: depth)
        }

        var lines = [prefix + arrayHeader(count: values.count) + ":"]
        for value in values {
            lines.append(contentsOf: try encodeListItem(value, depth: depth + 1))
        }
        return lines
    }

    private func encodeListItem(_ value: TOONValue, depth: Int) throws -> [String] {
        let prefix = indentation(depth) + "-"
        switch value {
        case .string, .integer, .number, .boolean, .null:
            return [prefix + " " + (try scalarEncoder.encodePrimitive(value))]
        case let .array(values):
            return try encodeArrayListItem(values, prefix: prefix, depth: depth)
        case let .object(fields):
            return try encodeObjectListItem(fields, prefix: prefix, depth: depth)
        }
    }

    private func encodeArrayListItem(
        _ values: [TOONValue],
        prefix: String,
        depth: Int
    ) throws -> [String] {
        if values.isEmpty { return [prefix + " " + arrayHeader(count: 0) + ":"] }
        if values.allSatisfy(\.isPrimitive) {
            return [
                prefix + " " + arrayHeader(count: values.count) + ": "
                    + (try scalarEncoder.encodePrimitiveRow(values))
            ]
        }

        var lines = [prefix + " " + arrayHeader(count: values.count) + ":"]
        for value in values {
            lines.append(contentsOf: try encodeListItem(value, depth: depth + 1))
        }
        return lines
    }

    private func encodeObjectListItem(
        _ fields: [TOONField],
        prefix: String,
        depth: Int
    ) throws -> [String] {
        guard let first = fields.first else { return [prefix] }
        var firstLines = try encodeField(first, depth: depth + 1)
        guard let firstLine = firstLines.first else {
            throw TOONEncodingError.invalidPresentationShape
        }
        let fieldIndent = indentation(depth + 1)
        guard firstLine.hasPrefix(fieldIndent) else {
            throw TOONEncodingError.invalidPresentationShape
        }
        firstLines[0] = prefix + " " + firstLine.dropFirst(fieldIndent.count)

        var lines = firstLines
        for field in fields.dropFirst() {
            lines.append(contentsOf: try encodeField(field, depth: depth + 1))
        }
        return lines
    }

    private func encodeTabularArray(
        _ values: [TOONValue],
        shape: [TOONFieldShape],
        key: String?,
        depth: Int
    ) throws -> [String] {
        let headerKey = key.map(scalarEncoder.encodeKey) ?? ""
        var lines = [
            indentation(depth) + headerKey + arrayHeader(count: values.count)
                + fieldList(shape) + ":"
        ]
        for value in values {
            guard case let .object(fields) = value else {
                throw TOONEncodingError.invalidPresentationShape
            }
            let row = try shapeAnalyzer.flattenedPrimitives(fields, shape: shape)
            lines.append(
                indentation(depth + 1) + (try scalarEncoder.encodePrimitiveRow(row))
            )
        }
        return lines
    }

    private func encodeKeyedObject(
        _ fields: [TOONField],
        shape: [TOONFieldShape],
        key: String?,
        depth: Int
    ) throws -> [String] {
        let headerKey = key.map(scalarEncoder.encodeKey) ?? ""
        var lines = [
            indentation(depth) + headerKey + keyedHeader(count: fields.count)
                + fieldList(shape) + ":"
        ]
        for field in fields {
            guard case let .object(valueFields) = field.value else {
                throw TOONEncodingError.invalidPresentationShape
            }
            let row = try shapeAnalyzer.flattenedPrimitives(valueFields, shape: shape)
            lines.append(
                indentation(depth + 1) + scalarEncoder.encodeKey(field.key) + ": "
                    + (try scalarEncoder.encodePrimitiveRow(row))
            )
        }
        return lines
    }

    private func fieldList(_ shape: [TOONFieldShape]) -> String {
        let fields = shape.map { field -> String in
            switch field {
            case let .primitive(key):
                scalarEncoder.encodeKey(key)
            case let .object(key, nested):
                scalarEncoder.encodeKey(key) + fieldList(nested)
            }
        }
        return "{" + fields.joined(separator: ",") + "}"
    }

    private func arrayHeader(count: Int) -> String {
        "[\(count)]"
    }

    private func keyedHeader(count: Int) -> String {
        "[\(count):]"
    }

    private func indentation(_ depth: Int) -> String {
        String(repeating: "  ", count: depth)
    }
}
