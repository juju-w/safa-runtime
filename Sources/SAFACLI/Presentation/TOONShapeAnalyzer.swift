indirect enum TOONFieldShape: Sendable {
    case primitive(String)
    case object(String, [TOONFieldShape])

    var key: String {
        switch self {
        case let .primitive(key), let .object(key, _): key
        }
    }
}

struct TOONShapeAnalyzer: Sendable {
    func tabularShape(_ values: [TOONValue]) -> [TOONFieldShape]? {
        guard !values.isEmpty else { return nil }
        var objects: [[TOONField]] = []
        for value in values {
            guard case let .object(fields) = value, !fields.isEmpty else { return nil }
            objects.append(fields)
        }
        return uniformShape(objects)
    }

    func keyedShape(_ fields: [TOONField]) -> [TOONFieldShape]? {
        guard fields.count >= 2 else { return nil }
        var objects: [[TOONField]] = []
        for field in fields {
            guard case let .object(valueFields) = field.value, !valueFields.isEmpty else {
                return nil
            }
            objects.append(valueFields)
        }
        return uniformShape(objects)
    }

    func flattenedPrimitives(
        _ fields: [TOONField],
        shape: [TOONFieldShape]
    ) throws -> [TOONValue] {
        var values: [TOONValue] = []
        for fieldShape in shape {
            guard let value = fields.first(where: { $0.key == fieldShape.key })?.value else {
                throw TOONEncodingError.invalidPresentationShape
            }
            switch fieldShape {
            case .primitive:
                guard value.isPrimitive else {
                    throw TOONEncodingError.invalidPresentationShape
                }
                values.append(value)
            case let .object(_, nestedShape):
                guard case let .object(nestedFields) = value else {
                    throw TOONEncodingError.invalidPresentationShape
                }
                values.append(
                    contentsOf: try flattenedPrimitives(nestedFields, shape: nestedShape)
                )
            }
        }
        return values
    }

    private func uniformShape(_ objects: [[TOONField]]) -> [TOONFieldShape]? {
        guard let first = objects.first, !first.isEmpty else { return nil }
        let expectedKeys = Set(first.map(\.key))
        guard objects.allSatisfy({ Set($0.map(\.key)) == expectedKeys }) else { return nil }

        var shape: [TOONFieldShape] = []
        for firstField in first {
            let column = objects.compactMap { fields in
                fields.first(where: { $0.key == firstField.key })?.value
            }
            guard column.count == objects.count else { return nil }

            if column.allSatisfy(\.isPrimitive) {
                shape.append(.primitive(firstField.key))
                continue
            }

            var nestedObjects: [[TOONField]] = []
            for value in column {
                guard case let .object(fields) = value, !fields.isEmpty else { return nil }
                nestedObjects.append(fields)
            }
            guard let nestedShape = uniformShape(nestedObjects) else { return nil }
            shape.append(.object(firstField.key, nestedShape))
        }
        return shape
    }
}
