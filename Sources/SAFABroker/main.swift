import Foundation

FileHandle.standardError.write(Data("safa-broker is not configured\n".utf8))
Foundation.exit(45)
