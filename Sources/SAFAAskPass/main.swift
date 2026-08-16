import Foundation

FileHandle.standardError.write(Data("safa-askpass requires a broker child binding\n".utf8))
Foundation.exit(45)
