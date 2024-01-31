import Foundation

/// Protocol defining the behaviors required to import keys
protocol KeyImporter {

    /// Imports a JWK key representation
    /// - Parameter key: JWK key to import
    /// - Returns: Alias of the imported key, which can be used to reference the key in future operations
    func `import`(key: Jwk) throws -> String
}
