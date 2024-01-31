import Foundation

/// Protocol defining the behaviors required to export keys
protocol KeyExporter {

    /// Exports the private key identified by the provided alias.
    /// - Parameter keyAlias: Alias of the private key to export
    /// - Returns: JWK representing the private key
    func exportKey(keyAlias: String) throws -> Jwk
}
