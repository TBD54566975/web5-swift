import Foundation

/// Decentralized Identifier (DID), according to the  [W3C DID Core specification](https://www.w3.org/TR/did-core).
public struct DID: Equatable {

    /// Represents the complete Decentralized Identifier (DID) URI
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#did-syntax) for more information
    public let uri: String

    /// DID URI without the fragment component
    public var uriWithoutFragment: String {
        return uri.components(separatedBy: "#").first ?? uri
    }

    /// DID method in the URI, which indicates the underlying method-specific
    /// identifier scheme (e.g.: `jwk`, `dht`, `web`, etc.)
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#method-schemes) for more information
    public let methodName: String

    /// Method-specific identifier part of the DID URI
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#method-specific-id) for more information
    public let identifier: String

    /// Optional map containing parameters present in the DID URI. These parameters
    /// are method-specific
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#did-parameters) for more information
    public let params: [String: String]?

    /// Optional path component in the DID URI
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#path) for more information
    public let path: String?

    /// Optional query component in the DID URI, used to express a request for a specific
    /// representation or resource related to a DID
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#query) for more information
    public let query: String?

    /// Optional fragment component in the DID URI, used to reference a specific part
    /// of a DID Document
    ///
    /// See [spec](https://www.w3.org/TR/did-core/#fragment) for more information
    public let fragment: String?

    /// Construct a DID from a URI in accordance to the ABNF rules specified in the specification
    /// [here](https://www.w3.org/TR/did-core/#did-syntax).
    /// - Parameter didURI: URI of DID to parse
    /// - Returns: `DID` instance if parsing was successful. Throws error otherwise.
    public init(didURI: String) throws {
        guard let matches = try? Regex.matches(for: Self.didRegexPattern, in: didURI),
            matches.count == Self.didRegexPatternExpectedMatchCount
        else {
            throw DID.Error.invalidURI
        }

        let methodName = matches[1]
        let identifier = matches[2]

        var params: [String: String]? = nil
        let paramsMatch = matches[3]
        if paramsMatch.count > 0 {
            params =
                paramsMatch
                .split(separator: ";")
                .map(String.init)
                .reduce(into: [String: String]()) { dict, param in
                    let parts = param.split(separator: "=", maxSplits: 1).map(String.init)
                    if parts.count == 2 {
                        dict[parts[0]] = parts[1]
                    }
                }
        }

        let path: String? = {
            let pathMatch = matches[4]
            if pathMatch.count > 0 {
                return pathMatch
            } else {
                return nil
            }
        }()

        let query: String? = {
            let queryMatch = matches[5]
            if queryMatch.count > 0 {
                // Drop the leading `?` character from the match
                return String(queryMatch.dropFirst())
            } else {
                return nil
            }
        }()

        let fragment: String? = {
            let fragmentMatch = matches[6]
            if fragmentMatch.count > 0 {
                // Drop the leading `#` character from the match
                return String(fragmentMatch.dropFirst())
            } else {
                return nil
            }
        }()

        self.uri = didURI
        self.methodName = methodName
        self.identifier = identifier
        self.params = params
        self.path = path
        self.query = query
        self.fragment = fragment
    }

    // MARK: - Private

    private static let methodNamePattern = "([a-z0-9]+)"
    private static let idCharPattern = "(?:[a-zA-Z0-9._-]|(?:%[0-9a-fA-F]{2}))"
    private static let identifierPattern = "((?:\(idCharPattern)*:)*(?:\(idCharPattern)+))"
    private static let paramCharPattern = "[a-zA-Z0-9_.:%\\-]"
    private static let paramsPattern = "((?:;\(paramCharPattern)+=\(paramCharPattern)*)*)"
    private static let pathPattern = "(/[^#?]*)?"
    private static let queryPattern = "(\\?[^#]*)?"
    private static let fragmentPattern = "(#.*)?"

    /// Number of captured matches expected from the DID regex pattern
    private static let didRegexPatternExpectedMatchCount = 7
    private static let didRegexPattern =
        "did:\(methodNamePattern):\(identifierPattern)\(paramsPattern)\(pathPattern)\(queryPattern)\(fragmentPattern)$"
}

// MARK: - Errors

extension DID {

    public enum Error: Swift.Error {
        case invalidURI
    }
}
