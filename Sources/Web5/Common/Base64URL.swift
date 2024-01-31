import ExtrasBase64
import Foundation

extension Collection where Element == UInt8 {
    /// Encodes a collection of bytes to a Base64URL encoded string
    public func base64UrlEncodedString(padded: Bool = false) -> String {
        let options: Base64.EncodingOptions =
            padded
            ? [.base64UrlAlphabet]
            : [.base64UrlAlphabet, .omitPaddingCharacter]

        return Base64.encodeString(bytes: self, options: options)
    }
}

extension String {
    /// Decodes a Base64URL encoded string into bytes
    public func decodeBase64Url(padded: Bool = false) throws -> Data {
        let options: Base64.DecodingOptions =
            padded
            ? [.base64UrlAlphabet]
            : [.base64UrlAlphabet, .omitPaddingCharacter]

        return Data(try Base64.decode(string: self, options: options))
    }
}
