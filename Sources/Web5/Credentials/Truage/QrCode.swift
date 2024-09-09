import Foundation
import Base32
import SwiftCBOR

let BASE_32_UPPERCASE_MULTIBASE_PREFIX = "B"

enum QRCodeError: Error {
    case unsupportedFormat
    case invalidEncoding
    case invalidInput
    case encodingError
}

func fromQrCodeText(expectedHeader: String = "", text: String) throws -> CBOR {
    guard text.starts(with: expectedHeader) else {
        throw QRCodeError.unsupportedFormat
    }
    
    let multibasePayload = String(text.dropFirst(expectedHeader.count))
    
    guard multibasePayload.starts(with: BASE_32_UPPERCASE_MULTIBASE_PREFIX) else {
        throw QRCodeError.invalidEncoding
    }
    
    let encodedPayload = String(multibasePayload.dropFirst())
    
    guard let cborArrayBuffer = base32Decode(encodedPayload) else {
        throw QRCodeError.invalidEncoding
    }
    
    // Remove the first 3 bytes
    let cborBytes = Array(cborArrayBuffer.dropFirst(3))
       
    guard let cbor = try CBOR.decode(cborBytes) else {
        throw QRCodeError.encodingError
    }
   
    return cbor
}

func toQrCodeText(header: String = "", jsonDocument: String? = nil, cborBytes: Data? = nil) throws -> String {
    guard jsonDocument == nil || cborBytes == nil else {
        throw QRCodeError.invalidInput // Only one of jsonDocument and cborBytes is allowed
    }
    
    var finalCborBytes: Data
    
    if let cborBytes = cborBytes {
        finalCborBytes = cborBytes
    } else if let jsonDocument = jsonDocument {
        finalCborBytes = Data(CBOR.encode(jsonDocument))
    } else {
        throw QRCodeError.invalidInput // At least one input must be provided
    }
    
    return bytesToQrCodeText(header: header, bytes: finalCborBytes)
}

private func bytesToQrCodeText(header: String = "", bytes: Data) -> String {
    let encoded = base32Encode(bytes)
    return "\(header)\(BASE_32_UPPERCASE_MULTIBASE_PREFIX)\(encoded)"
}
