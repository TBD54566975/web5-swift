import Foundation
import AnyCodable
import GZIP

public enum StatusListConstant {
    public static let defaultContext = "https://w3id.org/vc/status-list/2021/v1"
    public static let defaultVcType = "StatusList2021Credential";
    /// The size of the bitstring in bits.
    /// The bitstring is 16KB in size.
    public static let bitStringSize = 16 * 1024 * 8 // 16KiB in bits
}

/// The status purpose dictated by Status List 2021 spec.
/// See: [Status List 2021 Entry](https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/#statuslist2021entry)
public enum StatusPurpose: String {
    /// `revocation` purpose
    case revocation = "revocation"
    /// `suspension` purpose
    case suspension = "suspension"
}

/// StatusListCredentialCreateOptions for creating a status list credential.
public struct StatusListCredentialCreateOptions {
    /// The id used for the resolvable path to the status list credential String.
    let statusListCredentialId: String
    /// The issuer URI of the credential, as a String.
    let issuer: String
    /// The status purpose of the status list cred, eg: revocation, as a StatusPurpose.
    let statusPurpose: StatusPurpose
    /// The credentials to be included in the status list credential, eg: revoked credentials, list of type VerifiableCredential.
    let credentialsToDisable: [VerifiableCredential]
}

/// StatusList2021Entry Credential status lookup information included in a Verifiable Credential that supports status lookup.
/// Data model dictated by the Status List 2021 spec.
/// See: [Status List 2021 Entry](https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/#example-example-statuslist2021credential)
public struct StatusList2021Entry: Codable, Equatable {
    /// The id of the status list entry.
    let id: String
    /// The type of the status list entry.
    let type: String
    /// The status purpose of the status list entry.
    let statusPurpose: String
    /// The index of the status entry in the status list. Poorly named by spec, should really be `entryIndex`.
    let statusListIndex: String
    /// URL to the status list.
    let statusListCredential: String
}


public struct StatusListCredential {
    /**
     * Create a `StatusListCredential` with a specific purpose, e.g., for revocation.
     *
     * - Parameters:
     *   - options: The options for creating the status list credential.
     * - Returns: A special `VerifiableCredential` instance that is a StatusListCredential.
     * - Throws: An error if the status list credential cannot be created.
     *
     * Example:
     * ```
     * let options = StatusListCredentialCreateOptions(
     *     statusListCredentialId: "https://statuslistcred.com/123",
     *     issuer: issuerDid.uri,
     *     statusPurpose: .revocation,
     *     credentialsToDisable: [credWithCredStatus]
     * )
     * let credential = try StatusListCredential.create(options: options)
     * ```
     */
    public static func create(options: StatusListCredentialCreateOptions) throws -> VerifiableCredential {
        let indexesOfCredentialsToRevoke = try validateStatusListEntryIndexesAreAllUnique(statusPurpose: options.statusPurpose, credentials: options.credentialsToDisable)
        let bitString = try generateBitString(indexOfBitsToTurnOn: indexesOfCredentialsToRevoke)

        let credentialSubject: [String: AnyCodable] = [
            "id": AnyCodable(options.statusListCredentialId),
            "type": AnyCodable("StatusList2021"),
            "statusPurpose": AnyCodable(options.statusPurpose),
            "encodedList": AnyCodable(bitString)
        ]

        let vcDataModel = VCDataModel(
            context: [CredentialConstant.defaultContext, StatusListConstant.defaultContext],
            id: options.statusListCredentialId,
            type: [CredentialConstant.defaultVcType, StatusListConstant.defaultVcType],
            issuer: options.issuer,
            issuanceDate: ISO8601Date(wrappedValue: Date()), //getCurrentXmlSchema112Timestamp()
            expirationDate: nil,
            credentialSubject: credentialSubject,
            credentialStatus: nil,
            credentialSchema: nil,
            evidence: nil
        )

        return VerifiableCredential(vcDataModel: vcDataModel)
    }

    /**
     * Validates that the status list entry index in all the given credentials are unique,
     * and returns the unique index values.
     *
     * - Parameters:
     *   - statusPurpose: The status purpose that all given credentials must match to.
     *   - credentials: An array of VerifiableCredential objects each containing a status list entry index.
     * - Returns: An array of unique statusListIndex values.
     * - Throws: An error if any validation fails.
     */
    private static func validateStatusListEntryIndexesAreAllUnique(statusPurpose: StatusPurpose, credentials: [VerifiableCredential]) throws -> [Int] {
        var uniqueIndexes = Set<String>()
        
        for vc in credentials {
            guard let statusList2021Entry = vc.vcDataModel.credentialStatus else {
                throw StatusListCredential.Error.statusListCredentialError("No credential status found in credential")
            }
            
            guard statusList2021Entry.statusPurpose == statusPurpose.rawValue else {
                throw StatusListCredential.Error.statusListCredentialError("Status purpose mismatch")
            }
            
            guard !uniqueIndexes.contains(statusList2021Entry.statusListIndex) else {
                throw StatusListCredential.Error.statusListCredentialError("Duplicate entry found with index: \(statusList2021Entry.statusListIndex)")
            }
            
            guard let index = Int(statusList2021Entry.statusListIndex), index >= 0 else {
                throw StatusListCredential.Error.statusListCredentialError("Status list index cannot be negative")
            }
            
            guard index < StatusListConstant.bitStringSize else {
                throw StatusListCredential.Error.statusListCredentialError("Status list index is larger than the bitset size")
            }
            
            uniqueIndexes.insert(statusList2021Entry.statusListIndex)
        }
        
        return uniqueIndexes.compactMap { Int($0) }
    }

    /**
     * Validates if a given credential is part of the status list represented by a [VerifiableCredential].
     *
     * - Parameters:
     *   - credentialToValidate: The [VerifiableCredential] to be validated against the status list.
     *   - statusListCredential: The [VerifiableCredential] representing the status list.
     * - Returns: A [Bool] indicating whether the `credentialToValidate` is part of the status list.
     *
     * This function checks if the given `credentialToValidate`'s status list index is present in the expanded status list derived from the `statusListCredential`.
     */
    public static func validateCredentialInStatusList(
        credentialToValidate: VerifiableCredential,
        statusListCredential: VerifiableCredential
    ) throws -> Bool {
        guard let statusListEntryValue = credentialToValidate.vcDataModel.credentialStatus else {
            throw StatusListCredential.Error.validateError("Status list entry is missing in the credential to validate")
        }
        
        let credentialSubject = statusListCredential.vcDataModel.credentialSubject
        guard let statusListCredStatusPurpose = credentialSubject["statusPurpose"]?.value as? StatusPurpose,
              let encodedListCompressedBitString = credentialSubject["encodedList"]?.value as? String else {
            throw StatusListCredential.Error.validateError("Invalid status list credential format")
        }
        
        guard statusListEntryValue.statusPurpose == statusListCredStatusPurpose.rawValue else {
            throw StatusListCredential.Error.validateError("Status purposes do not match between the credentials")
        }
        
        guard !encodedListCompressedBitString.isEmpty else {
            throw StatusListCredential.Error.validateError("Compressed bitstring is null or empty")
        }
        
        guard let statusListIndex = Int(statusListEntryValue.statusListIndex) else {
            throw StatusListCredential.Error.validateError("Invalid status list index")
        }
        
        return try getBit(compressedBitstring: encodedListCompressedBitString, bitIndex: statusListIndex)
    }

     /**
     * Generates a Base64URL encoded, GZIP compressed bit string.
     *
     * - Parameter indexOfBitsToTurnOn: The indexes of the bits to turn on (set to 1) in the bit string.
     * - Returns: The compressed bit string as a base64-encoded string.
     */
    private static func generateBitString(indexOfBitsToTurnOn: [Int]) throws -> String {
        var bitArray = [UInt8](repeating: 0, count: StatusListConstant.bitStringSize / 8)

        indexOfBitsToTurnOn.forEach { index in
            let byteIndex = index / 8
            let bitIndex = index % 8
            bitArray[byteIndex] |= 1 << (7 - bitIndex)
        }

        guard let compressedData = (Data(bitArray) as NSData).gzipped() else {
            throw StatusListCredential.Error.generateBitError("Compression failed")
        }
        return compressedData.base64UrlEncodedString()
    }

     /**
     * Retrieves the value of a specific bit from a compressed base64 URL-encoded bitstring
     * by decoding and decompressing a bitstring, then extracting a bit's value by its index.
     *
     * - Parameters:
     *   - compressedBitstring: A base64 URL-encoded string representing the compressed bitstring.
     *   - bitIndex: The zero-based index of the bit to retrieve from the decompressed bitstream.
     * - Returns: True if the bit at the specified index is 1, false if it is 0.
     */
    private static func getBit(compressedBitstring: String, bitIndex: Int) throws -> Bool {
        guard let compressedData = try? compressedBitstring.decodeBase64Url(),
              let decompressedData = (compressedData as NSData).gunzipped() else {
            throw StatusListCredential.Error.generateBitError("Decompression failed")
        }

        let byteIndex = bitIndex / 8
        let bitIndexWithinByte = bitIndex % 8

        let byte = decompressedData[byteIndex]
        let bitInteger = (byte >> (7 - bitIndexWithinByte)) & 1

        return bitInteger == 1
    }

    #if DEBUG
    public static func getBit(s: String, i: Int) throws -> Bool {
        try getBit(compressedBitstring: s, bitIndex: i)
    }
    #endif

}

extension StatusListCredential {
    enum Error: Swift.Error, Equatable {
        case statusListCredentialError(String)
        case generateBitError(String)
        case validateError(String)
    }
}
