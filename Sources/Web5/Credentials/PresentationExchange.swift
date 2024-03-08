import AnyCodable
import Foundation
import Sextant
import JSONSchema

public struct VCDataModel: Codable {
    public let context: [String]
    public let id: String
    public let type: [String]
    public let issuer: String
    public let issuanceDate: String
    public let expirationDate: String?
    public let credentialSubject: [String: AnyCodable]
    public let credentialStatus: CredentialStatus?
    public let credentialSchema: CredentialSchema?
    public let evidence: [String: AnyCodable]?
    
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id
        case type
        case issuer
        case issuanceDate
        case expirationDate
        case credentialSubject
        case credentialStatus
        case credentialSchema
        case evidence
    }
}

public struct CredentialStatus: Codable {
    public let id: String
    public let type: String
    public let statusPurpose: String
    public let statusListIndex: String
    public let statusListCredential: String
}

public struct CredentialSchema: Codable {
    public let id: String
    public let type: String
}

public struct PresentationDefinitionV2: Codable {
    public let inputDescriptors: [InputDescriptorV2]
}

public struct InputDescriptorV2: Codable, Hashable {
    public let constraints: ConstraintsV2
}

public struct ConstraintsV2: Codable, Hashable {
    public let fields: [FieldV2]?
}

public struct FieldV2: Codable, Hashable {
    public let id: String?
    public let path: [String]
    public let purpose: String?
    public let filter: [String: AnyCodable]?
    public let predicate: Optionality?
    public let name: String?
    public let optional: Bool?

    public init(
        id: String? = nil,
        path: [String],
        purpose: String? = nil,
        filter: [String: AnyCodable]? = nil,
        predicate: Optionality? = nil,
        name: String? = nil,
        optional: Bool? = nil
    ) {
        self.id = id
        self.path = path
        self.purpose = purpose
        self.filter = filter
        self.predicate = predicate
        self.name = name
        self.optional = optional
    }
}

public enum Optionality: Codable {
    case required
    case preferred
}

public enum PresentationExchange {

    // MARK: - Select Credentials
    public static func selectCredentials(
        vcJWTs: [String],
        presentationDefinition: PresentationDefinitionV2
    ) throws -> [String] {
        let inputDescriptorToVcMap = try mapInputDescriptorsToVCs(vcJWTList: vcJWTs, presentationDefinition: presentationDefinition)
        return inputDescriptorToVcMap.flatMap { $0.value }
    }
    
    public enum Error: LocalizedError {
        case parseFailed
    }

    // MARK: - Map Input Descriptors to VCs
    private static func mapInputDescriptorsToVCs(
        vcJWTList: [String],
        presentationDefinition: PresentationDefinitionV2
    ) throws -> [InputDescriptorV2: [String]] {
        let vcJWTListMap: [VCDataModel] = try vcJWTList.map { vcJWT in
                let parsedJWT  = try JWT.parse(jwtString: vcJWT)
                guard let vcJSON = parsedJWT.payload["vc"]?.value as? [String: Any] else {
                    throw Error.parseFailed
                }

                let vcData = try JSONSerialization.data(withJSONObject: vcJSON)
                let vc = try JSONDecoder().decode(VCDataModel.self, from: vcData)

                return vc
            }
        
        let vcJwtListWithNodes = zip(vcJWTList, vcJWTListMap)

        let result = try presentationDefinition.inputDescriptors.reduce(into: [InputDescriptorV2: [String]]()) { result, inputDescriptor in
            let vcJwtList = try vcJwtListWithNodes.filter { (_, node) in
                try vcSatisfiesInputDescriptor(vc: node, inputDescriptor: inputDescriptor)
            }.map { (vcJwt, _) in
                vcJwt
            }
            if !vcJwtList.isEmpty {
                result[inputDescriptor] = vcJwtList
            }
        }
        return result
    }
 
    // MARK: - VC Satisfies Input Descriptor
    private static func vcSatisfiesInputDescriptor(vc: VCDataModel, inputDescriptor: InputDescriptorV2) throws -> Bool {
        // If the Input Descriptor has constraints and fields defined, evaluate them.
        guard let fields = inputDescriptor.constraints.fields else {
            // If no fields are defined, VC satisfies
            return true
        }

        let requiredFields = fields.filter { !($0.optional ?? false) }

        for field in requiredFields {
            
            // Takes field.path and queries the vc to see if there is a corresponding path.
            let vcJson = try JSONEncoder().encode(vc)
            guard let matchedPathValues = vcJson.query(values: field.path) else { return false }
            
            
            if matchedPathValues.isEmpty {
                // If no matching fields are found for a required field, the VC does not satisfy this Input Descriptor.
                return false
            }

            // If there is a filter, process it
            if let filter = field.filter {
                let fieldName = field.path[0]
                
                var filterProperties: [String: [String: String]] = [:]

                for (filterKey, filterValue) in filter {
                    guard let filterRule = filterValue.value as? String else {
                        return false
                    }
                    
                    filterProperties[fieldName, default: [:]][filterKey] = filterRule
                }
                
                let satisfiesSchemaMatches = try matchedPathValues.filter { value in
                    let result = try JSONSchema.validate([fieldName: value], schema: [
                      "properties": filterProperties
                    ])
                    return result.valid
                }
                
                if satisfiesSchemaMatches.isEmpty {
                    // If the field value does not satisfy the schema, the VC does not satisfy this Input Descriptor.
                    return false
                }
            }
        }

        // If the VC passes all the checks, it satisfies the criteria of the Input Descriptor.
        return true
    }
    
    private static func validateFilter() {
        
    }

}
