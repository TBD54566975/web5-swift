import AnyCodable
import Foundation

public struct PresentationDefinitionV2: Codable {
    public let inputDescriptors: [InputDescriptorV2]
}

public struct InputDescriptorV2: Codable, Hashable {
    public let fields: [FieldV2]
}

public struct FieldV2: Codable, Hashable {
    public let id: String?
    public let path: [String]
    public let purpose: String?
    public let filterJSON: AnyCodable?
    public let predicate: Optionality?
    public let name: String?
    public let optional: Bool?

    public init(
        id: String? = nil,
        path: [String],
        purpose: String? = nil,
        filterJSON: AnyCodable? = nil,
        predicate: Optionality? = nil,
        name: String? = nil,
        optional: Bool? = nil
    ) {
        self.id = id
        self.path = path
        self.purpose = purpose
        self.filterJSON = filterJSON
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

    public func selectCredentials(
        vcJWTs: [String],
        presentationDefinition: PresentationDefinitionV2
    ) throws -> [String] {
        
        fatalError("Not implemented")
    }

    private func mapInputDescriptorsToVCs(
        vcJWTList: [String],
        presentationDefinition: PresentationDefinitionV2
    ) -> [InputDescriptorV2: [String]] {
        let map = vcJWTList.map { vcJWT in
            
        }





        fatalError("Not implemented")
    }

    /**
     private fun mapInputDescriptorsToVCs(
       vcJwtList: Iterable<String>,
       presentationDefinition: PresentationDefinitionV2
     ): Map<InputDescriptorV2, List<String>> {
       val vcJwtListWithNodes = vcJwtList.zip(vcJwtList.map { vcJwt ->
         val vc = JWTParser.parse(vcJwt) as SignedJWT

         JsonPath.parse(vc.payload.toString())
           ?: throw JsonPathParseException()
       })
       return presentationDefinition.inputDescriptors.associateWith { inputDescriptor ->
         vcJwtListWithNodes.filter { (_, node) ->
           vcSatisfiesInputDescriptor(node, inputDescriptor)
         }.map { (vcJwt, _) -> vcJwt }
       }.filterValues { it.isNotEmpty() }
     }
     */

}
