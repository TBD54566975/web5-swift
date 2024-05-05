import Foundation

public struct DIDUtility {

    /**
    * Checks if a given object is a DID Verification Method.
    *
    * A {@link VerificationMethod} in the context of DID resources must include the properties `id`,
    * `type`, and `controller`.
    *
    * @param obj - The object to be checked.
    * @returns `true` if `obj` is a `VerificationMethod`; otherwise, `false`.
    */
    static func isDidVerificationMethod(obj: Any) -> Bool {

        let mirror = Mirror(reflecting: obj)
        var foundId = false
        var foundType = false
        var foundController = false
        
        for case let (label?, value) in mirror.children {
            if label == "id" && value is String {
                foundId = true
            } else if label == "type" && value is String {
                foundType = true
            } else if label == "controller" && value is String {
                foundController = true
            }
        }

        return (foundId && foundType && foundController)

    }
}
