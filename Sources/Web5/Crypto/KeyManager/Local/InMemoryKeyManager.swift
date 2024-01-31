import Foundation

public class InMemoryKeyManager: LocalKeyManager {

    public init() {
        super.init(keyStore: InMemoryKeyStore())
    }
}

class InMemoryKeyStore: LocalKeyStore {

    /// Dictionary that stores keys in memory
    private var keyStore = [String: Jwk]()

    func getKey(keyAlias: String) throws -> Jwk? {
        keyStore[keyAlias]
    }

    func setKey(_ privateKey: Jwk, keyAlias: String) throws {
        keyStore[keyAlias] = privateKey
    }
}
