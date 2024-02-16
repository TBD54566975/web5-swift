import DNS
import Foundation

extension DNS.TextRecord {
    
    /// Create a new text record, with values instead of attributes
    init(
        name: String,
        ttl: UInt32,
        values: [String]
    ) {
        var record = TextRecord(
            name: name,
            unique: false,
            internetClass: .internet,
            ttl: ttl,
            attributes: [:]
        )
        record.values = values
        self = record
    }


}
