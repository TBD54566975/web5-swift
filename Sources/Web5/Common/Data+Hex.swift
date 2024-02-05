import Foundation

extension Data {
    public static func fromHexString(_ hexString: String) -> Self? {
        var data = Data()
        var hex = hexString

        // Add leading 0 if the string is not even in length
        if hex.count % 2 != 0 {
            hex = "0" + hex
        }

        while !hex.isEmpty {
            // Get the first two characters
            let c = String(hex.prefix(2))
            hex = String(hex.dropFirst(2))

            // Convert the hex string to a byte
            if let byte = UInt8(c, radix: 16) {
                data.append(byte)
            } else {
                // Return nil if the string is not a valid hexadecimal
                return nil
            }
        }

        return data
    }

    public func toHexString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
