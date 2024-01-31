import Foundation

// Github currently uses macOS 12 for its CI, which does not have the new `RegexBuilder` APIs.
// Therefore, we need to use NSRegularExpression directly, which is pretty unfriendly.
// Structs & funcitons in this file are strictly here to make working with it easier.

enum Regex {

    static func matches(
        for pattern: String,
        in text: String
    ) throws -> [String]? {
        let regex = try NSRegularExpression(pattern: pattern, options: [])
        guard let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else {
            return nil
        }

        var matches = [String]()
        for i in 0..<match.numberOfRanges {
            let matchedString: String
            if let range = Range(match.range(at: i), in: text) {
                matchedString = String(text[range])
            } else {
                matchedString = ""
            }
            matches.append(matchedString)
        }

        return matches
    }
}
