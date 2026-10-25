import Foundation

/// A single PEM block. Parsing is deliberately tolerant of mangled whitespace,
/// because 1Password text fields don't always preserve line breaks.
public struct PEMBlock: Sendable, Equatable {
    public var label: String
    public var headers: [String: String]
    public var der: Data

    public init(label: String, der: Data, headers: [String: String] = [:]) {
        self.label = label
        self.der = der
        self.headers = headers
    }

    public var pemString: String {
        let base64 = der.base64EncodedString()
        var lines = ["-----BEGIN \(label)-----"]
        var index = base64.startIndex
        while index < base64.endIndex {
            let end = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(String(base64[index..<end]))
            index = end
        }
        lines.append("-----END \(label)-----")
        return lines.joined(separator: "\n") + "\n"
    }

    public static func parseAll(_ text: String) throws -> [PEMBlock] {
        var blocks: [PEMBlock] = []
        var remaining = Substring(text)
        while let begin = remaining.range(of: "-----BEGIN ") {
            guard let labelEnd = remaining[begin.upperBound...].range(of: "-----") else {
                throw CAError.invalidPEM("Unterminated BEGIN line")
            }
            let label = String(remaining[begin.upperBound..<labelEnd.lowerBound])
            let footer = "-----END \(label)-----"
            guard let end = remaining[labelEnd.upperBound...].range(of: footer) else {
                throw CAError.invalidPEM("Missing \(footer)")
            }
            var body = String(remaining[labelEnd.upperBound..<end.lowerBound])

            // RFC 1421 style headers (e.g. legacy "Proc-Type: 4,ENCRYPTED").
            var headers: [String: String] = [:]
            if body.contains(":") {
                var bodyLines: [String] = []
                for line in body.split(whereSeparator: \.isNewline) {
                    if let colon = line.firstIndex(of: ":") {
                        headers[line[..<colon].trimmingCharacters(in: .whitespaces)] =
                            line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                    } else {
                        bodyLines.append(String(line))
                    }
                }
                body = bodyLines.joined()
            }

            let base64 = body.filter { !$0.isWhitespace }
            guard let der = Data(base64Encoded: base64), !der.isEmpty else {
                throw CAError.invalidPEM("\(label) block is not valid base64")
            }
            blocks.append(PEMBlock(label: label, der: der, headers: headers))
            remaining = remaining[end.upperBound...]
        }
        return blocks
    }
}
