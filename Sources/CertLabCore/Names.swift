import Foundation
import SwiftASN1
import X509

/// Helpers for hostnames, IP addresses and CIDR ranges.
public enum Names {
    /// Splits free-form input on commas, whitespace and newlines.
    public static func tokens(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0.isWhitespace })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Normalises one SAN entry: canonical IP text, or a lower-cased hostname.
    public static func normalize(_ raw: String) throws -> (value: String, isIP: Bool) {
        let entry = raw.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if let bytes = ipBytes(entry) { return (ipString(bytes), true) }
        let name = raw.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard isValidHostname(name) else { throw CAError.invalidRequest("“\(raw)” is not a valid hostname or IP address.") }
        return (name, false)
    }

    /// Splits SAN input into DNS names and IP addresses, validating each.
    public static func classify(_ entries: [String]) throws -> (dns: [String], ips: [String]) {
        var dns: [String] = []
        var ips: [String] = []
        for raw in entries {
            let (value, isIP) = try normalize(raw)
            if isIP {
                if !ips.contains(value) { ips.append(value) }
            } else if !dns.contains(value) {
                dns.append(value)
            }
        }
        return (dns, ips)
    }

    /// The common name for a certificate: the first entry, whether it's a hostname or an IP.
    public static func commonName(for entries: [String]) -> String? {
        entries.first.flatMap { try? normalize($0).value }
    }

    public static func isValidHostname(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 253 else { return false }
        var labels = name.split(separator: ".", omittingEmptySubsequences: false)
        if labels.first == "*" {
            labels.removeFirst()
            guard !labels.isEmpty else { return false }
        }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-_")
        return labels.allSatisfy { label in
            !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.unicodeScalars.allSatisfy(allowed.contains)
        }
    }

    public static func ipBytes(_ string: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, string, &v4) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, string, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        return nil
    }

    public static func ipString(_ bytes: some Collection<UInt8>) -> String {
        let bytes = Array(bytes)
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = bytes.count == 4 ? AF_INET : AF_INET6
        guard bytes.count == 4 || bytes.count == 16,
              inet_ntop(family, bytes, &buffer, socklen_t(buffer.count)) != nil else {
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        return String(cString: buffer)
    }

    /// "10.0.0.0/8" → address bytes followed by mask bytes, as used in name constraints.
    public static func cidrBytes(_ cidr: String) throws -> [UInt8] {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard (1...2).contains(parts.count), let address = ipBytes(parts[0]) else {
            throw CAError.invalidRequest("“\(cidr)” is not a valid IP range (e.g. 192.168.0.0/16).")
        }
        let bits = address.count * 8
        let prefix = parts.count == 2 ? Int(parts[1]) : bits
        guard let prefix, (0...bits).contains(prefix) else {
            throw CAError.invalidRequest("“\(cidr)” has an invalid prefix length.")
        }
        let mask = (0..<address.count).map { i -> UInt8 in
            let remaining = prefix - i * 8
            if remaining >= 8 { return 0xFF }
            if remaining <= 0 { return 0 }
            return UInt8(truncatingIfNeeded: 0xFF << (8 - remaining))
        }
        return zip(address, mask).map { $0 & $1 } + mask
    }

    public static func cidrString(_ bytes: some Collection<UInt8>) -> String {
        let bytes = Array(bytes)
        guard bytes.count == 8 || bytes.count == 32 else { return ipString(bytes) }
        let half = bytes.count / 2
        let prefix = bytes[half...].reduce(0) { $0 + $1.nonzeroBitCount }
        return "\(ipString(bytes[..<half]))/\(prefix)"
    }

    // MARK: Name constraints

    /// Whether every name `name` stands for falls inside the constraint. A wildcard
    /// "*.D" is treated as a name whose first label is "*", so it's within a subtree
    /// exactly when all of the names it matches are.
    static func dnsName(_ name: String, isWithin constraint: String) -> Bool {
        let constraint = constraint.lowercased()
        if constraint.isEmpty { return true }
        if constraint.hasPrefix(".") { return name.hasSuffix(constraint) }
        return name == constraint || name.hasSuffix("." + constraint)
    }

    /// Whether *any* name `name` stands for falls inside the constraint, which is what
    /// matters for excluded subtrees: "*.home.arpa" overlaps an exclusion of "admin.home.arpa".
    static func dnsName(_ name: String, overlaps constraint: String) -> Bool {
        if dnsName(name, isWithin: constraint) { return true }
        let constraint = constraint.lowercased()
        guard name.hasPrefix("*."), !constraint.hasPrefix(".") else { return false }
        let base = name.dropFirst(2)
        guard constraint.hasSuffix("." + base) else { return false }
        let label = constraint.dropLast(base.count + 1)
        return !label.isEmpty && !label.contains(".")
    }

    static func ip(_ address: [UInt8], isWithin range: some Collection<UInt8>) -> Bool {
        let range = Array(range)
        guard range.count == address.count * 2 else { return false }
        let mask = range[address.count...]
        return zip(zip(address, range), mask).allSatisfy { pair, m in pair.0 & m == pair.1 & m }
    }

    static func check(dns: [String], ips: [String], against constraints: NameConstraints) throws {
        let permittedDNS = Array(constraints.permittedDNSDomains)
        let excludedDNS = Array(constraints.excludedDNSDomains)
        let permittedIPs = constraints.permittedIPRanges.map { Array($0.bytes) }
        let excludedIPs = constraints.excludedIPRanges.map { Array($0.bytes) }

        for name in dns {
            if !permittedDNS.isEmpty, !permittedDNS.contains(where: { dnsName(name, isWithin: $0) }) {
                throw CAError.nameConstraintViolation("\(name) is outside \(permittedDNS.joined(separator: ", "))")
            }
            if let excluded = excludedDNS.first(where: { dnsName(name, overlaps: $0) }) {
                throw CAError.nameConstraintViolation("\(name) is excluded by \(excluded)")
            }
        }
        for ip in ips {
            guard let address = ipBytes(ip) else { continue }
            let sameFamily = permittedIPs.filter { $0.count == address.count * 2 }
            if !permittedIPs.isEmpty, !sameFamily.contains(where: { Names.ip(address, isWithin: $0) }) {
                throw CAError.nameConstraintViolation("\(ip) is outside \(permittedIPs.map(cidrString).joined(separator: ", "))")
            }
            if let excluded = excludedIPs.first(where: { Names.ip(address, isWithin: $0) }) {
                throw CAError.nameConstraintViolation("\(ip) is excluded by \(cidrString(excluded))")
            }
        }
    }
}
