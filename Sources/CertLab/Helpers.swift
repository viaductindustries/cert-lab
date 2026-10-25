import AppKit
import CertLabCore
import SwiftUI
import UniformTypeIdentifiers

enum Clipboard {
    /// Copies text. Secrets are marked concealed (so clipboard managers skip them)
    /// and cleared after 90 seconds if still on the clipboard.
    @MainActor static func copy(_ string: String, secret: Bool = false) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        if secret {
            pasteboard.declareTypes([.string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")], owner: nil)
        }
        pasteboard.setString(string, forType: .string)
        guard secret else { return }
        let changeCount = pasteboard.changeCount
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(90))
            if NSPasteboard.general.changeCount == changeCount { NSPasteboard.general.clearContents() }
        }
    }
}

enum FileExport {
    struct File {
        var name: String
        var contents: String
        var isSecret = false
    }

    /// Asks for a folder and writes the files into it. Returns the folder, or nil if cancelled.
    @MainActor @discardableResult
    static func exportToFolder(_ files: [File], message: String) throws -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Export"
        panel.message = message
        guard panel.runModal() == .OK, let folder = panel.url else { return nil }

        let urls = files.map { folder.appendingPathComponent($0.name) }
        let existing = urls.filter { FileManager.default.fileExists(atPath: $0.path) }
        if !existing.isEmpty {
            let alert = NSAlert()
            alert.messageText = "Replace existing files?"
            alert.informativeText = existing.map(\.lastPathComponent).joined(separator: "\n")
            alert.addButton(withTitle: "Replace")
            alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        }
        for (file, url) in zip(files, urls) {
            try Data(file.contents.utf8).write(to: url, options: .atomic)
            if file.isSecret {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            }
        }
        NSWorkspace.shared.activateFileViewerSelecting(urls)
        return folder
    }

    @MainActor static func save(_ contents: String, suggestedName: String) throws {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try Data(contents.utf8).write(to: url, options: .atomic)
    }

    @MainActor static func chooseTextFile() -> String? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return try? String(contentsOf: url, encoding: .utf8)
    }

    /// "*.nas.home.arpa" → "wildcard.nas.home.arpa"
    static func baseName(for commonName: String) -> String {
        let name = commonName.replacingOccurrences(of: "*", with: "wildcard")
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        return String(name.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
    }
}

/// Read-only, selectable monospaced text for PEM blobs.
struct PEMTextView: View {
    var text: String

    var body: some View {
        ScrollView {
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
        }
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
    }
}

/// Multi-line editable text with a monospaced font.
struct CodeEditor: View {
    @Binding var text: String
    var placeholder: String

    var body: some View {
        TextEditor(text: $text)
            .font(.system(.caption, design: .monospaced))
            .scrollContentBackground(.hidden)
            .padding(4)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
            .overlay(alignment: .topLeading) {
                if text.isEmpty {
                    Text(placeholder)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 4)
                        .allowsHitTesting(false)
                }
            }
    }
}

enum ExpiryStatus: CaseIterable {
    case valid, expiringSoon, expired

    init(notAfter: Date, now: Date = Date()) {
        if notAfter <= now { self = .expired }
        else if notAfter.timeIntervalSince(now) < 30 * 86400 { self = .expiringSoon }
        else { self = .valid }
    }

    var label: String {
        switch self {
        case .valid: "Valid"
        case .expiringSoon: "Expiring soon"
        case .expired: "Expired"
        }
    }

    var color: Color {
        switch self {
        case .valid: .green
        case .expiringSoon: .orange
        case .expired: .red
        }
    }

    var systemImage: String {
        switch self {
        case .valid: "checkmark.circle.fill"
        case .expiringSoon: "clock.badge.exclamationmark.fill"
        case .expired: "xmark.circle.fill"
        }
    }
}

struct StatusBadge: View {
    var status: ExpiryStatus

    var body: some View {
        Text(status.label)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(status.color.opacity(0.15), in: Capsule())
            .foregroundStyle(status.color)
    }
}

/// Loads vaults from 1Password and lets the user pick one.
struct VaultPicker: View {
    @Environment(AppModel.self) private var model
    @Binding var vaultID: String
    @State private var vaults: [OPVault] = []
    @State private var error: String?
    @State private var loading = false

    var body: some View {
        LabeledContent("1Password vault") {
            HStack {
                if loading {
                    ProgressView().controlSize(.small)
                    Text("Waiting for 1Password…").foregroundStyle(.secondary)
                } else if vaults.isEmpty {
                    Button("Connect to 1Password") { Task { await load() } }
                } else {
                    Picker("", selection: $vaultID) {
                        ForEach(vaults) { Text($0.name).tag($0.id) }
                    }
                    .labelsHidden()
                }
            }
        }
        if let error {
            Text(error).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func load() async {
        loading = true
        defer { loading = false }
        do {
            vaults = try await model.listVaults()
            error = nil
            if !vaults.contains(where: { $0.id == vaultID }) {
                vaultID = vaults.first { $0.id == model.lastVaultID }?.id ?? vaults.first?.id ?? ""
            }
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct ErrorText: View {
    var message: String?

    var body: some View {
        if let message {
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

extension Date {
    var shortDate: String { formatted(date: .abbreviated, time: .omitted) }

    /// "in 11 months", "3 days ago"
    var relative: String { formatted(.relative(presentation: .named, unitsStyle: .wide)) }
}

extension Int {
    func counted(_ singular: String, _ plural: String? = nil) -> String {
        "\(self) \(self == 1 ? singular : plural ?? singular + "s")"
    }
}

// MARK: - Layout pieces

/// Title block at the top of every sheet.
struct SheetHeader: View {
    var title: String
    var subtitle: String?
    var systemImage: String
    var tint: Color = .accentColor

    var body: some View {
        HStack(spacing: 14) {
            IconTile(systemImage: systemImage, tint: tint, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.weight(.semibold))
                if let subtitle {
                    Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.top, 18)
        .padding(.bottom, 4)
    }
}

/// A rounded, tinted square with a white symbol, like a small app icon.
struct IconTile: View {
    var systemImage: String
    var tint: Color = .accentColor
    var size: CGFloat = 40

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
            .fill(tint.gradient)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: systemImage)
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .shadow(color: .black.opacity(0.15), radius: 1, y: 1)
    }
}

/// Bottom button row for sheets.
struct SheetFooter<Leading: View, Trailing: View>: View {
    @ViewBuilder var leading: Leading
    @ViewBuilder var trailing: Trailing

    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                leading
                Spacer(minLength: 12)
                trailing
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
    }
}

/// A small capsule label used for CA facts and parsed names.
struct Chip: View {
    var text: String
    var systemImage: String?
    var tint: Color = .secondary
    var monospaced = false

    var body: some View {
        HStack(spacing: 4) {
            if let systemImage {
                Image(systemName: systemImage).imageScale(.small).foregroundStyle(tint)
            }
            Text(text)
                .font(monospaced ? .system(.caption, design: .monospaced) : .caption)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(.quaternary.opacity(0.6), in: Capsule())
    }
}

/// Lays children out left to right, wrapping onto new lines.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(subviews, width: proposal.width ?? .infinity)
        let width = rows.map { $0.width }.max() ?? 0
        let height = rows.reduce(0) { $0 + $1.height } + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: proposal.width ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(subviews, width: bounds.width) {
            var x = bounds.minX
            for index in row.indices {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(at: CGPoint(x: x, y: y + (row.height - size.height) / 2), proposal: .unspecified)
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var indices: [Int] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(_ subviews: Subviews, width: CGFloat) -> [Row] {
        var rows: [Row] = []
        var row = Row()
        for index in subviews.indices {
            let size = subviews[index].sizeThatFits(.unspecified)
            let needed = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            if needed > width, !row.indices.isEmpty {
                rows.append(row)
                row = Row()
            }
            row.width = row.indices.isEmpty ? size.width : row.width + spacing + size.width
            row.height = max(row.height, size.height)
            row.indices.append(index)
        }
        if !row.indices.isEmpty { rows.append(row) }
        return rows
    }
}

/// A button that briefly shows "Copied" after copying.
struct CopyButton: View {
    var title: String
    var secret = false
    var text: () -> String
    var onCopy: () -> Void = {}
    @State private var copied = false

    var body: some View {
        Button {
            Clipboard.copy(text(), secret: secret)
            onCopy()
            copied = true
            Task {
                try? await Task.sleep(for: .seconds(1.5))
                copied = false
            }
        } label: {
            Label(copied ? "Copied" : title, systemImage: copied ? "checkmark" : "doc.on.doc")
                .contentTransition(.symbolEffect(.replace))
        }
    }
}
