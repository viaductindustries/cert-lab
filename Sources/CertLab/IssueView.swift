import CertLabCore
import SwiftUI

struct IssueView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var ca: CARecord

    @State private var namesText: String
    @State private var note: String
    @State private var expiry: Date
    @State private var keyAlgorithm: KeyAlgorithm
    @State private var clientAuth: Bool
    @State private var passphrase = ""
    @State private var working = false
    @State private var error: String?
    @State private var result: AppModel.IssueResult?

    private static let presets = [(30, "30 days"), (90, "90 days"), (365, "1 year"), (825, "825 days")]

    init(ca: CARecord, prefill: IssuedRecord?) {
        self.ca = ca
        _namesText = State(initialValue: prefill?.sans.joined(separator: "\n") ?? "")
        _note = State(initialValue: prefill?.note ?? "")
        _keyAlgorithm = State(initialValue: prefill?.keyAlgorithm ?? .p256)
        _clientAuth = State(initialValue: prefill?.includeClientAuth ?? false)
        let days = prefill.map { Int(($0.notAfter.timeIntervalSince($0.notBefore) / 86400).rounded()) } ?? 365
        _expiry = State(initialValue: Self.date(inDays: days))
    }

    private static func date(inDays days: Int) -> Date {
        Calendar.current.date(byAdding: .day, value: days, to: Date()) ?? Date()
    }

    /// Read live from the model: issuing can discover that the key's protection changed.
    private var needsPassphrase: Bool { model.authorities.first { $0.id == ca.id }?.keyEncrypted ?? ca.keyEncrypted }

    private var parsed: Result<(dns: [String], ips: [String]), Error> {
        Result { try CertificateAuthority.validate(names: Names.tokens(namesText), certificatePEM: ca.certificatePEM) }
    }

    private var days: Int {
        Calendar.current.dateComponents([.day], from: Calendar.current.startOfDay(for: Date()),
                                        to: Calendar.current.startOfDay(for: expiry)).day ?? 0
    }

    private var canIssue: Bool {
        !working && (!needsPassphrase || !passphrase.isEmpty) && (try? parsed.get()) != nil && expiryError == nil
    }

    var body: some View {
        if let result {
            IssuedResultView(bundle: result.bundle, warning: result.warning) { dismiss() }
        } else {
            form
        }
    }

    private var form: some View {
        VStack(spacing: 0) {
            SheetHeader(title: "Issue Certificate", subtitle: "Signed by \(ca.name)", systemImage: "doc.badge.plus")
            Form {
                Section {
                    CodeEditor(text: $namesText, placeholder: "nas.home.arpa\n*.nas.home.arpa\n192.168.1.10")
                        .frame(height: 84)
                    namesPreview
                } header: {
                    Text("Hostnames & IP addresses")
                } footer: {
                    Text("One per line or separated by commas. The first becomes the common name.")
                        .foregroundStyle(.secondary)
                }

                Section("Validity") {
                    DatePicker("Expires", selection: $expiry, in: Date()..., displayedComponents: .date)
                    LabeledContent("Lifetime") {
                        HStack(spacing: 6) {
                            ForEach(Self.presets, id: \.0) { value, label in
                                if days == value {
                                    Button(label) {}.buttonStyle(.borderedProminent).controlSize(.small)
                                } else {
                                    Button(label) { expiry = Self.date(inDays: value) }.buttonStyle(.bordered).controlSize(.small)
                                }
                            }
                        }
                    }
                    if let warning = expiryWarning {
                        Label(warning, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(expiryError != nil ? .red : .orange)
                            .font(.callout)
                    }
                }

                Section("Options") {
                    Picker("Key type", selection: $keyAlgorithm) {
                        ForEach([KeyAlgorithm.p256, .p384, .rsa2048, .rsa4096]) { Text($0.rawValue).tag($0) }
                    }
                    Toggle(isOn: $clientAuth) {
                        Text("Allow client authentication")
                        Text("For mutual TLS (mTLS), in addition to serving TLS.")
                    }
                    TextField("Note", text: $note, prompt: Text("Optional, e.g. Synology DSM"))
                }

                if needsPassphrase {
                    Section("Passphrase") {
                        SecureField("CA passphrase", text: $passphrase)
                            .onSubmit(issue)
                    }
                }
            }
            .formStyle(.grouped)

            SheetFooter {
                if let error {
                    ErrorText(message: error)
                } else {
                    Label("1Password will ask you to approve", systemImage: "lock.shield")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } trailing: {
                if working { ProgressView().controlSize(.small) }
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Issue Certificate", action: issue)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canIssue)
            }
        }
        .frame(width: 560, height: needsPassphrase ? 720 : 650)
    }

    @ViewBuilder private var namesPreview: some View {
        switch parsed {
        case .success(let names):
            FlowLayout(spacing: 6) {
                ForEach(Array(names.dns.enumerated()), id: \.element) { index, name in
                    Chip(text: name, systemImage: "globe", tint: index == 0 ? .accentColor : .secondary)
                }
                ForEach(Array(names.ips.enumerated()), id: \.element) { index, ip in
                    Chip(text: ip, systemImage: "network", tint: names.dns.isEmpty && index == 0 ? .accentColor : .secondary)
                }
            }
        case .failure(let error):
            if namesText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Text("Nothing entered yet").font(.callout).foregroundStyle(.tertiary)
            } else {
                ErrorText(message: error.localizedDescription)
            }
        }
    }

    private var expiryError: String? {
        guard let info = model.info(ca) else { return nil }
        return expiry > info.notAfter ? "That’s after the CA itself expires (\(info.notAfter.shortDate))." : nil
    }

    private var expiryWarning: String? {
        if let expiryError { return expiryError }
        if days > CertificateAuthority.appleMaximumValidityDays {
            return "Apple devices reject TLS certificates valid for more than 825 days (this is \(days))."
        }
        return nil
    }

    private func issue() {
        guard canIssue else { return }
        working = true
        error = nil
        let request = IssueRequest(names: Names.tokens(namesText), notAfter: expiry, keyAlgorithm: keyAlgorithm,
                                   includeClientAuth: clientAuth, note: note)
        Task {
            defer { working = false }
            do {
                result = try await model.issue(request, ca: ca, passphrase: needsPassphrase ? passphrase : nil)
                passphrase = ""
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

/// Shows the freshly issued key and certificates. Once dismissed the key is gone.
struct IssuedResultView: View {
    @Environment(AppModel.self) private var model
    var bundle: IssuedBundle
    var warning: String?
    var onDone: () -> Void

    enum Part: String, CaseIterable, Identifiable {
        case key = "Private Key", certificate = "Certificate", fullChain = "Full Chain", ca = "CA Certificate"
        var id: String { rawValue }
    }

    @State private var part = Part.key
    @State private var keySaved = false
    @State private var exportedTo: URL?
    @State private var confirmDiscard = false

    private var baseName: String { FileExport.baseName(for: bundle.record.commonName) }

    private func text(_ part: Part) -> String {
        switch part {
        case .key: bundle.privateKeyPEM
        case .certificate: bundle.certificatePEM
        case .fullChain: bundle.fullChainPEM
        case .ca: bundle.chainPEM
        }
    }

    private func caption(_ part: Part) -> String {
        switch part {
        case .key: "PKCS#8 private key. Keep it secret; it exists only here."
        case .certificate: "The server certificate on its own."
        case .fullChain: "Server certificate followed by the CA. Most servers want this one."
        case .ca: "Install this on devices that should trust your certificates."
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(title: "Certificate Issued",
                        subtitle: "\(bundle.record.sans.joined(separator: ", ")) · valid until \(bundle.record.notAfter.shortDate)",
                        systemImage: "checkmark.seal.fill", tint: .green)

            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: keySaved ? "checkmark.circle.fill" : "key.fill")
                        .foregroundStyle(keySaved ? .green : .orange)
                        .font(.title3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(keySaved ? "Private key saved" : "Save the private key now")
                            .font(.headline)
                        Text("It’s shown only once and isn’t stored anywhere, including 1Password.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background((keySaved ? Color.green : Color.orange).opacity(0.1), in: RoundedRectangle(cornerRadius: 10))

                if let warning {
                    Label(warning, systemImage: "exclamationmark.icloud")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Picker("", selection: $part) {
                    ForEach(Part.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                Text(caption(part)).font(.callout).foregroundStyle(.secondary)

                PEMTextView(text: text(part))

                if let exportedTo {
                    Label("Exported to \(exportedTo.path(percentEncoded: false))", systemImage: "folder")
                        .font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
            .padding(20)

            SheetFooter {
                CopyButton(title: "Copy \(part.rawValue)", secret: part == .key) { text(part) } onCopy: {
                    if part == .key { keySaved = true }
                }
                Button("Export Files…", systemImage: "square.and.arrow.up", action: export)
                    .help("Saves \(baseName).key, \(baseName).crt, \(baseName).fullchain.crt and ca.crt")
            } trailing: {
                Button("Done") {
                    if keySaved { onDone() } else { confirmDiscard = true }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 640, height: 640)
        .interactiveDismissDisabled()
        .confirmationDialog("Discard the private key?", isPresented: $confirmDiscard) {
            Button("Discard Key", role: .destructive, action: onDone)
        } message: {
            Text("You haven’t copied or exported the private key. It can’t be recovered; you’d need to issue a new certificate.")
        }
    }

    private func export() {
        do {
            let files: [FileExport.File] = [
                .init(name: "\(baseName).key", contents: bundle.privateKeyPEM, isSecret: true),
                .init(name: "\(baseName).crt", contents: bundle.certificatePEM),
                .init(name: "\(baseName).fullchain.crt", contents: bundle.fullChainPEM),
                .init(name: "ca.crt", contents: bundle.chainPEM),
            ]
            if let folder = try FileExport.exportToFolder(files, message: "Choose a folder for the key and certificates") {
                keySaved = true
                exportedTo = folder
            }
        } catch {
            model.alert = "Export failed: \(error.localizedDescription)"
        }
    }
}
