import CertLabCore
import SwiftUI

struct CADetailView: View {
    @Environment(AppModel.self) private var model
    var ca: CARecord
    @State private var search = ""
    @State private var filter: ExpiryStatus?
    @State private var selection: IssuedRecord.ID?
    @State private var sortOrder = [KeyPathComparator(\IssuedRecord.issuedAt, order: .reverse)]

    private var allEntries: [IssuedRecord] { model.entries(for: ca) }

    private var entries: [IssuedRecord] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return allEntries
            .filter { filter == nil || ExpiryStatus(notAfter: $0.notAfter) == filter }
            .filter { record in
                query.isEmpty || (record.sans + [record.note, record.serialNumber]).contains { $0.lowercased().contains(query) }
            }
            .sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            if let info = model.info(ca) {
                CAHeader(ca: ca, info: info)
            }
            Divider()
            if allEntries.isEmpty {
                ContentUnavailableView {
                    Label("No Certificates Yet", systemImage: "doc.badge.plus")
                } description: {
                    Text("Certificates issued by \(ca.name) will appear here.")
                } actions: {
                    Button("Issue Certificate…") { model.sheet = .issue(ca, prefill: nil) }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                filterBar
                table
            }
            statusBar
        }
        .navigationTitle(ca.name)
        .searchable(text: $search, placement: .toolbar, prompt: "Search certificates")
        .toolbar {
            ToolbarItem {
                Button {
                    model.startSync(ca)
                } label: {
                    Label("Sync with 1Password", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(model.syncing.contains(ca.id))
                .help("Save unsynced certificates to 1Password and fetch ones issued on other Macs (⌘R)")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.sheet = .issue(ca, prefill: nil)
                } label: {
                    Label("Issue Certificate", systemImage: "plus")
                }
                .help("Issue a new certificate (⌘N)")
            }
        }
    }

    private var filterBar: some View {
        HStack {
            Picker("Show", selection: $filter) {
                Text("All \(allEntries.count)").tag(ExpiryStatus?.none)
                ForEach(ExpiryStatus.allCases, id: \.self) { status in
                    let count = allEntries.filter { ExpiryStatus(notAfter: $0.notAfter) == status }.count
                    Text("\(status.label) \(count)").tag(Optional(status))
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private var table: some View {
        Table(entries, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Names", value: \.commonName) { record in
                VStack(alignment: .leading, spacing: 1) {
                    Text(record.commonName).fontWeight(.medium)
                    if record.sans.count > 1 {
                        Text(record.sans.dropFirst().joined(separator: ", "))
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .padding(.vertical, 2)
            }
            .width(min: 160, ideal: 240)
            TableColumn("Note", value: \.note) { Text($0.note).foregroundStyle(.secondary) }
                .width(min: 60, ideal: 120)
            TableColumn("Issued", value: \.issuedAt) { Text($0.issuedAt.shortDate) }
                .width(min: 80, ideal: 95)
            TableColumn("Expires", value: \.notAfter) { record in
                VStack(alignment: .leading, spacing: 1) {
                    Text(record.notAfter.shortDate)
                    Text(record.notAfter.relative).font(.caption).foregroundStyle(.secondary)
                }
            }
            .width(min: 90, ideal: 110)
            TableColumn("Status") { record in
                HStack(spacing: 4) {
                    StatusBadge(status: ExpiryStatus(notAfter: record.notAfter))
                    if record.opItemID == nil {
                        Image(systemName: "exclamationmark.icloud")
                            .foregroundStyle(.orange)
                            .help("Not yet saved to 1Password. Use Sync.")
                    }
                }
            }
            .width(min: 110, ideal: 120)
        }
        .contextMenu(forSelectionType: IssuedRecord.ID.self) { ids in
            if let record = record(ids) {
                Button("Show Details") { model.sheet = .certificate(record) }
                Button("Copy Certificate") { Clipboard.copy(record.certificatePEM) }
                Divider()
                Button("Issue Again with Same Names…") { model.sheet = .issue(ca, prefill: record) }
            }
        } primaryAction: { ids in
            if let record = record(ids) { model.sheet = .certificate(record) }
        }
        .overlay {
            if entries.isEmpty {
                ContentUnavailableView.search(text: search)
            }
        }
    }

    private var statusBar: some View {
        let unsynced = model.unsyncedCount(for: ca)
        return VStack(spacing: 0) {
            Divider()
            HStack(spacing: 12) {
                Text(allEntries.count.counted("certificate"))
                if unsynced > 0 {
                    Label("\(unsynced) not in 1Password", systemImage: "exclamationmark.icloud")
                        .foregroundStyle(.orange)
                }
                Spacer()
                if model.syncing.contains(ca.id) {
                    ProgressView().controlSize(.mini)
                    Text("Syncing with 1Password…")
                } else if let status = model.syncStatus[ca.id] {
                    Label(status.message, systemImage: status.failed ? "exclamationmark.triangle" : "checkmark.icloud")
                        .foregroundStyle(status.failed ? .red : .secondary)
                        .lineLimit(1)
                        .help(status.message)
                    Text(status.date.formatted(date: .omitted, time: .shortened)).foregroundStyle(.tertiary)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 16)
            .padding(.vertical, 6)
        }
        .background(.bar)
    }

    private func record(_ ids: Set<IssuedRecord.ID>) -> IssuedRecord? {
        guard let id = ids.first else { return nil }
        return allEntries.first { $0.id == id }
    }
}

private struct CAHeader: View {
    @Environment(AppModel.self) private var model
    var ca: CARecord
    var info: CAInfo

    var body: some View {
        let status = ExpiryStatus(notAfter: info.notAfter)
        let constraints = info.permittedDNS + info.permittedIPRanges
        HStack(alignment: .top, spacing: 16) {
            IconTile(systemImage: "checkmark.seal.fill", tint: status == .valid ? .accentColor : status.color, size: 52)
            VStack(alignment: .leading, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(ca.name).font(.title2.weight(.semibold))
                    Text(info.subject).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                }
                FlowLayout(spacing: 6) {
                    Chip(text: status == .expired ? "Expired \(info.notAfter.shortDate)" : "Valid until \(info.notAfter.shortDate)",
                         systemImage: status.systemImage, tint: status.color)
                    Chip(text: info.keyDescription, systemImage: "key.fill")
                    Chip(text: constraints.isEmpty ? "Any name" : constraints.joined(separator: ", "),
                         systemImage: constraints.isEmpty ? "globe" : "scope")
                        .help(constraints.isEmpty
                              ? "No name constraints: this CA can sign certificates for any name."
                              : "Name constraints: certificates are limited to these domains and IP ranges.")
                    Chip(text: ca.item.vaultName, systemImage: "lock.rectangle.stack.fill")
                        .help("1Password vault holding this CA and its certificates")
                    Chip(text: ca.keyEncrypted ? "Passphrase + 1Password" : "1Password approval",
                         systemImage: ca.keyEncrypted ? "lock.fill" : "person.badge.key.fill")
                        .help("What’s needed to issue a certificate")
                }
            }
            Spacer(minLength: 12)
            Menu {
                Button("Copy CA Certificate", systemImage: "doc.on.doc") { Clipboard.copy(ca.certificatePEM) }
                Button("Export CA Certificate…", systemImage: "square.and.arrow.up") {
                    do { try FileExport.save(ca.certificatePEM, suggestedName: FileExport.baseName(for: info.commonName) + ".crt") }
                    catch { model.alert = error.localizedDescription }
                }
                Button("Copy SHA-256 Fingerprint", systemImage: "number") { Clipboard.copy(info.fingerprint) }
                Divider()
                Button("Remove from Cert Lab…", systemImage: "minus.circle", role: .destructive) { model.pendingRemoval = ca }
            } label: {
                Label("CA Certificate", systemImage: "ellipsis.circle")
            }
            .menuStyle(.button)
            .fixedSize()
            .help("SHA-256 \(info.fingerprint)")
        }
        .padding(20)
    }
}

struct CertificateDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var record: IssuedRecord

    var body: some View {
        let status = ExpiryStatus(notAfter: record.notAfter)
        VStack(spacing: 0) {
            SheetHeader(title: record.commonName,
                        subtitle: record.note.isEmpty ? status.label : "\(record.note) · \(status.label)",
                        systemImage: "doc.text.fill", tint: status == .valid ? .accentColor : status.color)
            Form {
                Section("Names") {
                    FlowLayout(spacing: 6) {
                        ForEach(record.dnsNames, id: \.self) { Chip(text: $0, systemImage: "globe") }
                        ForEach(record.ipAddresses, id: \.self) { Chip(text: $0, systemImage: "network") }
                    }
                }
                Section("Validity") {
                    LabeledContent("Expires", value: "\(record.notAfter.formatted(date: .long, time: .shortened)) (\(record.notAfter.relative))")
                    LabeledContent("Valid from", value: record.notBefore.formatted(date: .long, time: .shortened))
                    LabeledContent("Issued", value: record.issuedAt.formatted(date: .long, time: .shortened))
                }
                Section("Details") {
                    LabeledContent("Key", value: record.keyAlgorithm.rawValue)
                    LabeledContent("Usage", value: record.includeClientAuth ? "TLS server and client" : "TLS server")
                    LabeledContent("Serial") { Text(record.serialNumber).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("SHA-256 fingerprint")
                        Text(record.fingerprint)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    LabeledContent("1Password") {
                        if record.opItemID != nil {
                            Label("Saved", systemImage: "checkmark.icloud").foregroundStyle(.secondary)
                        } else {
                            Label("Not yet saved (use Sync)", systemImage: "exclamationmark.icloud").foregroundStyle(.orange)
                        }
                    }
                }
                Section {
                    PEMTextView(text: record.certificatePEM).frame(height: 130)
                } header: {
                    Text("Certificate")
                } footer: {
                    Text("The private key was shown once at issuance and can’t be recovered.").foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

            SheetFooter {
                CopyButton(title: "Copy") { record.certificatePEM }
                Button("Export…", systemImage: "square.and.arrow.up") {
                    do { try FileExport.save(record.certificatePEM, suggestedName: FileExport.baseName(for: record.commonName) + ".crt") }
                    catch { model.alert = error.localizedDescription }
                }
            } trailing: {
                if let ca = model.authorities.first(where: { $0.fingerprint == record.caFingerprint }) {
                    Button("Issue Again…") { model.sheet = .issue(ca, prefill: record) }
                }
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 600, height: 680)
    }
}
