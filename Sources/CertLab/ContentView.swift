import CertLabCore
import SwiftUI

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                Section("Certificate Authorities") {
                    ForEach(model.authorities) { ca in
                        SidebarRow(ca: ca)
                            .tag(ca.id)
                            .contextMenu {
                                Button("Issue Certificate…") { model.sheet = .issue(ca, prefill: nil) }
                                Button("Sync with 1Password") { model.startSync(ca) }
                                Divider()
                                Button("Copy CA Certificate") { Clipboard.copy(ca.certificatePEM) }
                                Divider()
                                Button("Remove from Cert Lab…", role: .destructive) { model.pendingRemoval = ca }
                            }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 240)
            .toolbar {
                ToolbarItem {
                    AddCAMenu()
                }
            }
        } detail: {
            if let ca = model.selectedCA {
                CADetailView(ca: ca)
                    .id(ca.id)
            } else {
                WelcomeView()
            }
        }
        .sheet(item: $model.sheet) { sheet in
            switch sheet {
            case .newCA: NewCAView()
            case .importCA: ImportCAView()
            case .linkCA: LinkCAView()
            case .issue(let ca, let prefill): IssueView(ca: ca, prefill: prefill)
            case .certificate(let record): CertificateDetailView(record: record)
            }
        }
        .alert("Cert Lab", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) {
            Button("OK") { model.alert = nil }
        } message: {
            Text(model.alert ?? "")
        }
        .confirmationDialog("Remove “\(model.pendingRemoval?.name ?? "")” from Cert Lab?",
                            isPresented: Binding(get: { model.pendingRemoval != nil },
                                                 set: { if !$0 { model.pendingRemoval = nil } })) {
            Button("Remove", role: .destructive) {
                if let ca = model.pendingRemoval { model.remove(ca) }
            }
        } message: {
            Text("The CA and its certificates stay in 1Password. You can link it again at any time.")
        }
    }
}

private struct SidebarRow: View {
    @Environment(AppModel.self) private var model
    var ca: CARecord

    var body: some View {
        let status = model.info(ca).map { ExpiryStatus(notAfter: $0.notAfter) } ?? .valid
        HStack(spacing: 4) {
            // A plain sidebar Label: macOS tints the icon with the accent colour and
            // switches it to white when the row is selected.
            Label {
                VStack(alignment: .leading, spacing: 1) {
                    Text(ca.name).lineLimit(1)
                    Text(model.entries(for: ca).count.counted("certificate"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "checkmark.seal.fill")
            }
            Spacer(minLength: 0)
            if status != .valid {
                Image(systemName: status.systemImage)
                    .foregroundStyle(status.color)
                    .help("CA certificate: \(status.label.lowercased())")
            }
            if model.syncing.contains(ca.id) {
                ProgressView().controlSize(.mini)
            } else if model.unsyncedCount(for: ca) > 0 {
                Image(systemName: "exclamationmark.icloud")
                    .foregroundStyle(.orange)
                    .help("Some certificates aren’t in 1Password yet")
            }
        }
        .padding(.vertical, 2)
    }
}

struct AddCAMenu: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Menu {
            Button("New Certificate Authority…", systemImage: "plus.circle") { model.sheet = .newCA }
            Button("Import Existing CA…", systemImage: "square.and.arrow.down") { model.sheet = .importCA }
            Button("Link CA from 1Password…", systemImage: "link") { model.sheet = .linkCA }
        } label: {
            Label("Add CA", systemImage: "plus")
        }
        .help("Add a certificate authority")
    }
}

private struct WelcomeView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 24) {
            IconTile(systemImage: "checkmark.seal.fill", size: 72)
            VStack(spacing: 6) {
                Text("Welcome to Cert Lab").font(.title.weight(.semibold))
                Text("Certificates for your home lab, signed by a CA that lives in 1Password.")
                    .foregroundStyle(.secondary)
            }
            VStack(spacing: 10) {
                WelcomeAction(title: "Create a new CA", detail: "Generate a CA and store it in its own vault",
                              systemImage: "plus.circle.fill") { model.sheet = .newCA }
                WelcomeAction(title: "Import an existing CA", detail: "Bring a certificate and key from elsewhere",
                              systemImage: "square.and.arrow.down.fill") { model.sheet = .importCA }
                WelcomeAction(title: "Link a CA from 1Password", detail: "Use a CA set up on another Mac",
                              systemImage: "link.circle.fill") { model.sheet = .linkCA }
            }
            .frame(width: 380)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct WelcomeAction: View {
    var title: String
    var detail: String
    var systemImage: String
    var action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: systemImage)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 28)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.headline)
                    Text(detail).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .padding(12)
            .contentShape(Rectangle())
            .background(.quaternary.opacity(hovering ? 0.8 : 0.4), in: RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
