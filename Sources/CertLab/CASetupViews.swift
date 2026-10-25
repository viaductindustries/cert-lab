import CertLabCore
import SwiftUI

struct NewCAView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var commonName = ""
    @State private var organization = ""
    @State private var algorithm = KeyAlgorithm.p384
    @State private var years = 10
    @State private var permittedDNS = ""
    @State private var permittedIPs = ""
    @State private var storage = StorageOptions()
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(title: "New Certificate Authority", subtitle: "Generated on this Mac and stored in 1Password",
                        systemImage: "checkmark.seal.fill")
            Form {
                Section("Certificate Authority") {
                    TextField("Name", text: $commonName, prompt: Text("Home Lab Root CA"))
                    TextField("Organization", text: $organization, prompt: Text("Optional"))
                    Picker("Key type", selection: $algorithm) {
                        ForEach([KeyAlgorithm.p256, .p384, .rsa3072, .rsa4096]) { Text($0.rawValue).tag($0) }
                    }
                    Stepper("Valid for \(years.counted("year"))", value: $years, in: 1...30)
                }

                Section {
                    TextField("Domains", text: $permittedDNS, prompt: Text("home.arpa, internal"))
                    TextField("IP ranges", text: $permittedIPs, prompt: Text("192.168.0.0/16, 10.0.0.0/8"))
                } header: {
                    Text("Name constraints")
                } footer: {
                    Text("Recommended. The CA can then only sign these domains (and their subdomains) and IP ranges, so trusting it on your devices can’t be abused for other websites.")
                        .foregroundStyle(.secondary)
                }

                StorageSections(options: $storage, caName: commonName)
            }
            .formStyle(.grouped)

            SheetButtons(error: error, working: working, action: "Create CA",
                         disabled: commonName.trimmingCharacters(in: .whitespaces).isEmpty || !storage.isComplete(caName: commonName),
                         onCancel: { dismiss() }, onAction: create)
        }
        .frame(width: 560, height: 720)
    }

    private func create() {
        let passphrase: String?
        do { passphrase = try storage.validatedPassphrase() } catch {
            self.error = error.localizedDescription
            return
        }
        let params = CertificateAuthority.NewCAParameters(
            commonName: commonName, organization: organization, algorithm: algorithm, validityYears: years,
            permittedDNS: Names.tokens(permittedDNS), permittedIPRanges: Names.tokens(permittedIPs))
        let destination = storage.destination(caName: commonName)
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                try await model.createCA(params, passphrase: passphrase, destination: destination)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

struct ImportCAView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var certificatePEM = ""
    @State private var keyPEM = ""
    @State private var currentPassphrase = ""
    @State private var storage = StorageOptions()
    @State private var working = false
    @State private var error: String?

    private var info: Result<CAInfo, Error>? {
        certificatePEM.isEmpty ? nil : Result { try CertificateAuthority.info(certificatePEM: certificatePEM) }
    }

    private var commonName: String { (try? info?.get())?.commonName ?? "" }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(title: "Import Certificate Authority", subtitle: "Bring an existing CA certificate and key into 1Password",
                        systemImage: "square.and.arrow.down.fill")
            Form {
                Section {
                    CodeEditor(text: $certificatePEM, placeholder: "-----BEGIN CERTIFICATE-----")
                        .frame(height: 90)
                    HStack {
                        switch info {
                        case .success(let info):
                            Label("\(info.commonName) · expires \(info.notAfter.shortDate)"
                                  + (info.chainLength > 1 ? " · +\(info.chainLength - 1) in chain" : ""),
                                  systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.secondary)
                        case .failure(let error): ErrorText(message: error.localizedDescription)
                        case nil: EmptyView()
                        }
                        Spacer()
                        Button("Choose File…") { if let text = FileExport.chooseTextFile() { certificatePEM = text } }
                    }
                } header: {
                    Text("CA certificate (PEM)")
                } footer: {
                    Text("For an intermediate CA, include its parent certificates after it; they’re added to every issued chain.")
                        .foregroundStyle(.secondary)
                }

                Section("CA private key (PEM)") {
                    CodeEditor(text: $keyPEM, placeholder: "-----BEGIN PRIVATE KEY-----")
                        .frame(height: 90)
                    HStack {
                        if !keyPEM.isEmpty, SigningKey.isEncrypted(pem: keyPEM) {
                            Label("Encrypted key", systemImage: "lock.fill").foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Choose File…") { if let text = FileExport.chooseTextFile() { keyPEM = text } }
                    }
                    if SigningKey.isEncrypted(pem: keyPEM) {
                        SecureField("Current key passphrase", text: $currentPassphrase)
                    }
                }

                StorageSections(options: $storage, caName: commonName)
            }
            .formStyle(.grouped)

            SheetButtons(error: error, working: working, action: "Import CA",
                         disabled: certificatePEM.isEmpty || keyPEM.isEmpty || !storage.isComplete(caName: commonName),
                         onCancel: { dismiss() }, onAction: importCA)
        }
        .frame(width: 580, height: 800)
    }

    private func importCA() {
        let passphrase: String?
        do { passphrase = try storage.validatedPassphrase() } catch {
            self.error = error.localizedDescription
            return
        }
        let name = commonName.isEmpty ? "Imported CA" : commonName
        let destination = storage.destination(caName: name)
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                try await model.importCA(certificatePEM: certificatePEM, keyPEM: keyPEM,
                                         currentPassphrase: currentPassphrase.isEmpty ? nil : currentPassphrase,
                                         newPassphrase: passphrase, title: "CA: \(name)", destination: destination)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

struct LinkCAView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var items: [OPItemRef]?
    @State private var error: String?
    @State private var linking: OPItemRef?

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(title: "Link CA from 1Password", subtitle: "Use a CA created by Cert Lab on another Mac",
                        systemImage: "link")
            Group {
                if let items {
                    if items.isEmpty {
                        ContentUnavailableView("No CAs Found", systemImage: "tray",
                                               description: Text("Cert Lab didn’t find any CAs in your 1Password vaults."))
                    } else {
                        List(items, id: \.itemID) { item in
                            row(item)
                        }
                        .listStyle(.inset)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                        .padding(.horizontal, 20)
                    }
                } else {
                    VStack(spacing: 10) {
                        ProgressView()
                        Text("Waiting for 1Password…").foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(maxHeight: .infinity)
            .padding(.vertical, 12)

            SheetFooter {
                if let error {
                    ErrorText(message: error)
                } else {
                    Text("Only the CA certificate is kept on this Mac; the key stays in 1Password.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            } trailing: {
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .frame(width: 520, height: 440)
        .task {
            do { items = try await model.vault().listCAItems() } catch {
                items = []
                self.error = error.localizedDescription
            }
        }
    }

    private func row(_ item: OPItemRef) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.seal.fill").foregroundStyle(.tint).imageScale(.large)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.hasPrefix("CA: ") ? String(item.title.dropFirst(4)) : item.title)
                Label(item.vaultName, systemImage: "lock.rectangle.stack")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if model.authorities.contains(where: { $0.item.itemID == item.itemID }) {
                Label("Linked", systemImage: "checkmark").foregroundStyle(.secondary)
            } else if linking == item {
                ProgressView().controlSize(.small)
            } else {
                Button("Link") { link(item) }.disabled(linking != nil)
            }
        }
        .padding(.vertical, 4)
    }

    private func link(_ item: OPItemRef) {
        linking = item
        error = nil
        Task {
            defer { linking = nil }
            do { try await model.link(item) } catch { self.error = error.localizedDescription }
        }
    }
}

/// Where a CA is stored and whether its key gets a passphrase.
struct StorageOptions {
    var createVault = true
    var vaultName = ""
    var existingVaultID = ""
    var usePassphrase = false
    var passphrase = ""
    var confirmation = ""

    func resolvedVaultName(caName: String) -> String {
        let name = vaultName.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? "CA: \(caName)" : name
    }

    func isComplete(caName: String) -> Bool {
        createVault ? !caName.isEmpty || !vaultName.isEmpty : !existingVaultID.isEmpty
    }

    func destination(caName: String) -> VaultDestination {
        createVault ? .new(name: resolvedVaultName(caName: caName)) : .existing(id: existingVaultID)
    }

    func validatedPassphrase() throws -> String? {
        guard usePassphrase else { return nil }
        try CertificateAuthority.validate(passphrase: passphrase, confirmation: confirmation)
        return passphrase
    }
}

struct StorageSections: View {
    @Binding var options: StorageOptions
    var caName: String

    var body: some View {
        Section {
            Picker("Store in", selection: $options.createVault) {
                Text("New vault").tag(true)
                Text("Existing vault").tag(false)
            }
            .pickerStyle(.segmented)
            if options.createVault {
                TextField("Vault name", text: $options.vaultName,
                          prompt: Text(options.resolvedVaultName(caName: caName.isEmpty ? "…" : caName)))
            } else {
                VaultPicker(vaultID: $options.existingVaultID)
            }
        } header: {
            Text("1Password")
        } footer: {
            Text("The vault holds the CA and every certificate it issues (never their private keys). Anyone with access to the vault can issue certificates.")
                .foregroundStyle(.secondary)
        }

        Section {
            Toggle(isOn: $options.usePassphrase) {
                Text("Also require a passphrase")
                Text(options.usePassphrase
                     ? "Keep it outside this vault, otherwise it adds nothing."
                     : "Off: issuing only needs 1Password’s approval.")
            }
            if options.usePassphrase {
                SecureField("Passphrase", text: $options.passphrase)
                SecureField("Confirm passphrase", text: $options.confirmation)
            }
        }
    }
}

struct SheetButtons: View {
    var error: String?
    var working: Bool
    var action: String
    var disabled: Bool
    var onCancel: () -> Void
    var onAction: () -> Void

    var body: some View {
        SheetFooter {
            if let error {
                ErrorText(message: error)
            } else if working {
                ProgressView().controlSize(.small)
                Text("Waiting for 1Password…").font(.callout).foregroundStyle(.secondary)
            }
        } trailing: {
            Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
            Button(action, action: onAction)
                .keyboardShortcut(.defaultAction)
                .disabled(disabled || working)
        }
    }
}

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var status: (ok: Bool, message: String)?
    @State private var testing = false

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                LabeledContent("1Password CLI") {
                    if let path = model.detectedOPPath {
                        Label(path, systemImage: "checkmark.circle.fill")
                            .labelStyle(StatusLabelStyle(color: .green))
                    } else {
                        Label("Not found", systemImage: "xmark.circle.fill")
                            .labelStyle(StatusLabelStyle(color: .red))
                    }
                }
                TextField("Custom path", text: $model.opPathOverride, prompt: Text("Detected automatically"))
                TextField("Account", text: $model.opAccount, prompt: Text("Only if you use several accounts"))
                HStack {
                    Button("Test Connection", action: test).disabled(testing)
                    if testing {
                        ProgressView().controlSize(.small)
                    } else if let status {
                        Label(status.message, systemImage: status.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .labelStyle(StatusLabelStyle(color: status.ok ? .green : .red))
                            .lineLimit(2)
                    }
                }
            } header: {
                Text("Connection")
            } footer: {
                Text("Cert Lab uses the 1Password CLI (`brew install 1password-cli`). In the 1Password app, turn on Settings › Developer › Integrate with 1Password CLI.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func test() {
        testing = true
        Task {
            defer { testing = false }
            do {
                let vaults = try await model.listVaults()
                status = (true, "Connected · \(vaults.count.counted("vault"))")
            } catch {
                status = (false, error.localizedDescription)
            }
        }
    }
}

private struct StatusLabelStyle: LabelStyle {
    var color: Color

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon.foregroundStyle(color)
            configuration.title.foregroundStyle(.secondary)
        }
    }
}
