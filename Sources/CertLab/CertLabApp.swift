import AppKit
import CertLabCore
import SwiftUI

@main
struct CertLabApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        Window("Cert Lab", id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 880, minHeight: 560)
        }
        .defaultSize(width: 1080, height: 700)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Issue Certificate…") {
                    if let ca = model.selectedCA { model.sheet = .issue(ca, prefill: nil) }
                }
                .keyboardShortcut("n")
                .disabled(model.selectedCA == nil)
                Divider()
                Button("New Certificate Authority…") { model.sheet = .newCA }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                Button("Import Certificate Authority…") { model.sheet = .importCA }
                Button("Link CA from 1Password…") { model.sheet = .linkCA }
            }
            CommandGroup(after: .toolbar) {
                Button("Sync with 1Password") {
                    if let ca = model.selectedCA { model.startSync(ca) }
                }
                .keyboardShortcut("r")
                .disabled(model.selectedCA == nil)
                Divider()
            }
        }

        Settings {
            SettingsView().environment(model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Lets `swift run` behave like a bundled app.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
