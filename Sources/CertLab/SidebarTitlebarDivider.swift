import AppKit
import SwiftUI

/// Extends the sidebar's native divider through the window toolbar.
struct SidebarTitlebarDivider: NSViewRepresentable {
    var isVisible: Bool

    func makeNSView(context: Context) -> DividerAnchorView { DividerAnchorView() }
    func updateNSView(_ nsView: DividerAnchorView, context: Context) {
        nsView.isDividerVisible = isVisible
    }

    static func dismantleNSView(_ nsView: DividerAnchorView, coordinator: ()) {
        nsView.removeDivider()
    }

    final class DividerAnchorView: NSView {
        private var divider: SeparatorView?
        private var dividerConstraints: [NSLayoutConstraint] = []

        var isDividerVisible = true {
            didSet { divider?.isHidden = !isDividerVisible }
        }

        func removeDivider() {
            NSLayoutConstraint.deactivate(dividerConstraints)
            dividerConstraints = []
            divider?.removeFromSuperview()
            divider = nil
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            removeDivider()
            // The toolbar is above SwiftUI's content; draw only its missing segment
            // in the window frame, anchored to the resizable sidebar edge.
            guard let frameView = window?.contentView?.superview else { return }
            let line = SeparatorView()
            var ancestor = superview
            while let view = ancestor {
                if let splitView = view as? NSSplitView {
                    line.splitView = splitView
                    break
                }
                ancestor = view.superview
            }
            line.translatesAutoresizingMaskIntoConstraints = false
            line.isHidden = !isDividerVisible
            line.setAccessibilityElement(false)
            frameView.addSubview(line)
            dividerConstraints = [
                line.leadingAnchor.constraint(equalTo: trailingAnchor),
                line.widthAnchor.constraint(equalToConstant: 1),
                line.topAnchor.constraint(equalTo: frameView.topAnchor),
                line.bottomAnchor.constraint(equalTo: topAnchor)
            ]
            NSLayoutConstraint.activate(dividerConstraints)
            divider = line
        }

        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }

    final class SeparatorView: NSView {
        weak var splitView: NSSplitView?

        override func viewDidChangeEffectiveAppearance() {
            super.viewDidChangeEffectiveAppearance()
            needsDisplay = true
        }

        override func draw(_ dirtyRect: NSRect) {
            (splitView?.dividerColor ?? .separatorColor).setFill()
            bounds.fill()
        }

        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }
}
