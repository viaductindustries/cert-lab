// Draws the Cert Lab app icon and writes Resources/AppIcon.icns.
// Usage: swift scripts/make-icon.swift
import AppKit

func render(size: CGFloat) -> Data {
    let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
        let scale = size / 1024
        // macOS icon grid: 824pt squircle centred on a 1024 canvas.
        let tile = NSRect(x: 100 * scale, y: 100 * scale, width: 824 * scale, height: 824 * scale)
        let path = NSBezierPath(roundedRect: tile, xRadius: 185 * scale, yRadius: 185 * scale)

        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.3)
        shadow.shadowBlurRadius = 20 * scale
        shadow.shadowOffset = NSSize(width: 0, height: -10 * scale)
        shadow.set()
        NSColor.black.setFill()
        path.fill()
        NSGraphicsContext.restoreGraphicsState()

        NSGradient(colors: [NSColor(red: 0.13, green: 0.62, blue: 0.62, alpha: 1),
                            NSColor(red: 0.16, green: 0.30, blue: 0.70, alpha: 1)])!
            .draw(in: path, angle: -60)

        // Soft highlight across the top.
        NSGraphicsContext.saveGraphicsState()
        path.addClip()
        NSGradient(colors: [NSColor.white.withAlphaComponent(0.18), NSColor.white.withAlphaComponent(0)])!
            .draw(in: NSRect(x: tile.minX, y: tile.midY, width: tile.width, height: tile.height / 2), angle: -90)
        NSGraphicsContext.restoreGraphicsState()

        let config = NSImage.SymbolConfiguration(pointSize: 470 * scale, weight: .semibold)
            .applying(.init(paletteColors: [NSColor(red: 0.15, green: 0.42, blue: 0.67, alpha: 1), .white]))
        if let seal = NSImage(systemSymbolName: "checkmark.seal.fill", accessibilityDescription: nil)?
            .withSymbolConfiguration(config) {
            let s = seal.size
            seal.draw(in: NSRect(x: rect.midX - s.width / 2, y: rect.midY - s.height / 2 - 6 * scale, width: s.width, height: s.height))
        }
        return true
    }
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    image.draw(in: NSRect(x: 0, y: 0, width: size, height: size))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let iconset = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try render(size: CGFloat(base)).write(to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
    try render(size: CGFloat(base * 2)).write(to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
process.arguments = ["-c", "icns", iconset.path, "-o", "Resources/AppIcon.icns"]
try process.run()
process.waitUntilExit()
try render(size: 512).write(to: URL(fileURLWithPath: "Resources/AppIcon-preview.png"))
print(process.terminationStatus == 0 ? "Wrote Resources/AppIcon.icns" : "iconutil failed")
