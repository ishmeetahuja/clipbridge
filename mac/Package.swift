// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ClipBridge",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "ClipBridge", path: "Sources/ClipBridge")
    ]
)
