// ClipBridge for macOS
// Menu-bar app that watches the clipboard (text + images) and new screenshots,
// keeps a local history, and syncs to/from your Android phone through an ntfy
// server, end-to-end encrypted (AES-256-GCM, key from a shared passphrase via
// PBKDF2-SHA256).
//
// Wire formats (must match the Android app):
//   text  : ntfy message body (or "clip.txt" attachment) =
//           base64( nonce12 || AES-GCM( JSON{v,from,name,text,ts} ) || tag16 )
//   image : ntfy attachment "clip.cbin" (raw bytes) =
//           nonce12 || AES-GCM( u32be(len) || JSON{v:2,type:"image",from,name,ts,mime} || imageBytes ) || tag16

import AppKit
import CryptoKit
import CommonCrypto
import CoreImage
import ImageIO
import UniformTypeIdentifiers

// MARK: - Helpers

let alnum = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
let lowerAlnum = "abcdefghijkmnpqrstuvwxyz23456789"

func randomString(_ n: Int, alphabet: String) -> String {
    let chars = Array(alphabet)
    return String((0..<n).map { _ in chars[Int.random(in: 0..<chars.count)] })
}

func preview(_ s: String, _ n: Int = 40) -> String {
    let one = s.replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespaces)
    return one.count > n ? String(one.prefix(n)) + "…" : one
}

func trimmed(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }

func sizeString(_ n: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }

enum Paths {
    static let dir: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let d = base.appendingPathComponent("ClipBridge", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return d
    }()
    static let images: URL = {
        let d = dir.appendingPathComponent("images", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return d
    }()
    static var received: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Pictures/ClipBridge", isDirectory: true)
    }
    static var config: URL { dir.appendingPathComponent("config.json") }
    static var history: URL { dir.appendingPathComponent("history.json") }
    static var launchAgent: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/ca.ishmeet.clipbridge.plist")
    }
}

func writePrivate(_ data: Data, to url: URL) {
    try? data.write(to: url, options: .atomic)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

// MARK: - Config

struct Config: Codable {
    var server = "https://ntfy.sh"
    var topic = ""
    var passphrase = ""
    var token = ""
    var deviceId = UUID().uuidString
    var deviceName = Host.current().localizedName ?? "Mac"
    var autoSend = true
    var paused = false
    var sendImages = true        // images copied to the clipboard
    var sendScreenshots = true   // new screenshot files (⌘⇧3 / ⌘⇧4 / ⌘⇧5)
    var saveImages = true        // save received images to ~/Pictures/ClipBridge
    var receiveFromMacs = true   // apply clips sent by other Macs in the same pairing

    var isReady: Bool { !baseURL.isEmpty && !topic.isEmpty && !passphrase.isEmpty }
    var baseURL: String {
        var s = trimmed(server)
        while s.hasSuffix("/") { s.removeLast() }
        return s
    }

    init() {}

    // Tolerant decoding so new fields never wipe an existing config.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Config()
        server = try c.decodeIfPresent(String.self, forKey: .server) ?? d.server
        topic = try c.decodeIfPresent(String.self, forKey: .topic) ?? ""
        passphrase = try c.decodeIfPresent(String.self, forKey: .passphrase) ?? ""
        token = try c.decodeIfPresent(String.self, forKey: .token) ?? ""
        deviceId = try c.decodeIfPresent(String.self, forKey: .deviceId) ?? d.deviceId
        deviceName = try c.decodeIfPresent(String.self, forKey: .deviceName) ?? d.deviceName
        autoSend = try c.decodeIfPresent(Bool.self, forKey: .autoSend) ?? true
        paused = try c.decodeIfPresent(Bool.self, forKey: .paused) ?? false
        sendImages = try c.decodeIfPresent(Bool.self, forKey: .sendImages) ?? true
        sendScreenshots = try c.decodeIfPresent(Bool.self, forKey: .sendScreenshots) ?? true
        saveImages = try c.decodeIfPresent(Bool.self, forKey: .saveImages) ?? true
        receiveFromMacs = try c.decodeIfPresent(Bool.self, forKey: .receiveFromMacs) ?? true
    }
}

// MARK: - Crypto (must match the Android app exactly)

enum Crypto {
    static let iterations: UInt32 = 200_000

    /// PBKDF2-HMAC-SHA256(passphrase, "clipbridge:" + topic, 200k) -> 32-byte AES key
    static func deriveKey(passphrase: String, topic: String) -> SymmetricKey? {
        let salt = Array("clipbridge:\(topic)".utf8)
        var out = [UInt8](repeating: 0, count: 32)
        let rc = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                      passphrase, passphrase.utf8.count,
                                      salt, salt.count,
                                      CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                      iterations,
                                      &out, out.count)
        guard rc == Int32(kCCSuccess) else { return nil }
        return SymmetricKey(data: out)
    }

    /// nonce[12] || ciphertext || tag[16]
    static func sealRaw(_ plain: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.seal(plain, using: key)
        guard let combined = box.combined else { throw CocoaError(.coderInvalidValue) }
        return combined
    }

    static func openRaw(_ data: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: data)
        return Data(try AES.GCM.open(box, using: key))
    }

    static func seal(_ plain: Data, key: SymmetricKey) throws -> String {
        try sealRaw(plain, key: key).base64EncodedString()
    }

    static func open(_ b64: String, key: SymmetricKey) throws -> Data {
        guard let d = Data(base64Encoded: trimmed(b64)) else { throw CocoaError(.coderReadCorrupt) }
        return try openRaw(d, key: key)
    }
}

struct Payload: Codable {
    var v: Int?
    var from: String
    var name: String?
    var text: String
    var ts: Double?   // epoch milliseconds
    var platform: String?   // "mac" or "android" (missing on older phone builds)
}

struct BlobHeader: Codable {
    var v: Int
    var type: String
    var from: String
    var name: String?
    var ts: Double?
    var mime: String
    var platform: String?
}

enum Blob {
    static func seal(header: BlobHeader, body: Data, key: SymmetricKey) throws -> Data {
        let h = try JSONEncoder().encode(header)
        let n = h.count
        var plain = Data([UInt8(n >> 24 & 0xFF), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)])
        plain.append(h)
        plain.append(body)
        return try Crypto.sealRaw(plain, key: key)
    }

    static func open(_ data: Data, key: SymmetricKey) throws -> (BlobHeader, Data) {
        let p = try Crypto.openRaw(data, key: key)
        guard p.count >= 4 else { throw CocoaError(.coderReadCorrupt) }
        let b = [UInt8](p.prefix(4))
        let len = Int(b[0]) << 24 | Int(b[1]) << 16 | Int(b[2]) << 8 | Int(b[3])
        guard len > 0, 4 + len <= p.count else { throw CocoaError(.coderReadCorrupt) }
        let header = try JSONDecoder().decode(BlobHeader.self, from: p.subdata(in: 4..<(4 + len)))
        return (header, p.subdata(in: (4 + len)..<p.count))
    }
}

struct HistoryItem: Codable {
    var text: String
    var date: Date
    var from: String
    var image: String?   // file name in Paths.images
    var size: Int?
}

// MARK: - Images

struct ImageClip {
    var data: Data
    var mime: String
}

enum ImageUtil {
    static let maxBytes = 14_000_000

    static func ext(for mime: String) -> String {
        switch mime {
        case "image/png": return "png"
        case "image/jpeg", "image/jpg": return "jpg"
        case "image/heic", "image/heif": return "heic"
        case "image/gif": return "gif"
        case "image/webp": return "webp"
        case "image/tiff": return "tiff"
        default: return "png"
        }
    }

    static func mime(forExt e: String) -> String {
        switch e.lowercased() {
        case "jpg", "jpeg": return "image/jpeg"
        case "heic", "heif": return "image/heic"
        case "gif": return "image/gif"
        case "webp": return "image/webp"
        case "tiff", "tif": return "image/tiff"
        default: return "image/png"
        }
    }

    static func uti(for mime: String) -> NSPasteboard.PasteboardType {
        switch mime {
        case "image/png": return .png
        case "image/jpeg", "image/jpg": return NSPasteboard.PasteboardType("public.jpeg")
        case "image/heic", "image/heif": return NSPasteboard.PasteboardType("public.heic")
        case "image/gif": return NSPasteboard.PasteboardType("com.compuserve.gif")
        case "image/webp": return NSPasteboard.PasteboardType("org.webmproject.webp")
        default: return .tiff
        }
    }

    static func fromPasteboard(_ pb: NSPasteboard) -> ImageClip? {
        if let png = pb.data(forType: .png) { return ImageClip(data: png, mime: "image/png") }
        if let jpg = pb.data(forType: NSPasteboard.PasteboardType("public.jpeg")) { return ImageClip(data: jpg, mime: "image/jpeg") }
        if let tiff = pb.data(forType: .tiff), let rep = NSBitmapImageRep(data: tiff),
           let png = rep.representation(using: .png, properties: [:]) {
            return ImageClip(data: png, mime: "image/png")
        }
        return nil
    }

    /// Big images are re-encoded as JPEG so they stay quick to sync.
    static let phoneFriendly: Set<String> = ["image/png", "image/jpeg", "image/gif", "image/webp"]

    static func prepare(_ img: ImageClip) -> ImageClip? {
        var out = img
        let mustConvert = !phoneFriendly.contains(out.mime)          // HEIC, TIFF, BMP…
        let shouldShrink = out.data.count > 5_000_000 && out.mime != "image/gif"
        if mustConvert || shouldShrink,
           let rep = NSBitmapImageRep(data: out.data),
           let jpg = rep.representation(using: .jpeg, properties: [.compressionFactor: 0.85]),
           mustConvert || jpg.count < out.data.count {
            out = ImageClip(data: jpg, mime: "image/jpeg")
        }
        return out.data.count <= maxBytes ? out : nil
    }

    /// Files copied in Finder (the clipboard holds their URLs plus the file name as text).
    static func filesFromPasteboard(_ pb: NSPasteboard) -> [URL]? {
        guard let urls = pb.readObjects(forClasses: [NSURL.self],
                                        options: [.urlReadingFileURLsOnly: true]) as? [URL],
              !urls.isEmpty else { return nil }
        return urls
    }

    static func isImageFile(_ url: URL) -> Bool {
        guard let t = UTType(filenameExtension: url.pathExtension) else { return false }
        return t.conforms(to: .image) && !t.conforms(to: .pdf)
    }

    static func mime(forFile url: URL) -> String {
        UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? mime(forExt: url.pathExtension)
    }

    static func thumbnail(_ url: URL, width: CGFloat = 28) -> NSImage? {
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: 96,
            kCGImageSourceCreateThumbnailWithTransform: true,
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
        let h = min(width * 1.5, width * CGFloat(cg.height) / CGFloat(max(cg.width, 1)))
        return NSImage(cgImage: cg, size: NSSize(width: width, height: max(h, 8)))
    }
}

// MARK: - ntfy JSON stream subscriber

final class NtfyStream: NSObject, URLSessionDataDelegate {
    let baseURL: String
    let topic: String
    let token: String
    var onEvent: (([String: Any]) -> Void)?
    var onState: ((Bool, String?) -> Void)?

    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var buffer = Data()
    private var lastId: String?
    private var backoff: TimeInterval = 2
    private var stopped = false
    private var announced = false

    init(baseURL: String, topic: String, token: String) {
        self.baseURL = baseURL
        self.topic = topic
        self.token = token
        super.init()
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 100          // ntfy sends a keepalive every ~45s
        cfg.timeoutIntervalForResource = 60 * 60 * 24 * 30
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: .main)
    }

    func start() { stopped = false; connect() }

    func stop() {
        stopped = true
        task?.cancel()
        task = nil
        session?.invalidateAndCancel()
        session = nil
    }

    private func connect() {
        guard !stopped, let session else { return }
        var comps = URLComponents(string: "\(baseURL)/\(topic)/json")
        if let lastId { comps?.queryItems = [URLQueryItem(name: "since", value: lastId)] }
        guard let url = comps?.url else { onState?(false, "Bad server URL"); return }
        var req = URLRequest(url: url)
        if !token.isEmpty { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        buffer = Data()
        announced = false
        let t = session.dataTask(with: req)
        task = t
        t.resume()
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard dataTask === task else { return }
        if !announced {
            announced = true
            let code = (dataTask.response as? HTTPURLResponse)?.statusCode ?? 0
            if code != 200 {
                let body = String(data: data, encoding: .utf8) ?? ""
                onState?(false, "HTTP \(code) \(preview(body, 60))")
                dataTask.cancel()
                return
            }
            backoff = 2
            onState?(true, nil)
        }
        buffer.append(data)
        while let nl = buffer.firstIndex(of: 0x0A) {
            let line = buffer.subdata(in: buffer.startIndex..<nl)
            buffer = buffer.subdata(in: buffer.index(after: nl)..<buffer.endIndex)
            guard !line.isEmpty,
                  let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
            if (obj["event"] as? String) == "message", let id = obj["id"] as? String { lastId = id }
            onEvent?(obj)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard task === self.task, !stopped else { return }
        onState?(false, error?.localizedDescription ?? "Disconnected")
        let delay = backoff
        backoff = min(backoff * 2, 60)
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in self?.connect() }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    static let skipTypes: Set<String> = [
        "org.nspasteboard.ConcealedType",      // password managers
        "org.nspasteboard.TransientType",
        "org.nspasteboard.AutoGeneratedType",
        "com.agilebits.onepassword",
    ]
    static let staleAfterMs: Double = 5 * 60 * 1000
    static let maxTextBytes = 1_000_000
    static let maxImagesInHistory = 30

    var config = Config()
    var key: SymmetricKey?
    var statusItem: NSStatusItem!
    let menu = NSMenu()
    let pb = NSPasteboard.general
    var lastChange = 0
    var lastSyncedText: String?
    var lastImageHash: Data?
    var history: [HistoryItem] = []
    var thumbCache: [String: NSImage] = [:]
    var stream: NtfyStream?
    var connected = false
    var lastEvent = "Starting…"
    var pollTimer: Timer?
    var shotTimer: Timer?
    var watchStart = Date()
    var seenShots = Set<String>()
    var flashWork: DispatchWorkItem?
    var firstRun = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        installEditMenu()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        menu.delegate = self
        statusItem.menu = menu
        loadConfig()
        loadHistory()
        setIcon(baseIcon)

        lastChange = pb.changeCount   // don't send whatever was already on the clipboard
        watchStart = Date()
        pollTimer = Timer.scheduledTimer(timeInterval: 0.5, target: self,
                                         selector: #selector(poll), userInfo: nil, repeats: true)
        shotTimer = Timer.scheduledTimer(timeInterval: 1.0, target: self,
                                         selector: #selector(scanScreenshots), userInfo: nil, repeats: true)
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(didWake), name: NSWorkspace.didWakeNotification, object: nil)

        restartStream()
        lastEvent = config.isReady ? "Ready" : "Not configured"
        if firstRun {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in self?.showPairing(firstRun: true) }
        }
    }

    // Cmd+C / Cmd+V inside our dialogs need an Edit menu, even for a menu-bar-only app.
    func installEditMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit ClipBridge", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        main.addItem(appItem)
        let editItem = NSMenuItem()
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        main.addItem(editItem)
        NSApp.mainMenu = main
    }

    // MARK: Config & history persistence

    func loadConfig() {
        if let d = try? Data(contentsOf: Paths.config),
           let c = try? JSONDecoder().decode(Config.self, from: d), !c.topic.isEmpty {
            config = c
        } else {
            config = Config()
            config.topic = "clipbridge-" + randomString(20, alphabet: lowerAlnum)
            config.passphrase = randomString(28, alphabet: alnum)
            firstRun = true
            saveConfig()
        }
        deriveKey()
    }

    func saveConfig() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(config) { writePrivate(d, to: Paths.config) }
    }

    func deriveKey() {
        key = config.isReady ? Crypto.deriveKey(passphrase: config.passphrase, topic: config.topic) : nil
    }

    func loadHistory() {
        if let d = try? Data(contentsOf: Paths.history),
           let h = try? JSONDecoder().decode([HistoryItem].self, from: d) {
            history = h
        }
    }

    func saveHistory() {
        if let d = try? JSONEncoder().encode(history) { writePrivate(d, to: Paths.history) }
    }

    func deleteImageFile(_ h: HistoryItem) {
        guard let f = h.image else { return }
        try? FileManager.default.removeItem(at: Paths.images.appendingPathComponent(f))
        thumbCache[f] = nil
    }

    func addHistory(_ item: HistoryItem) {
        if item.image == nil { history.removeAll { $0.image == nil && $0.text == item.text } }
        history.insert(item, at: 0)
        var images = 0
        history = history.filter { h in
            guard h.image != nil else { return true }
            images += 1
            if images > Self.maxImagesInHistory { deleteImageFile(h); return false }
            return true
        }
        while history.count > 200 { deleteImageFile(history.removeLast()) }
        saveHistory()
    }

    func addTextHistory(_ text: String, from: String) {
        addHistory(HistoryItem(text: text, date: Date(), from: from, image: nil, size: nil))
    }

    func storeImage(_ img: ImageClip) -> String {
        let name = UUID().uuidString + "." + ImageUtil.ext(for: img.mime)
        writePrivate(img.data, to: Paths.images.appendingPathComponent(name))
        return name
    }

    // MARK: Clipboard watching

    @objc func poll() {
        let cc = pb.changeCount
        guard cc != lastChange else { return }
        lastChange = cc
        let types = (pb.types ?? []).map(\.rawValue)
        if types.contains(where: { Self.skipTypes.contains($0) }) { return }

        // Files copied in Finder: send the images themselves, never just their names.
        if let files = ImageUtil.filesFromPasteboard(pb) {
            let images = files.filter(ImageUtil.isImageFile).prefix(10)
            let doSend = config.autoSend && config.sendImages && !config.paused
            for url in images {
                guard let data = try? Data(contentsOf: url), !data.isEmpty else { continue }
                lastImageHash = nil   // allow several in a row
                handleLocalImage(ImageClip(data: data, mime: ImageUtil.mime(forFile: url)),
                                 label: url.deletingPathExtension().lastPathComponent, send: doSend)
            }
            if images.isEmpty { lastEvent = "Copied file(s) — only images are synced" }
            return
        }

        if let text = pb.string(forType: .string), !text.isEmpty {
            addTextHistory(text, from: "This Mac")
            if config.autoSend && !config.paused { send(text) }
            return
        }
        if let img = ImageUtil.fromPasteboard(pb) {
            handleLocalImage(img, label: "Image", send: config.autoSend && config.sendImages && !config.paused)
        }
    }

    func handleLocalImage(_ img: ImageClip, label: String, send doSend: Bool) {
        guard let prepared = ImageUtil.prepare(img) else {
            lastEvent = "Image too large to sync (max 14 MB)"
            return
        }
        let name = storeImage(prepared)
        addHistory(HistoryItem(text: label, date: Date(), from: "This Mac", image: name, size: prepared.data.count))
        if doSend { sendImage(prepared, label: label) }
    }

    // MARK: Screenshot files (⌘⇧3 / ⌘⇧4 / ⌘⇧5 save to a folder, not the clipboard)

    func screenshotDirectory() -> URL {
        if let loc = UserDefaults(suiteName: "com.apple.screencapture")?.string(forKey: "location"), !loc.isEmpty {
            return URL(fileURLWithPath: (loc as NSString).expandingTildeInPath, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop", isDirectory: true)
    }

    func isScreenCapture(_ url: URL) -> Bool {
        if getxattr(url.path, "com.apple.metadata:kMDItemIsScreenCapture", nil, 0, 0, 0) >= 0 { return true }
        let n = url.lastPathComponent.lowercased()
        return n.hasPrefix("screenshot") || n.hasPrefix("screen shot")
    }

    @objc func scanScreenshots() {
        guard config.sendScreenshots, config.autoSend, !config.paused, config.isReady else { return }
        let dir = screenshotDirectory()
        let keys: [URLResourceKey] = [.creationDateKey]
        guard let items = try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles]) else { return }
        for url in items {
            let ext = url.pathExtension.lowercased()
            guard ["png", "jpg", "jpeg", "heic", "tiff"].contains(ext), !seenShots.contains(url.path) else { continue }
            guard let created = (try? url.resourceValues(forKeys: Set(keys)))?.creationDate,
                  created > watchStart else { continue }
            seenShots.insert(url.path)
            guard isScreenCapture(url) else { continue }
            // Give the screenshot tool a moment to finish writing.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
                guard let self, let data = try? Data(contentsOf: url), !data.isEmpty else { return }
                self.handleLocalImage(ImageClip(data: data, mime: ImageUtil.mime(forExt: ext)),
                                      label: "Screenshot", send: true)
            }
        }
    }

    // MARK: Sending

    func upload(_ body: Data, filename: String?, done: @escaping (String?) -> Void) {
        guard let url = URL(string: "\(config.baseURL)/\(config.topic)") else { done("Bad server URL"); return }
        var req = URLRequest(url: url)
        if let filename {
            req.httpMethod = "PUT"
            req.setValue(filename, forHTTPHeaderField: "Filename")
        } else {
            req.httpMethod = "POST"
        }
        if !config.token.isEmpty { req.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization") }
        req.timeoutInterval = 120
        URLSession.shared.uploadTask(with: req, from: body) { data, resp, err in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let errBody = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let problem: String?
            if let err { problem = err.localizedDescription }
            else if !(200...299).contains(code) { problem = "HTTP \(code) \(preview(errBody, 50))" }
            else { problem = nil }
            DispatchQueue.main.async { done(problem) }
        }.resume()
    }

    func send(_ text: String, force: Bool = false) {
        guard config.isReady, let key else { lastEvent = "Not configured — open Settings"; return }
        if !force && text == lastSyncedText { return }
        guard text.utf8.count <= Self.maxTextBytes else { lastEvent = "Skipped: clip too large (>1 MB)"; return }

        let p = Payload(v: 1, from: config.deviceId, name: config.deviceName, text: text,
                        ts: (Date().timeIntervalSince1970 * 1000).rounded(), platform: "mac")
        guard let json = try? JSONEncoder().encode(p),
              let body = try? Crypto.seal(json, key: key) else { lastEvent = "Encryption failed"; return }
        lastSyncedText = text
        let bytes = Data(body.utf8)
        // ntfy's message limit is 4 KB; bigger goes as an attachment
        upload(bytes, filename: bytes.count > 3800 ? "clip.txt" : nil) { [weak self] problem in
            guard let self else { return }
            if let problem {
                self.lastEvent = "Send failed: \(problem)"
                self.lastSyncedText = nil
            } else {
                self.lastEvent = "Sent: \(preview(text))"
                self.flash("arrow.up.doc")
            }
        }
    }

    func sendImage(_ img: ImageClip, label: String) {
        guard config.isReady, let key else { lastEvent = "Not configured — open Settings"; return }
        let hash = Data(SHA256.hash(data: img.data))
        if hash == lastImageHash { return }
        let header = BlobHeader(v: 2, type: "image", from: config.deviceId, name: config.deviceName,
                                ts: (Date().timeIntervalSince1970 * 1000).rounded(), mime: img.mime,
                                platform: "mac")
        guard let blob = try? Blob.seal(header: header, body: img.data, key: key) else {
            lastEvent = "Encryption failed"
            return
        }
        lastImageHash = hash
        lastEvent = "Sending \(label.lowercased()) (\(sizeString(img.data.count)))…"
        flash("arrow.up.circle")
        upload(blob, filename: "clip.cbin") { [weak self] problem in
            guard let self else { return }
            if let problem {
                self.lastEvent = "Image send failed: \(problem)"
                self.lastImageHash = nil
            } else {
                self.lastEvent = "Sent \(label.lowercased()) (\(sizeString(img.data.count)))"
                self.flash("photo")
            }
        }
    }

    // MARK: Receiving

    func restartStream() {
        stream?.stop()
        stream = nil
        connected = false
        guard config.isReady else { return }
        let s = NtfyStream(baseURL: config.baseURL, topic: config.topic, token: config.token)
        s.onEvent = { [weak self] obj in self?.handleEvent(obj) }
        s.onState = { [weak self] ok, err in
            self?.connected = ok
            if let err { self?.lastEvent = "Connection: \(err)" }
        }
        stream = s
        s.start()
    }

    @objc func didWake() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in self?.restartStream() }
    }

    func handleEvent(_ obj: [String: Any]) {
        guard (obj["event"] as? String) == "message" else { return }
        if let att = obj["attachment"] as? [String: Any],
           let urlStr = att["url"] as? String, let url = URL(string: urlStr) {
            let isBlob = (att["name"] as? String ?? "").hasSuffix(".cbin")
            var req = URLRequest(url: url)
            req.timeoutInterval = 120
            if !config.token.isEmpty { req.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization") }
            URLSession.shared.dataTask(with: req) { [weak self] data, _, _ in
                guard let data else { return }
                DispatchQueue.main.async {
                    if isBlob {
                        self?.handleBlob(data)
                    } else if let s = String(data: data, encoding: .utf8) {
                        self?.handleCipher(s)
                    }
                }
            }.resume()
        } else if let msg = obj["message"] as? String {
            handleCipher(msg)
        }
    }

    func handleCipher(_ s: String) {
        guard let key,
              let plain = try? Crypto.open(s, key: key),
              let p = try? JSONDecoder().decode(Payload.self, from: plain) else { return }  // not ours / wrong passphrase
        guard p.from != config.deviceId else { return }                                      // our own echo
        if p.platform == "mac" && !config.receiveFromMacs { return }
        let who = p.name ?? "Phone"
        addTextHistory(p.text, from: who)
        let age = Date().timeIntervalSince1970 * 1000 - (p.ts ?? 0)
        guard !config.paused, age < Self.staleAfterMs else { return }   // keep old ones in history only

        lastSyncedText = p.text
        pb.clearContents()
        pb.setString(p.text, forType: .string)
        lastChange = pb.changeCount
        lastEvent = "From \(who): \(preview(p.text))"
        flash("arrow.down.doc")
    }

    func handleBlob(_ data: Data) {
        guard let key, let opened = try? Blob.open(data, key: key) else { return }
        let (h, body) = opened
        guard h.from != config.deviceId, h.type == "image", !body.isEmpty else { return }
        if h.platform == "mac" && !config.receiveFromMacs { return }
        let who = h.name ?? "Phone"
        let img = ImageClip(data: body, mime: h.mime)
        let name = storeImage(img)
        addHistory(HistoryItem(text: "Image", date: Date(), from: who, image: name, size: body.count))
        if config.saveImages { saveToPictures(img, from: who) }

        let age = Date().timeIntervalSince1970 * 1000 - (h.ts ?? 0)
        guard !config.paused, age < Self.staleAfterMs else { return }
        putImageOnPasteboard(img)
        lastImageHash = Data(SHA256.hash(data: body))
        lastEvent = "Image from \(who) (\(sizeString(body.count)))"
        flash("photo")
    }

    func putImageOnPasteboard(_ img: ImageClip) {
        pb.clearContents()
        let item = NSPasteboardItem()
        let type = ImageUtil.uti(for: img.mime)
        item.setData(img.data, forType: type)
        if type != .png && type != .tiff, let tiff = NSImage(data: img.data)?.tiffRepresentation {
            item.setData(tiff, forType: .tiff)   // widest compatibility for non-PNG formats
        }
        pb.writeObjects([item])
        lastChange = pb.changeCount
    }

    func saveToPictures(_ img: ImageClip, from who: String) {
        let dir = Paths.received
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd 'at' HH.mm.ss"
        let safeWho = who.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
        var url = dir.appendingPathComponent("\(safeWho) \(fmt.string(from: Date())).\(ImageUtil.ext(for: img.mime))")
        var i = 2
        while FileManager.default.fileExists(atPath: url.path) {
            url = dir.appendingPathComponent("\(safeWho) \(fmt.string(from: Date())) \(i).\(ImageUtil.ext(for: img.mime))")
            i += 1
        }
        try? img.data.write(to: url)
    }

    // MARK: Menu

    var baseIcon: String { config.paused ? "pause.circle" : "doc.on.clipboard" }

    func setIcon(_ name: String) {
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "ClipBridge")
            ?? NSImage(systemSymbolName: "doc.on.clipboard", accessibilityDescription: "ClipBridge")
        img?.isTemplate = true
        statusItem.button?.image = img
    }

    func flash(_ name: String) {
        setIcon(name)
        flashWork?.cancel()
        let w = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.setIcon(self.baseIcon)
        }
        flashWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: w)
    }

    func item(_ title: String, _ sel: Selector, key: String = "") -> NSMenuItem {
        let it = NSMenuItem(title: title, action: sel, keyEquivalent: key)
        it.target = self
        return it
    }

    func disabled(_ title: String) -> NSMenuItem {
        let it = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        it.isEnabled = false
        return it
    }

    func toggle(_ title: String, _ sel: Selector, _ on: Bool) -> NSMenuItem {
        let it = item(title, sel)
        it.state = on ? .on : .off
        return it
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let host = URL(string: config.baseURL)?.host ?? config.baseURL
        let status: String
        if !config.isReady { status = "Not configured" }
        else if config.paused { status = "⏸ Paused" }
        else if connected { status = "● Connected — \(host)" }
        else { status = "○ Connecting to \(host)…" }
        menu.addItem(disabled(status))
        menu.addItem(disabled(lastEvent))
        menu.addItem(.separator())

        let recent = NSMenuItem(title: "Recent Clips", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        if history.isEmpty { sub.addItem(disabled("Nothing yet")) }
        let fmt = DateFormatter()
        fmt.dateStyle = .short
        fmt.timeStyle = .short
        for (i, h) in history.prefix(30).enumerated() {
            let title: String
            if h.image != nil {
                title = "\(h.text) · \(sizeString(h.size ?? 0))" + (h.from == "This Mac" ? "" : " · from \(h.from)")
            } else {
                title = preview(h.text, 60)
            }
            let it = item(title, #selector(copyHistory(_:)))
            it.tag = i
            it.toolTip = "\(h.from) · \(fmt.string(from: h.date))"
            if let f = h.image {
                if thumbCache[f] == nil { thumbCache[f] = ImageUtil.thumbnail(Paths.images.appendingPathComponent(f)) }
                it.image = thumbCache[f]
            } else if h.from != "This Mac" {
                it.image = NSImage(systemSymbolName: "iphone", accessibilityDescription: nil)
            }
            sub.addItem(it)
        }
        sub.addItem(.separator())
        sub.addItem(item("Open Received Images Folder", #selector(openReceived)))
        sub.addItem(item("Clear History", #selector(clearHistory)))
        recent.submenu = sub
        menu.addItem(recent)
        menu.addItem(item("Send Current Clipboard to Phone", #selector(sendNow)))
        menu.addItem(.separator())

        menu.addItem(toggle("Auto-send Every Copy", #selector(toggleAuto), config.autoSend))
        menu.addItem(toggle("Include Images", #selector(toggleImages), config.sendImages))
        menu.addItem(toggle("Send New Screenshots", #selector(toggleScreenshots), config.sendScreenshots))
        menu.addItem(toggle("Save Received Images to Pictures", #selector(toggleSaveImages), config.saveImages))
        menu.addItem(toggle("Receive from Other Macs", #selector(toggleMacs), config.receiveFromMacs))
        menu.addItem(toggle("Pause Sync", #selector(togglePause), config.paused))
        menu.addItem(toggle("Open at Login", #selector(toggleLogin),
                            FileManager.default.fileExists(atPath: Paths.launchAgent.path)))
        menu.addItem(.separator())
        menu.addItem(item("Pair Phone…", #selector(pairPhone)))
        menu.addItem(item("Join Existing Pairing…", #selector(joinPairing)))
        menu.addItem(item("Settings…", #selector(openSettings), key: ","))
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit ClipBridge", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    @objc func copyHistory(_ sender: NSMenuItem) {
        guard sender.tag < history.count else { return }
        let h = history[sender.tag]
        if let f = h.image {
            let url = Paths.images.appendingPathComponent(f)
            guard let data = try? Data(contentsOf: url) else { return }
            putImageOnPasteboard(ImageClip(data: data, mime: ImageUtil.mime(forExt: url.pathExtension)))
            lastEvent = "Image copied from history"
        } else {
            pb.clearContents()
            pb.setString(h.text, forType: .string)
            // the poller picks this up, moves it to the top and syncs it
        }
    }

    @objc func clearHistory() {
        history.forEach(deleteImageFile)
        history.removeAll()
        thumbCache.removeAll()
        saveHistory()
    }

    @objc func openReceived() {
        try? FileManager.default.createDirectory(at: Paths.received, withIntermediateDirectories: true)
        NSWorkspace.shared.open(Paths.received)
    }

    @objc func sendNow() {
        if let text = pb.string(forType: .string), !text.isEmpty {
            send(text, force: true)
        } else if let img = ImageUtil.fromPasteboard(pb), let prepared = ImageUtil.prepare(img) {
            lastImageHash = nil
            sendImage(prepared, label: "Image")
        } else {
            lastEvent = "Clipboard is empty"
        }
    }

    @objc func toggleAuto() { config.autoSend.toggle(); saveConfig() }
    @objc func toggleImages() { config.sendImages.toggle(); saveConfig() }
    @objc func toggleSaveImages() { config.saveImages.toggle(); saveConfig() }
    @objc func toggleMacs() { config.receiveFromMacs.toggle(); saveConfig() }

    @objc func toggleScreenshots() {
        config.sendScreenshots.toggle()
        watchStart = Date()   // don't send screenshots taken while it was off
        saveConfig()
    }

    @objc func togglePause() {
        config.paused.toggle()
        watchStart = Date()
        saveConfig()
        setIcon(baseIcon)
    }

    @objc func toggleLogin() {
        let path = Paths.launchAgent
        if FileManager.default.fileExists(atPath: path.path) {
            try? FileManager.default.removeItem(at: path)
            return
        }
        let plist: [String: Any] = [
            "Label": "ca.ishmeet.clipbridge",
            "ProgramArguments": ["/usr/bin/open", Bundle.main.bundlePath],
            "RunAtLoad": true,
            "LimitLoadToSessionType": "Aqua",
        ]
        try? FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
            try? d.write(to: path)
        }
    }

    // MARK: Settings dialog

    func label(_ s: String) -> NSTextField {
        let l = NSTextField(labelWithString: s)
        l.alignment = .right
        return l
    }

    func field(_ v: String, placeholder: String = "") -> NSTextField {
        let f = NSTextField(string: v)
        f.placeholderString = placeholder
        f.translatesAutoresizingMaskIntoConstraints = false
        f.widthAnchor.constraint(equalToConstant: 320).isActive = true
        return f
    }

    @objc func openSettings() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "ClipBridge Settings"
        alert.informativeText = "Your phone must use the same server, topic and passphrase. Easiest: use “Pair Phone…” and scan the QR code."
        let fServer = field(config.server, placeholder: "https://ntfy.sh")
        let fTopic = field(config.topic)
        let fPass = field(config.passphrase)
        let fToken = field(config.token, placeholder: "optional (tk_… for protected servers)")
        let fName = field(config.deviceName)
        let grid = NSGridView(views: [
            [label("Server"), fServer],
            [label("Topic"), fTopic],
            [label("Passphrase"), fPass],
            [label("Access token"), fToken],
            [label("This Mac’s name"), fName],
        ])
        grid.rowSpacing = 8
        grid.columnSpacing = 8
        grid.frame = NSRect(x: 0, y: 0, width: 450, height: 160)
        alert.accessoryView = grid
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "New Random Topic & Passphrase")

        switch alert.runModal() {
        case .alertFirstButtonReturn:
            config.server = trimmed(fServer.stringValue)
            config.topic = trimmed(fTopic.stringValue)
            config.passphrase = trimmed(fPass.stringValue)
            config.token = trimmed(fToken.stringValue)
            config.deviceName = trimmed(fName.stringValue).isEmpty ? (Host.current().localizedName ?? "Mac") : trimmed(fName.stringValue)
            applyConfig()
        case .alertThirdButtonReturn:
            config.topic = "clipbridge-" + randomString(20, alphabet: lowerAlnum)
            config.passphrase = randomString(28, alphabet: alnum)
            applyConfig()
            showPairing(firstRun: false)
        default:
            break
        }
    }

    func applyConfig() {
        saveConfig()
        deriveKey()
        lastSyncedText = nil
        lastImageHash = nil
        restartStream()
        lastEvent = config.isReady ? "Settings saved" : "Not configured"
    }

    // MARK: Pairing

    func pairingURI() -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s }
        var u = "clipbridge://pair?server=\(enc(config.baseURL))&topic=\(enc(config.topic))&pass=\(enc(config.passphrase))"
        if !config.token.isEmpty { u += "&token=\(enc(config.token))" }
        return u
    }

    func qrImage(_ s: String, size: CGFloat) -> NSImage? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(s.utf8), forKey: "inputMessage")
        f.setValue("M", forKey: "inputCorrectionLevel")
        guard let img = f.outputImage else { return nil }
        let scale = max(1, floor(size / img.extent.width))
        let scaled = img.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let rep = NSCIImageRep(ciImage: scaled)
        let ns = NSImage(size: rep.size)
        ns.addRepresentation(rep)
        return ns
    }

    @objc func pairPhone() { showPairing(firstRun: false) }

    func showPairing(firstRun: Bool) {
        NSApp.activate(ignoringOtherApps: true)
        let uri = pairingURI()
        let alert = NSAlert()
        alert.messageText = firstRun ? "Welcome to ClipBridge — pair your phone" : "Pair your phone"
        alert.informativeText = """
        1. Install ClipBridge on your Android phone.
        2. Scan this QR code with the phone’s camera and open the link — or copy the pairing link, \
        get it to your phone, and tap “Paste pairing link” in the app.

        The QR contains your secret passphrase. Don't share it.
        """
        if let img = qrImage(uri, size: 260) {
            let v = NSImageView(frame: NSRect(x: 0, y: 0, width: img.size.width, height: img.size.height))
            v.image = img
            v.imageScaling = .scaleNone
            alert.accessoryView = v
        }
        alert.addButton(withTitle: "Done")
        alert.addButton(withTitle: "Copy Pairing Link")
        alert.addButton(withTitle: "Join Existing Pairing…")
        switch alert.runModal() {
        case .alertSecondButtonReturn:
            pb.clearContents()
            pb.setString(uri, forType: .string)
            lastChange = pb.changeCount   // don't sync or log the secret link
            lastEvent = "Pairing link copied"
        case .alertThirdButtonReturn:
            joinPairing()
        default:
            break
        }
    }

    // MARK: Joining an existing pairing (e.g. a second Mac)

    struct PairingInfo {
        var server: String
        var topic: String
        var pass: String
        var token: String
    }

    func parsePairing(_ s: String) -> PairingInfo? {
        guard let c = URLComponents(string: trimmed(s)), c.scheme == "clipbridge" else { return nil }
        func q(_ n: String) -> String { trimmed(c.queryItems?.first { $0.name == n }?.value ?? "") }
        let info = PairingInfo(server: q("server"), topic: q("topic"), pass: q("pass"), token: q("token"))
        return info.server.isEmpty || info.topic.isEmpty || info.pass.isEmpty ? nil : info
    }

    @objc func joinPairing() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Join an existing ClipBridge pairing"
        alert.informativeText = "On the device that's already set up (e.g. your other Mac): ClipBridge menu → Pair Phone… → Copy Pairing Link. Get that link to this Mac (Notes, email, Messages) and paste it below — or just click the link and ClipBridge opens it."
        let f = NSTextField(string: "")
        f.placeholderString = "clipbridge://pair?server=…&topic=…&pass=…"
        f.frame = NSRect(x: 0, y: 0, width: 420, height: 24)
        if let s = pb.string(forType: .string), parsePairing(s) != nil { f.stringValue = trimmed(s) }
        alert.accessoryView = f
        alert.addButton(withTitle: "Join")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = f
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard let info = parsePairing(f.stringValue) else {
            let bad = NSAlert()
            bad.messageText = "That isn't a ClipBridge pairing link"
            bad.informativeText = "It should start with clipbridge://pair?"
            bad.runModal()
            return
        }
        applyPairing(info)
    }

    func applyPairing(_ info: PairingInfo) {
        config.server = info.server
        config.topic = info.topic
        config.passphrase = info.pass
        config.token = info.token
        applyConfig()   // keeps this Mac's own device ID, so devices don't ignore each other
        lastEvent = "Joined pairing ✓"
        flash("checkmark.circle")
    }

    // clipbridge://pair?… links clicked anywhere on this Mac
    func application(_ application: NSApplication, open urls: [URL]) {
        guard let url = urls.first, let info = parsePairing(url.absoluteString) else { return }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Join this ClipBridge pairing?"
        alert.informativeText = "This Mac will sync with every device using topic “\(info.topic)” on \(info.server)."
        alert.addButton(withTitle: "Join")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { applyPairing(info) }
    }
}

// MARK: - Entry point

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
