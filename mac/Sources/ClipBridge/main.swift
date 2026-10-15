// ClipBridge for macOS
// Menu-bar app that watches the clipboard, keeps a local history, and syncs
// copies to/from your Android phone through an ntfy server, end-to-end encrypted
// (AES-256-GCM, key derived from a shared passphrase with PBKDF2-SHA256).

import AppKit
import CryptoKit
import CommonCrypto
import CoreImage

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

enum Paths {
    static let dir: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let d = base.appendingPathComponent("ClipBridge", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return d
    }()
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

    /// base64( nonce[12] || ciphertext || tag[16] )
    static func seal(_ plain: Data, key: SymmetricKey) throws -> String {
        let box = try AES.GCM.seal(plain, using: key)
        guard let combined = box.combined else { throw CocoaError(.coderInvalidValue) }
        return combined.base64EncodedString()
    }

    static func open(_ b64: String, key: SymmetricKey) throws -> Data {
        guard let d = Data(base64Encoded: trimmed(b64)) else { throw CocoaError(.coderReadCorrupt) }
        let box = try AES.GCM.SealedBox(combined: d)
        return try AES.GCM.open(box, using: key)
    }
}

struct Payload: Codable {
    var v: Int?
    var from: String
    var name: String?
    var text: String
    var ts: Double?   // epoch milliseconds
}

struct HistoryItem: Codable {
    var text: String
    var date: Date
    var from: String
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
    static let maxBytes = 1_000_000

    var config = Config()
    var key: SymmetricKey?
    var statusItem: NSStatusItem!
    let menu = NSMenu()
    let pb = NSPasteboard.general
    var lastChange = 0
    var lastSyncedText: String?
    var history: [HistoryItem] = []
    var stream: NtfyStream?
    var connected = false
    var lastEvent = "Starting…"
    var pollTimer: Timer?
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
        pollTimer = Timer.scheduledTimer(timeInterval: 0.5, target: self,
                                         selector: #selector(poll), userInfo: nil, repeats: true)
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

    func addHistory(_ text: String, from: String) {
        history.removeAll { $0.text == text }
        history.insert(HistoryItem(text: text, date: Date(), from: from), at: 0)
        if history.count > 200 { history.removeLast(history.count - 200) }
        saveHistory()
    }

    // MARK: Clipboard watching

    @objc func poll() {
        let cc = pb.changeCount
        guard cc != lastChange else { return }
        lastChange = cc
        let types = (pb.types ?? []).map(\.rawValue)
        if types.contains(where: { Self.skipTypes.contains($0) }) { return }
        guard let text = pb.string(forType: .string), !text.isEmpty else { return }
        addHistory(text, from: "This Mac")
        if config.autoSend && !config.paused { send(text) }
    }

    func send(_ text: String, force: Bool = false) {
        guard config.isReady, let key else { lastEvent = "Not configured — open Settings"; return }
        if !force && text == lastSyncedText { return }
        guard text.utf8.count <= Self.maxBytes else { lastEvent = "Skipped: clip too large (>1 MB)"; return }
        guard let url = URL(string: "\(config.baseURL)/\(config.topic)") else { lastEvent = "Bad server URL"; return }

        let p = Payload(v: 1, from: config.deviceId, name: config.deviceName, text: text,
                        ts: (Date().timeIntervalSince1970 * 1000).rounded())
        guard let json = try? JSONEncoder().encode(p),
              let body = try? Crypto.seal(json, key: key) else { lastEvent = "Encryption failed"; return }
        lastSyncedText = text

        var req = URLRequest(url: url)
        let bytes = Data(body.utf8)
        if bytes.count > 3800 {               // ntfy message limit is 4 KB; bigger goes as an attachment
            req.httpMethod = "PUT"
            req.setValue("clip.txt", forHTTPHeaderField: "Filename")
        } else {
            req.httpMethod = "POST"
        }
        if !config.token.isEmpty { req.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization") }
        req.timeoutInterval = 30

        URLSession.shared.uploadTask(with: req, from: bytes) { [weak self] data, resp, err in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let errBody = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            DispatchQueue.main.async {
                guard let self else { return }
                if let err {
                    self.lastEvent = "Send failed: \(err.localizedDescription)"
                    self.lastSyncedText = nil
                } else if !(200...299).contains(code) {
                    self.lastEvent = "Send failed: HTTP \(code) \(preview(errBody, 50))"
                    self.lastSyncedText = nil
                } else {
                    self.lastEvent = "Sent: \(preview(text))"
                    self.flash("arrow.up.doc")
                }
            }
        }.resume()
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
            var req = URLRequest(url: url)
            if !config.token.isEmpty { req.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization") }
            URLSession.shared.dataTask(with: req) { [weak self] data, _, _ in
                guard let data, let s = String(data: data, encoding: .utf8) else { return }
                DispatchQueue.main.async { self?.handleCipher(s) }
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
        let who = p.name ?? "Phone"
        addHistory(p.text, from: who)
        let age = Date().timeIntervalSince1970 * 1000 - (p.ts ?? 0)
        guard !config.paused, age < Self.staleAfterMs else { return }   // keep old ones in history only

        lastSyncedText = p.text
        pb.clearContents()
        pb.setString(p.text, forType: .string)
        lastChange = pb.changeCount
        lastEvent = "From \(who): \(preview(p.text))"
        flash("arrow.down.doc")
    }

    // MARK: Menu

    var baseIcon: String { config.paused ? "pause.circle" : "doc.on.clipboard" }

    func setIcon(_ name: String) {
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "ClipBridge")
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
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2, execute: w)
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
            let it = item(preview(h.text, 60), #selector(copyHistory(_:)))
            it.tag = i
            it.toolTip = "\(h.from) · \(fmt.string(from: h.date))"
            if h.from != "This Mac" { it.image = NSImage(systemSymbolName: "iphone", accessibilityDescription: nil) }
            sub.addItem(it)
        }
        sub.addItem(.separator())
        sub.addItem(item("Clear History", #selector(clearHistory)))
        recent.submenu = sub
        menu.addItem(recent)
        menu.addItem(item("Send Current Clipboard to Phone", #selector(sendNow)))
        menu.addItem(.separator())

        let auto = item("Auto-send Every Copy", #selector(toggleAuto))
        auto.state = config.autoSend ? .on : .off
        menu.addItem(auto)
        let pause = item("Pause Sync", #selector(togglePause))
        pause.state = config.paused ? .on : .off
        menu.addItem(pause)
        let login = item("Open at Login", #selector(toggleLogin))
        login.state = FileManager.default.fileExists(atPath: Paths.launchAgent.path) ? .on : .off
        menu.addItem(login)
        menu.addItem(.separator())
        menu.addItem(item("Pair Phone…", #selector(pairPhone)))
        menu.addItem(item("Settings…", #selector(openSettings), key: ","))
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit ClipBridge", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
    }

    @objc func copyHistory(_ sender: NSMenuItem) {
        guard sender.tag < history.count else { return }
        pb.clearContents()
        pb.setString(history[sender.tag].text, forType: .string)
        // the poller picks this up, moves it to the top and syncs it
    }

    @objc func clearHistory() { history.removeAll(); saveHistory() }

    @objc func sendNow() {
        guard let text = pb.string(forType: .string), !text.isEmpty else { lastEvent = "Clipboard has no text"; return }
        send(text, force: true)
    }

    @objc func toggleAuto() { config.autoSend.toggle(); saveConfig() }

    @objc func togglePause() {
        config.paused.toggle()
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
        if alert.runModal() == .alertSecondButtonReturn {
            pb.clearContents()
            pb.setString(uri, forType: .string)
            lastChange = pb.changeCount   // don't sync or log the secret link
            lastEvent = "Pairing link copied"
        }
    }
}

// MARK: - Entry point

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
