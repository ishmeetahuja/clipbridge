# ClipBridge — Mac ⇄ Android clipboard sync

Copy text on your Mac and paste it on your phone a second or two later. Send text from your phone back to the Mac. The Mac also keeps a history of everything you copy.

```
Mac (menu-bar app) ──encrypted──▶  ntfy server  ──encrypted──▶  Android (background service)
        ▲                                                                    │
        └──────────── Share / Quick-Settings tile / notification button ─────┘
```

- **Transport:** [ntfy](https://ntfy.sh). It uses the free public server by default, and you can self-host it later (see `server/`).
- **Encryption:** AES-256-GCM, with the key derived from a shared passphrase using PBKDF2-SHA256 (200k rounds). The server only ever sees ciphertext.
- **Passwords:** the Mac skips anything your password manager marks as concealed (1Password, Bitwarden and others).
- **Content:** text only, up to 1 MB per clip.

---

## ⚡ Quick install (prebuilt)

Every push to `main` builds both apps and publishes them under this repo's **Releases** (right-hand sidebar on GitHub).

- **Android:** on your phone, open the latest Release, download **ClipBridge.apk**, and install it. Allow "install unknown apps" when prompted. Then follow **Pair it** below.
- **Mac:** download **ClipBridge-mac.zip**, unzip it, drag **ClipBridge.app** into Applications, and run once in Terminal:
  ```bash
  xattr -dr com.apple.quarantine /Applications/ClipBridge.app && open /Applications/ClipBridge.app
  ```
  The `xattr` command is needed because the app isn't notarized by Apple. Without it, macOS says the app "is damaged".

If you'd rather build from source, follow the sections below.

---

## 1. Mac (about 3 minutes)

1. If you've never installed Apple's developer tools, open Terminal and run `xcode-select --install`.
2. In Terminal:
   ```bash
   cd ~/Downloads/ClipBridge/mac      # wherever you unzipped it
   chmod +x build.sh
   ./build.sh
   ```
   This builds `ClipBridge.app`, installs it in `~/Applications`, and launches it.
3. A **clipboard icon** appears in your menu bar.
   - On first launch, ClipBridge makes a random private topic and passphrase and shows a **pairing QR code**. Leave that window open for step 2.
4. If macOS asks whether ClipBridge may **paste from other apps**, choose **Allow**. Without that, it can't see what you copy.
5. Optional: menu-bar icon → **Open at Login**.

## 2. Android

### Build the APK (pick one)

**Option A: Android Studio**
1. Install [Android Studio](https://developer.android.com/studio).
2. **File → Open** the `ClipBridge/android` folder and wait for the Gradle sync to finish. The first time takes a few minutes. Accept any SDK prompts.
3. Install the app on your phone in one of two ways:
   - **Over USB:** turn on Developer options → USB debugging on the phone, plug it in, and press **Run ▶**.
   - **As a file:** choose **Build → Build App Bundle(s)/APK(s) → Build APK(s)**, then **locate** `app-debug.apk`. Copy it to the phone and open it. Allow "install unknown apps" when asked.

**Option B: GitHub (no Android Studio)**
1. Push the whole `ClipBridge` folder to a private GitHub repo.
2. Go to the **Actions** tab, open the latest run, and download **ClipBridge-apk** from Artifacts.
3. Install the APK on the phone.

### Pair it
1. Open **ClipBridge** on the phone and allow notifications.
2. Use the phone camera to **scan the QR code** on the Mac and tap the link. The app fills in the settings and starts syncing.
   - If your camera only shows the text, copy that text and tap **Paste pairing link** in the app.
   - You can also copy the link on the Mac with **Pair Phone… → Copy Pairing Link** and send it to yourself, for example by email.
3. Tap **Let it run in background (battery)** and allow it. Otherwise Android may kill the connection when the screen is off.
4. Optional: pull down Quick Settings → edit (✏️) → drag the **Send to Mac** tile in.

The notification should say **Connected · ntfy.sh · waiting for clips**.

## 3. Using it

| You want to… | Do this |
|---|---|
| Mac → phone | Just copy (⌘C) on the Mac. Paste on the phone a moment later. |
| Phone → Mac | Select text → **Share → Send to Mac**, *or* copy it and tap the **Send to Mac** tile, *or* tap **Send clipboard to Mac** in the ClipBridge notification. Then ⌘V on the Mac. |
| Find something you copied earlier | Menu-bar icon → **Recent Clips** → click an item to copy it again. A 📱 icon means it came from the phone. |
| Temporarily stop syncing | Menu-bar icon → **Pause Sync**, or turn off **Auto-send Every Copy** to only send manually. |

The menu-bar icon briefly shows ↑ when a clip is sent and ↓ when one arrives.

## Troubleshooting

- **The Mac menu says "Connecting…" forever.** Check your internet connection and the Server URL under Settings.
- **The phone shows "Reconnecting… (HTTP 403/401)".** The server needs an access token. Put the same token in both apps.
- **Nothing arrives on the phone with the screen off.** Do step 2.3 (battery). On Samsung, also go to Settings → Battery → Background usage limits → **Never sleeping apps** and add ClipBridge.
- **Nothing arrives at all.** The topic and passphrase must match *exactly* on both devices. Re-pair with the QR code to be sure.
- **Long clips (> ~2.8 KB) don't sync on a self-hosted server.** Turn on attachments (`NTFY_ATTACHMENT_CACHE_DIR`, already set in `server/docker-compose.yml`).
- **Clips sent while a device was asleep didn't land on its clipboard.** By design, a clip older than 5 minutes is added to the Mac's history but not put on the clipboard, so a stale clip never overwrites what you have now.

## Self-hosting ntfy (optional)

See `server/docker-compose.yml`. Run it on your server, then change **Server** in both apps (Mac: **Settings…**; phone: main screen) to your URL. Use **Pair Phone…** again so both sides match.

## Security notes

- The **topic is random and the content is encrypted**. Someone who guessed the topic would only see ciphertext and couldn't inject clips, because messages that fail decryption are ignored.
- The passphrase is stored in `~/Library/Application Support/ClipBridge/config.json` with permissions 0600, and in the app's private storage on Android.
- Clipboard history is stored locally in `~/Library/Application Support/ClipBridge/history.json` (0600, last 200 items). Use **Recent Clips → Clear History** to wipe it.
- To rotate keys, go to Settings → **New Random Topic & Passphrase**, then re-pair the phone.

## Files

```
mac/        Swift menu-bar app (Package.swift, Sources/, build.sh, Info.plist)
android/    Kotlin app, no third-party dependencies (open this folder in Android Studio)
server/     Optional docker-compose for self-hosted ntfy
.github/    Optional GitHub Actions workflow that builds the APK
```
