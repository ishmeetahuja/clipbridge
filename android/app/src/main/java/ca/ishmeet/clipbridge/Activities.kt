package ca.ishmeet.clipbridge

import android.Manifest
import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast

private fun Context.clipboardText(): String {
    val cm = getSystemService(ClipboardManager::class.java)
    val clip = cm.primaryClip ?: return ""
    if (clip.itemCount == 0) return ""
    return clip.getItemAt(0).coerceToText(this)?.toString() ?: ""
}

/** The clipboard's image URI, if it currently holds an image. */
private fun Context.clipboardImageUri(): Uri? {
    val clip = getSystemService(ClipboardManager::class.java).primaryClip ?: return null
    if (clip.itemCount == 0) return null
    val uri = clip.getItemAt(0).uri ?: return null
    val isImage = clip.description.hasMimeType("image/*") ||
        (try { contentResolver.getType(uri) } catch (e: Exception) { null })?.startsWith("image/") == true
    return if (isImage) uri else null
}

@Suppress("DEPRECATION")
private fun Intent.streamUri(): Uri? =
    if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
    else getParcelableExtra(Intent.EXTRA_STREAM)

// ---------------------------------------------------------------- Main screen

class MainActivity : Activity() {
    private lateinit var server: EditText
    private lateinit var topic: EditText
    private lateinit var pass: EditText
    private lateinit var token: EditText
    private lateinit var name: EditText
    private lateinit var status: TextView
    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            status.text = if (SyncService.running) SyncService.status else "Sync is off"
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        server = findViewById(R.id.server)
        topic = findViewById(R.id.topic)
        pass = findViewById(R.id.pass)
        token = findViewById(R.id.token)
        name = findViewById(R.id.name)
        status = findViewById(R.id.status)

        val cfg = Config.load(this)
        server.setText(cfg.server)
        topic.setText(cfg.topic)
        pass.setText(Config.passphrase(this))
        token.setText(cfg.token)
        name.setText(Config.name(this))

        findViewById<Button>(R.id.btnSave).setOnClickListener { saveAndConnect() }
        findViewById<Button>(R.id.btnPastePair).setOnClickListener {
            val t = clipboardText().trim()
            if (!t.startsWith("clipbridge://") || !applyPairing(Uri.parse(t))) {
                toast("Clipboard doesn't contain a ClipBridge pairing link")
            }
        }
        findViewById<Button>(R.id.btnSend).setOnClickListener {
            val img = clipboardImageUri()
            if (img != null) Sender.sendImage(this, img) { toast(it) }
            else Sender.send(this, clipboardText()) { toast(it) }
        }
        findViewById<Button>(R.id.btnBattery).setOnClickListener { requestUnrestricted() }
        findViewById<CheckBox>(R.id.saveImages).apply {
            isChecked = Config.saveImages(this@MainActivity)
            setOnCheckedChangeListener { _, on -> Config.setSaveImages(this@MainActivity, on) }
        }
        findViewById<Button>(R.id.btnStop).setOnClickListener {
            SyncService.stop(this)
            toast("Sync stopped")
        }

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }

        if (!handlePairIntent(intent) && Config.isEnabled(this) && cfg.ready) {
            SyncService.start(this)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handlePairIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        ui.post(tick)
    }

    override fun onPause() {
        ui.removeCallbacks(tick)
        super.onPause()
    }

    private fun handlePairIntent(i: Intent?): Boolean {
        if (i == null || i.action != Intent.ACTION_VIEW) return false
        val data = i.data ?: return false
        return applyPairing(data)
    }

    private fun applyPairing(u: Uri): Boolean {
        if (u.scheme != "clipbridge") return false
        val s = u.getQueryParameter("server")
        val t = u.getQueryParameter("topic")
        val p = u.getQueryParameter("pass")
        if (s.isNullOrBlank() || t.isNullOrBlank() || p.isNullOrBlank()) return false
        server.setText(s)
        topic.setText(t)
        pass.setText(p)
        token.setText(u.getQueryParameter("token") ?: "")
        saveAndConnect()
        return true
    }

    private fun saveAndConnect() {
        val s = server.text.toString()
        val t = topic.text.toString()
        val p = pass.text.toString()
        val k = token.text.toString()
        val n = name.text.toString()
        if (s.isBlank() || t.isBlank() || p.isBlank()) {
            toast("Server, topic and passphrase are required")
            return
        }
        status.text = "Deriving encryption key…"
        Thread {
            Config.save(this, s, t, p, k, n)
            runOnUiThread {
                SyncService.restart(this)
                toast("Paired — syncing with your Mac")
            }
        }.start()
    }

    private fun requestUnrestricted() {
        val pm = getSystemService(PowerManager::class.java)
        if (pm.isIgnoringBatteryOptimizations(packageName)) {
            toast("Already unrestricted 👍")
            return
        }
        try {
            startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
            )
        } catch (e: Exception) {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}

// ---------------------------------------------------------------- Share sheet target

class ShareActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val done: (String) -> Unit = { msg ->
            Toast.makeText(applicationContext, msg, Toast.LENGTH_SHORT).show()
            finish()
        }
        val image = intent?.takeIf { it.type?.startsWith("image/") == true }?.streamUri()
        if (image != null) {
            Sender.sendImage(this, image, done)
        } else {
            Sender.send(this, intent?.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString() ?: "", done)
        }
    }
}

// ---------------------------------------------------------------- Clipboard reader (tile + notification button)

/** Android only lets the focused app read the clipboard, so we briefly become focused (invisibly). */
class SendClipboardActivity : Activity() {
    private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.decorView.postDelayed({ if (!done) finish() }, 5000)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || done) return
        done = true
        val done: (String) -> Unit = { msg ->
            Toast.makeText(applicationContext, msg, Toast.LENGTH_SHORT).show()
            finish()
        }
        val img = clipboardImageUri()
        if (img != null) Sender.sendImage(this, img, done) else Sender.send(this, clipboardText(), done)
    }
}

// ---------------------------------------------------------------- Quick Settings tile

class ClipTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        qsTile?.let {
            it.state = Tile.STATE_ACTIVE
            it.label = "Send to Mac"
            it.updateTile()
        }
    }

    @Suppress("DEPRECATION")
    override fun onClick() {
        super.onClick()
        val i = Intent(this, SendClipboardActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE))
        } else {
            startActivityAndCollapse(i)
        }
    }
}

// ---------------------------------------------------------------- Auto-start after reboot / update

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Config.isEnabled(context) && Config.load(context).ready) {
            try {
                context.startForegroundService(Intent(context, SyncService::class.java))
            } catch (_: Exception) {
            }
        }
    }
}
