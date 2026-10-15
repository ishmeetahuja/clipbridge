package ca.ishmeet.clipbridge

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Foreground service that keeps a streaming connection to ntfy open and writes
 * incoming (decrypted) clips straight onto the Android clipboard.
 */
class SyncService : Service() {

    companion object {
        private const val CHANNEL = "sync"
        private const val NOTIF_ID = 1
        private const val ACTION_RESTART = "ca.ishmeet.clipbridge.RESTART"
        private const val STALE_MS = 5 * 60 * 1000L

        @Volatile var status: String = "Stopped"
        @Volatile var running: Boolean = false
            private set

        fun start(ctx: Context) {
            Config.setEnabled(ctx, true)
            ctx.startForegroundService(Intent(ctx, SyncService::class.java))
        }

        fun restart(ctx: Context) {
            Config.setEnabled(ctx, true)
            ctx.startForegroundService(Intent(ctx, SyncService::class.java).setAction(ACTION_RESTART))
        }

        fun stop(ctx: Context) {
            Config.setEnabled(ctx, false)
            ctx.stopService(Intent(ctx, SyncService::class.java))
        }
    }

    @Volatile private var conn: HttpURLConnection? = null
    @Volatile private var lastId: String? = null
    private var worker: Thread? = null
    private val main = Handler(Looper.getMainLooper())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createChannel()
        val n = buildNotification(status.takeIf { running } ?: "Starting…")
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
        if (intent?.action == ACTION_RESTART) {
            lastId = null
            dropConnection()
            worker?.interrupt()    // wakes it if it's sleeping between retries
        }
        if (!running) {
            running = true
            worker = Thread({ loop() }, "clipbridge-stream").also { it.start() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        dropConnection()
        worker?.interrupt()
        status = "Stopped"
        super.onDestroy()
    }

    private fun dropConnection() {
        val c = conn ?: return
        Thread { try { c.disconnect() } catch (_: Exception) {} }.start()
    }

    // ------------------------------------------------------------ stream loop

    private fun loop() {
        var backoff = 2_000L
        while (running) {
            val cfg = Config.load(this)
            if (!cfg.ready) {
                setStatus("Not paired yet — open ClipBridge")
                if (!nap(15_000)) break
                continue
            }
            try {
                val q = lastId?.let { "?since=$it" } ?: ""
                val c = URL("${cfg.base}/${cfg.topic}/json$q").openConnection() as HttpURLConnection
                c.connectTimeout = 15_000
                c.readTimeout = 100_000     // ntfy sends a keepalive every ~45s
                Ntfy.auth(c, cfg)
                conn = c
                val code = c.responseCode
                if (code != 200) throw IOException("server returned HTTP $code")
                setStatus("Connected · ${hostOf(cfg.base)} · waiting for clips")
                backoff = 2_000L
                c.inputStream.bufferedReader().use { r ->
                    while (running) {
                        val line = r.readLine() ?: break
                        if (line.isNotBlank()) handleLine(cfg, line)
                    }
                }
                if (running) setStatus("Disconnected — reconnecting…")
            } catch (e: Exception) {
                if (!running) break
                setStatus("Reconnecting… (${e.message ?: e.javaClass.simpleName})")
            } finally {
                try { conn?.disconnect() } catch (_: Exception) {}
                conn = null
            }
            if (!nap(backoff)) break
            backoff = (backoff * 2).coerceAtMost(60_000L)
        }
    }

    /** Sleep; returns false if the service is shutting down. Interrupts just cut the sleep short. */
    private fun nap(ms: Long): Boolean {
        try { Thread.sleep(ms) } catch (_: InterruptedException) {}
        return running
    }

    private fun handleLine(cfg: Cfg, line: String) {
        val o = try { JSONObject(line) } catch (e: Exception) { return }
        if (o.optString("event") != "message") return
        val id = o.optString("id")
        if (id.isNotEmpty()) lastId = id

        val att = o.optJSONObject("attachment")
        val cipher = if (att != null && att.optString("url").isNotEmpty()) {
            try { Ntfy.download(cfg, att.getString("url")) } catch (e: Exception) { return }
        } else {
            o.optString("message")
        }
        val clip = Payload.decode(cfg, cipher) ?: return
        if (clip.from == cfg.deviceId) return                                  // our own echo
        if (System.currentTimeMillis() - clip.ts > STALE_MS) return            // old, don't clobber

        main.post {
            val cm = getSystemService(ClipboardManager::class.java)
            cm.setPrimaryClip(ClipData.newPlainText("From ${clip.name}", clip.text))
            setStatus("From ${clip.name}: ${preview(clip.text)}")
        }
    }

    // ------------------------------------------------------------ notification

    private fun hostOf(url: String) = try { URL(url).host } catch (e: Exception) { url }

    private fun setStatus(s: String) {
        status = s
        if (!running) return
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(s))
    }

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            val ch = NotificationChannel(CHANNEL, "Clipboard sync", NotificationManager.IMPORTANCE_LOW)
            ch.description = "Shows ClipBridge connection status"
            ch.setShowBadge(false)
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val send = PendingIntent.getActivity(
            this, 1,
            Intent(this, SendClipboardActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE
        )
        val icon = Icon.createWithResource(this, R.drawable.ic_stat_clip)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_clip)
            .setContentTitle("ClipBridge")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(icon, "Send clipboard to Mac", send).build())
            .build()
    }
}
