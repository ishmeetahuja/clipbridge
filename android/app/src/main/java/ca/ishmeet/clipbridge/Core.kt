package ca.ishmeet.clipbridge

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ---------------------------------------------------------------- Config

data class Cfg(
    val server: String,
    val topic: String,
    val token: String,
    val key: ByteArray?,
    val deviceId: String,
    val deviceName: String,
) {
    val ready: Boolean get() = server.isNotBlank() && topic.isNotBlank() && key != null
    val base: String get() = server.trim().trimEnd('/')
}

object Config {
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("clipbridge", Context.MODE_PRIVATE)

    fun load(ctx: Context): Cfg {
        val p = prefs(ctx)
        var id = p.getString("deviceId", null)
        if (id == null) {
            id = UUID.randomUUID().toString()
            p.edit().putString("deviceId", id).apply()
        }
        val key = p.getString("key", null)?.let { Base64.decode(it, Base64.NO_WRAP) }
        val name = p.getString("name", null)?.takeIf { it.isNotBlank() } ?: Build.MODEL ?: "Android"
        return Cfg(
            server = p.getString("server", "https://ntfy.sh") ?: "https://ntfy.sh",
            topic = p.getString("topic", "") ?: "",
            token = p.getString("token", "") ?: "",
            key = key,
            deviceId = id,
            deviceName = name,
        )
    }

    fun passphrase(ctx: Context): String = prefs(ctx).getString("pass", "") ?: ""
    fun name(ctx: Context): String = prefs(ctx).getString("name", "") ?: ""

    /** Slow (PBKDF2, ~1s) — call off the main thread. */
    fun save(ctx: Context, server: String, topic: String, passphrase: String, token: String, name: String) {
        val t = topic.trim()
        val pass = passphrase.trim()
        val key = Crypto.deriveKey(pass, t)
        prefs(ctx).edit()
            .putString("server", server.trim().trimEnd('/'))
            .putString("topic", t)
            .putString("pass", pass)
            .putString("token", token.trim())
            .putString("name", name.trim())
            .putString("key", Base64.encodeToString(key, Base64.NO_WRAP))
            .commit()
    }

    fun saveImages(ctx: Context) = prefs(ctx).getBoolean("saveImages", true)
    fun setSaveImages(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean("saveImages", on).apply()

    fun isEnabled(ctx: Context) = prefs(ctx).getBoolean("enabled", false)
    fun setEnabled(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean("enabled", on).apply()
}

// ---------------------------------------------------------------- Crypto (must match the Mac app)

object Crypto {
    private const val ITERATIONS = 200_000
    private val rng = SecureRandom()

    /** PBKDF2-HMAC-SHA256(passphrase, "clipbridge:" + topic, 200k) -> 32-byte key */
    fun deriveKey(passphrase: String, topic: String): ByteArray =
        pbkdf2(passphrase.toByteArray(Charsets.UTF_8), "clipbridge:$topic".toByteArray(Charsets.UTF_8), ITERATIONS, 32)

    private fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val hLen = 32
        val blocks = (length + hLen - 1) / hLen
        val out = ByteArray(length)
        for (i in 1..blocks) {
            mac.update(salt)
            mac.update(byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (j in 2..iterations) {
                u = mac.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            val off = (i - 1) * hLen
            System.arraycopy(t, 0, out, off, minOf(hLen, length - off))
        }
        return out
    }

    /** nonce[12] || ciphertext || tag[16] — same layout as CryptoKit's AES.GCM combined */
    fun sealRaw(plain: ByteArray, key: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return nonce + c.doFinal(plain)
    }

    fun openRaw(d: ByteArray, key: ByteArray): ByteArray {
        require(d.size >= 28) { "too short" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, d, 0, 12))
        return c.doFinal(d, 12, d.size - 12)
    }

    fun seal(plain: ByteArray, key: ByteArray): String =
        Base64.encodeToString(sealRaw(plain, key), Base64.NO_WRAP)

    fun open(b64: String, key: ByteArray): ByteArray =
        openRaw(Base64.decode(b64.trim(), Base64.DEFAULT), key)
}

// ---------------------------------------------------------------- Payload

data class Clip(val from: String, val name: String, val text: String, val ts: Long)

object Payload {
    fun encode(cfg: Cfg, text: String): String {
        val o = JSONObject()
            .put("v", 1)
            .put("from", cfg.deviceId)
            .put("name", cfg.deviceName)
            .put("text", text)
            .put("ts", System.currentTimeMillis())
        return Crypto.seal(o.toString().toByteArray(Charsets.UTF_8), cfg.key!!)
    }

    /** null if it isn't ours (wrong passphrase / junk on the topic). */
    fun decode(cfg: Cfg, cipher: String): Clip? = try {
        val o = JSONObject(String(Crypto.open(cipher, cfg.key!!), Charsets.UTF_8))
        Clip(o.getString("from"), o.optString("name", "Mac"), o.getString("text"), o.optLong("ts", 0L))
    } catch (e: Exception) {
        null
    }
}

// ---------------------------------------------------------------- Binary blobs (images)
// sealRaw( u32be(headerLen) || header JSON || image bytes ), sent as an ntfy attachment "clip.cbin"

class ImageBlob(val from: String, val name: String, val ts: Long, val mime: String, val data: ByteArray)

object BlobCodec {
    const val FILENAME = "clip.cbin"

    fun encodeImage(cfg: Cfg, mime: String, data: ByteArray): ByteArray {
        val h = JSONObject()
            .put("v", 2)
            .put("type", "image")
            .put("from", cfg.deviceId)
            .put("name", cfg.deviceName)
            .put("ts", System.currentTimeMillis())
            .put("mime", mime)
            .toString().toByteArray(Charsets.UTF_8)
        val plain = ByteArray(4 + h.size + data.size)
        ByteBuffer.wrap(plain).putInt(h.size).put(h).put(data)
        return Crypto.sealRaw(plain, cfg.key!!)
    }

    fun decode(cfg: Cfg, bytes: ByteArray): ImageBlob? = try {
        val p = Crypto.openRaw(bytes, cfg.key!!)
        val len = ByteBuffer.wrap(p, 0, 4).int
        require(len > 0 && 4 + len <= p.size)
        val h = JSONObject(String(p, 4, len, Charsets.UTF_8))
        if (h.optString("type") != "image") null
        else ImageBlob(
            h.getString("from"), h.optString("name", "Mac"), h.optLong("ts", 0L),
            h.optString("mime", "image/png"), p.copyOfRange(4 + len, p.size)
        )
    } catch (e: Exception) {
        null
    }
}

// ---------------------------------------------------------------- ntfy HTTP

object Ntfy {
    fun auth(c: HttpURLConnection, cfg: Cfg) {
        if (cfg.token.isNotBlank()) c.setRequestProperty("Authorization", "Bearer ${cfg.token}")
    }

    fun publish(cfg: Cfg, body: String) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        // ntfy's message limit is 4 KB; bigger goes as an attachment
        publishBytes(cfg, bytes, if (bytes.size > 3800) "clip.txt" else null)
    }

    fun publishBytes(cfg: Cfg, bytes: ByteArray, filename: String?) {
        val c = URL("${cfg.base}/${cfg.topic}").openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 15_000
            c.readTimeout = 120_000
            c.doOutput = true
            if (filename != null) {
                c.requestMethod = "PUT"
                c.setRequestProperty("Filename", filename)
            } else {
                c.requestMethod = "POST"
            }
            auth(c, cfg)
            c.setFixedLengthStreamingMode(bytes.size)
            c.outputStream.use { it.write(bytes) }
            val code = c.responseCode
            if (code !in 200..299) {
                val err = try { c.errorStream?.bufferedReader()?.readText() ?: "" } catch (e: Exception) { "" }
                throw IOException("HTTP $code ${err.take(120)}".trim())
            }
        } finally {
            c.disconnect()
        }
    }

    fun download(cfg: Cfg, url: String): String = String(downloadBytes(cfg, url), Charsets.UTF_8)

    fun downloadBytes(cfg: Cfg, url: String): ByteArray {
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 15_000
            c.readTimeout = 120_000
            auth(c, cfg)
            if (c.responseCode != 200) throw IOException("HTTP ${c.responseCode}")
            return c.inputStream.use { it.readBytes() }
        } finally {
            c.disconnect()
        }
    }
}

// ---------------------------------------------------------------- Sending

object Sender {
    private val main = Handler(Looper.getMainLooper())

    fun send(ctx: Context, text: String, done: (String) -> Unit) {
        val app = ctx.applicationContext
        Thread {
            val msg = try {
                val cfg = Config.load(app)
                when {
                    !cfg.ready -> "ClipBridge isn't paired yet — open the app"
                    text.isEmpty() -> "Clipboard is empty"
                    text.toByteArray().size > 1_000_000 -> "Too large (max 1 MB)"
                    else -> {
                        Ntfy.publish(cfg, Payload.encode(cfg, text))
                        SyncService.status = "Sent: ${preview(text)}"
                        "Sent to Mac ✓"
                    }
                }
            } catch (e: Exception) {
                "Send failed: ${e.message}"
            }
            main.post { done(msg) }
        }.start()
    }

    fun sendImage(ctx: Context, uri: Uri, done: (String) -> Unit) {
        val app = ctx.applicationContext
        // Read on the caller's side of the permission grant, then upload in the background.
        Thread {
            val msg = try {
                val cfg = Config.load(app)
                if (!cfg.ready) {
                    "ClipBridge isn't paired yet — open the app"
                } else {
                    var mime = app.contentResolver.getType(uri)?.takeIf { it.startsWith("image/") } ?: "image/png"
                    var data = app.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IOException("Couldn't read the image")
                    if (data.size > Images.MAX_BYTES) {
                        data = Images.toJpeg(data) ?: data
                        mime = "image/jpeg"
                    }
                    if (data.size > Images.MAX_BYTES) {
                        "Image too large (max 14 MB)"
                    } else {
                        Ntfy.publishBytes(cfg, BlobCodec.encodeImage(cfg, mime, data), BlobCodec.FILENAME)
                        SyncService.status = "Sent image (${data.size / 1024} KB)"
                        "Image sent to Mac ✓"
                    }
                }
            } catch (e: Exception) {
                "Send failed: ${e.message}"
            }
            main.post { done(msg) }
        }.start()
    }
}

fun preview(s: String, n: Int = 40): String {
    val one = s.replace('\n', ' ').trim()
    return if (one.length > n) one.take(n) + "…" else one
}
