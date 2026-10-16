package ca.ishmeet.clipbridge

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import android.provider.OpenableColumns
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException

object Images {
    const val MAX_BYTES = 14_000_000

    fun ext(mime: String) = when (mime) {
        "image/jpeg", "image/jpg" -> "jpg"
        "image/heic", "image/heif" -> "heic"
        "image/gif" -> "gif"
        "image/webp" -> "webp"
        "image/tiff" -> "tiff"
        else -> "png"
    }

    fun mimeForName(name: String) = when (name.substringAfterLast('.', "").lowercase()) {
        "jpg", "jpeg" -> "image/jpeg"
        "heic", "heif" -> "image/heic"
        "gif" -> "image/gif"
        "webp" -> "image/webp"
        "tiff" -> "image/tiff"
        else -> "image/png"
    }

    /** Saves into Pictures/ClipBridge so it shows up in the Gallery (Android 10+). */
    fun saveToGallery(ctx: Context, data: ByteArray, mime: String, displayName: String): Uri? {
        if (Build.VERSION.SDK_INT < 29) return null
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/ClipBridge")
        }
        val uri = ctx.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values) ?: return null
        ctx.contentResolver.openOutputStream(uri)?.use { it.write(data) }
        return uri
    }

    /** Keeps a private copy and returns a content:// URI other apps can paste from. */
    fun cacheForClipboard(ctx: Context, data: ByteArray, mime: String): Uri {
        val dir = File(ctx.cacheDir, ClipProvider.DIR).apply { mkdirs() }
        dir.listFiles()?.sortedByDescending { it.lastModified() }?.drop(4)?.forEach { it.delete() }
        val f = File(dir, "clip-${System.currentTimeMillis()}.${ext(mime)}")
        f.writeBytes(data)
        return Uri.parse("content://${ClipProvider.AUTHORITY}/${f.name}")
    }

    /** Small bitmap for the notification preview. */
    fun previewBitmap(data: ByteArray, maxSide: Int = 1024): Bitmap? = try {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(data, 0, data.size, bounds)
        var sample = 1
        while (bounds.outWidth / sample > maxSide || bounds.outHeight / sample > maxSide) sample *= 2
        BitmapFactory.decodeByteArray(data, 0, data.size, BitmapFactory.Options().apply { inSampleSize = sample })
    } catch (e: Throwable) {
        null
    }

    /** Re-encode a huge image as JPEG (max 4096px side) so it fits the size limit. */
    fun toJpeg(data: ByteArray): ByteArray? {
        val bmp = previewBitmap(data, 4096) ?: return null
        val out = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.JPEG, 85, out)
        bmp.recycle()
        return out.toByteArray()
    }
}

/**
 * Serves received images from our cache so they can sit on the clipboard.
 * Not exported: the clipboard grants read access to whichever app pastes.
 */
class ClipProvider : ContentProvider() {
    companion object {
        const val AUTHORITY = "ca.ishmeet.clipbridge.clips"
        const val DIR = "clips"
    }

    private fun fileFor(uri: Uri): File {
        val name = uri.lastPathSegment ?: throw FileNotFoundException("no name")
        if (name.contains('/') || name.startsWith(".")) throw FileNotFoundException("bad name")
        val f = File(File(context!!.cacheDir, DIR), name)
        if (!f.exists()) throw FileNotFoundException(name)
        return f
    }

    override fun onCreate() = true

    override fun getType(uri: Uri): String = Images.mimeForName(uri.lastPathSegment ?: "")

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor =
        ParcelFileDescriptor.open(fileFor(uri), ParcelFileDescriptor.MODE_READ_ONLY)

    override fun query(
        uri: Uri, projection: Array<String>?, selection: String?,
        selectionArgs: Array<String>?, sortOrder: String?
    ): Cursor {
        val f = fileFor(uri)
        val cols = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(cols, 1).apply { addRow(arrayOf<Any>(f.name, f.length())) }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?) = 0
}
