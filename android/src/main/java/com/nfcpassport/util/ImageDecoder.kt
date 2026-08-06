package com.nfcpassport.util

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import com.gemalto.jp2.JP2Decoder
import java.io.ByteArrayOutputStream

/**
 * Giải mã ảnh sinh trắc trong DG2/DG5/DG7.
 *
 * DG2 của eMRTD (ISO/IEC 19794-5) thường chứa JPEG 2000 — Android không có
 * decoder sẵn nên dùng OpenJPEG qua `com.gemalto.jp2`. Kết quả luôn được
 * transcode sang JPEG để React Native hiển thị được bằng `<Image>`.
 */
object ImageDecoder {

  data class DecodedImage(
    val base64: String,
    val mimeType: String,
    val width: Int,
    val height: Int,
    val transcoded: Boolean,
  )

  private const val JPEG_QUALITY = 90

  fun decode(bytes: ByteArray, declaredMimeType: String?, fallbackWidth: Int, fallbackHeight: Int): DecodedImage {
    val mime = (declaredMimeType ?: sniffMimeType(bytes)).lowercase()

    val bitmap: Bitmap? = try {
      when {
        mime.contains("jp2") || mime.contains("jpeg2000") || isJpeg2000(bytes) ->
          JP2Decoder(bytes).decode()
        else -> BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
      }
    } catch (e: Throwable) {
      // JP2Decoder có thể ném UnsatisfiedLinkError trên ABI không hỗ trợ.
      null
    }

    if (bitmap == null) {
      // Không decode được: trả bytes gốc để ứng dụng tự xử lý.
      return DecodedImage(
        base64 = Base64.encodeToString(bytes, Base64.NO_WRAP),
        mimeType = if (mime.isBlank()) "application/octet-stream" else mime,
        width = fallbackWidth,
        height = fallbackHeight,
        transcoded = false,
      )
    }

    val out = ByteArrayOutputStream(bytes.size)
    bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, out)
    val width = bitmap.width
    val height = bitmap.height
    bitmap.recycle()

    return DecodedImage(
      base64 = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP),
      mimeType = "image/jpeg",
      width = width,
      height = height,
      transcoded = true,
    )
  }

  /** Nhận diện JPEG 2000 qua signature box (JP2) hoặc SOC marker (codestream J2K). */
  private fun isJpeg2000(bytes: ByteArray): Boolean {
    if (bytes.size < 12) return false
    val jp2Signature = byteArrayOf(
      0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87.toByte(), 0x0A
    )
    if (bytes.copyOfRange(0, 12).contentEquals(jp2Signature)) return true
    // Raw codestream: FF 4F FF 51
    return (bytes[0].toInt() and 0xFF) == 0xFF && (bytes[1].toInt() and 0xFF) == 0x4F &&
      (bytes[2].toInt() and 0xFF) == 0xFF && (bytes[3].toInt() and 0xFF) == 0x51
  }

  private fun sniffMimeType(bytes: ByteArray): String = when {
    bytes.size >= 3 && (bytes[0].toInt() and 0xFF) == 0xFF &&
      (bytes[1].toInt() and 0xFF) == 0xD8 -> "image/jpeg"
    isJpeg2000(bytes) -> "image/jp2"
    bytes.size >= 8 && (bytes[0].toInt() and 0xFF) == 0x89 &&
      bytes[1].toInt().toChar() == 'P' -> "image/png"
    else -> ""
  }
}
