package com.nfcpassport.reader

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher

/**
 * Kiểm chứng kết quả Active Authentication (ICAO 9303 Part 11 §6.1).
 *
 * JMRTD gửi lệnh INTERNAL AUTHENTICATE nhưng để việc xác minh chữ ký cho phía
 * gọi, nên phần này được cài đặt tại đây.
 *
 * - Khoá RSA: chữ ký theo ISO/IEC 9796-2 Digital Signature Scheme 1 có khôi phục
 *   một phần thông điệp. Thuật toán băm được suy ra từ byte trailer.
 * - Khoá EC: chữ ký ECDSA dạng thô `r || s` trên chính challenge.
 */
object ActiveAuthVerifier {

  /** Bảng hash-id trong trailer 2 byte của ISO/IEC 9796-2. */
  private val HASH_BY_TRAILER_ID = mapOf(
    0x31 to "RIPEMD160",
    0x32 to "RIPEMD128",
    0x33 to "SHA-1",
    0x34 to "SHA-256",
    0x35 to "SHA-512",
    0x36 to "SHA-384",
    0x38 to "SHA-224",
  )

  fun verify(publicKey: PublicKey, challenge: ByteArray, response: ByteArray): Boolean = try {
    when (publicKey) {
      is RSAPublicKey -> verifyRsa(publicKey, challenge, response)
      is ECPublicKey -> verifyEcdsa(publicKey, challenge, response)
      else -> false
    }
  } catch (e: Exception) {
    false
  }

  // ------------------------------------------------------------------- RSA

  private fun verifyRsa(publicKey: RSAPublicKey, challenge: ByteArray, response: ByteArray): Boolean {
    val cipher = Cipher.getInstance("RSA/NONE/NoPadding", BouncyCastleProvider.PROVIDER_NAME)
    cipher.init(Cipher.DECRYPT_MODE, publicKey)
    val recovered = cipher.doFinal(response)

    val modulusLength = (publicKey.modulus.bitLength() + 7) / 8
    // Kết quả RSA thô có thể mất các byte 0 ở đầu — chuẩn hoá lại độ dài.
    val f = if (recovered.size >= modulusLength) recovered
    else ByteArray(modulusLength).also {
      System.arraycopy(recovered, 0, it, modulusLength - recovered.size, recovered.size)
    }

    if (f.isEmpty()) return false
    val header = f[0].toInt() and 0xFF
    // 0x6A: khôi phục một phần; 0x4A: khôi phục toàn bộ.
    if (header != 0x6A && header != 0x4A) return false

    val lastByte = f[f.size - 1].toInt() and 0xFF
    val (digestAlgorithm, trailerLength) = when (lastByte) {
      0xBC -> "SHA-1" to 1
      0xCC -> {
        val id = f[f.size - 2].toInt() and 0xFF
        (HASH_BY_TRAILER_ID[id] ?: return false) to 2
      }
      else -> return false
    }

    val digest = MessageDigest.getInstance(digestAlgorithm)
    val digestLength = digest.digestLength
    val m1End = f.size - digestLength - trailerLength
    if (m1End <= 1) return false

    val m1 = f.copyOfRange(1, m1End)
    val expected = f.copyOfRange(m1End, m1End + digestLength)

    digest.update(m1)
    digest.update(challenge)
    return MessageDigest.isEqual(digest.digest(), expected)
  }

  // ----------------------------------------------------------------- ECDSA

  private fun verifyEcdsa(publicKey: ECPublicKey, challenge: ByteArray, response: ByteArray): Boolean {
    if (response.size % 2 != 0) return false
    val half = response.size / 2
    val r = BigInteger(1, response.copyOfRange(0, half))
    val s = BigInteger(1, response.copyOfRange(half, response.size))
    val der = DERSequence(ASN1EncodableVector().apply {
      add(ASN1Integer(r))
      add(ASN1Integer(s))
    }).encoded

    // ICAO không cố định hàm băm cho AA-ECDSA; thử các lựa chọn phổ biến.
    for (algorithm in listOf("SHA256withECDSA", "SHA1withECDSA", "SHA384withECDSA", "SHA512withECDSA")) {
      val verified = try {
        Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).run {
          initVerify(publicKey)
          update(challenge)
          verify(der)
        }
      } catch (e: Exception) {
        false
      }
      if (verified) return true
    }
    return false
  }
}
