package com.nfcpassport.util

object Hex {
  private const val DIGITS = "0123456789abcdef"

  fun encode(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
      val v = b.toInt() and 0xFF
      sb.append(DIGITS[v ushr 4])
      sb.append(DIGITS[v and 0x0F])
    }
    return sb.toString()
  }

  fun decode(hex: String): ByteArray {
    val clean = hex.filter { !it.isWhitespace() }
    require(clean.length % 2 == 0) { "Chuỗi hex phải có độ dài chẵn" }
    return ByteArray(clean.length / 2) {
      ((Character.digit(clean[it * 2], 16) shl 4) or Character.digit(clean[it * 2 + 1], 16)).toByte()
    }
  }
}
