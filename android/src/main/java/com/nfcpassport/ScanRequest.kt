package com.nfcpassport

import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType

/** Tuỳ chọn của một phiên quét, đã chuẩn hoá từ payload JavaScript. */
data class ScanRequest(
  val useCan: Boolean,
  val can: String,
  val documentNumber: String,
  val dateOfBirth: String,
  val dateOfExpiry: String,
  val dataGroups: Set<String>,
  val usePace: Boolean,
  val allowBacFallback: Boolean,
  val chipAuthentication: Boolean,
  val activeAuthentication: Boolean,
  val passiveAuthentication: Boolean,
  val cscaCertificates: List<String>,
  val includeImages: Boolean,
  val includeRawData: Boolean,
  val timeoutMs: Long,
) {
  companion object {
    private val DEFAULT_DATA_GROUPS = setOf("DG1", "DG2", "DG13", "DG14", "DG15")

    fun from(options: ReadableMap?): ScanRequest {
      if (options == null) {
        throw NfcPassportException(ErrorCode.INVALID_ARGUMENT, "Thiếu tham số scan")
      }

      val accessKey = options.getMap("accessKey")
        ?: throw NfcPassportException(ErrorCode.INVALID_ARGUMENT, "Thiếu `accessKey`")

      val type = accessKey.getStringOr("type", "mrz")
      val useCan = type == "can"

      val can = accessKey.getStringOr("can", "")
      val documentNumber = accessKey.getStringOr("documentNumber", "")
      val dateOfBirth = accessKey.getStringOr("dateOfBirth", "")
      val dateOfExpiry = accessKey.getStringOr("dateOfExpiry", "")

      if (useCan) {
        if (can.length != 6) {
          throw NfcPassportException(ErrorCode.INVALID_ARGUMENT, "CAN phải gồm 6 chữ số")
        }
      } else {
        if (documentNumber.isEmpty() || dateOfBirth.length != 6 || dateOfExpiry.length != 6) {
          throw NfcPassportException(
            ErrorCode.INVALID_ARGUMENT,
            "MRZ không hợp lệ: cần documentNumber, dateOfBirth (YYMMDD), dateOfExpiry (YYMMDD)"
          )
        }
      }

      val dataGroups = options.getArray("dataGroups")?.let { array ->
        (0 until array.size())
          .mapNotNull { if (array.getType(it) == ReadableType.String) array.getString(it) else null }
          .map { it.uppercase() }
          .toSet()
      }?.takeIf { it.isNotEmpty() } ?: DEFAULT_DATA_GROUPS

      val csca = options.getArray("cscaCertificates")?.let { array ->
        (0 until array.size()).mapNotNull {
          if (array.getType(it) == ReadableType.String) array.getString(it) else null
        }
      } ?: emptyList()

      return ScanRequest(
        useCan = useCan,
        can = can,
        documentNumber = documentNumber.uppercase(),
        dateOfBirth = dateOfBirth,
        dateOfExpiry = dateOfExpiry,
        dataGroups = dataGroups,
        usePace = options.getBooleanOr("usePace", true),
        allowBacFallback = options.getBooleanOr("allowBacFallback", true),
        chipAuthentication = options.getBooleanOr("chipAuthentication", true),
        activeAuthentication = options.getBooleanOr("activeAuthentication", true),
        passiveAuthentication = options.getBooleanOr("passiveAuthentication", true),
        cscaCertificates = csca,
        includeImages = options.getBooleanOr("includeImages", true),
        includeRawData = options.getBooleanOr("includeRawData", false),
        timeoutMs = options.getDoubleOr("timeout", 60000.0).toLong(),
      )
    }

    private fun ReadableMap.getStringOr(key: String, fallback: String): String =
      if (hasKey(key) && getType(key) == ReadableType.String) getString(key) ?: fallback else fallback

    private fun ReadableMap.getBooleanOr(key: String, fallback: Boolean): Boolean =
      if (hasKey(key) && getType(key) == ReadableType.Boolean) getBoolean(key) else fallback

    private fun ReadableMap.getDoubleOr(key: String, fallback: Double): Double =
      if (hasKey(key) && getType(key) == ReadableType.Number) getDouble(key) else fallback
  }
}
