package com.nfcpassport

import net.sf.scuba.smartcards.CardServiceException
import java.io.IOException

/** Mã lỗi khớp 1-1 với `NfcPassportErrorCode` phía JavaScript. */
enum class ErrorCode {
  NOT_SUPPORTED,
  NFC_DISABLED,
  CANCELLED,
  TIMEOUT,
  TAG_LOST,
  NOT_AN_EMRTD,
  INVALID_MRZ_KEY,
  PACE_FAILED,
  BAC_FAILED,
  COMMUNICATION_ERROR,
  PARSE_ERROR,
  AUTHENTICATION_FAILED,
  INVALID_ARGUMENT,
  SESSION_BUSY,
  UNKNOWN,
}

class NfcPassportException(
  val code: ErrorCode,
  message: String,
  val statusWord: String? = null,
  cause: Throwable? = null,
) : Exception(message, cause)

object ErrorMapper {

  /** SW mà chip trả về khi khoá BAC/PACE sai hoặc điều kiện bảo mật chưa thoả. */
  private val MRZ_MISMATCH_STATUS_WORDS = setOf(0x6300, 0x6982, 0x6983, 0x6A80)

  fun map(throwable: Throwable, stage: Stage): NfcPassportException {
    if (throwable is NfcPassportException) return throwable

    if (throwable is CardServiceException) {
      val sw = throwable.sw
      val swHex = if (sw != 0) String.format("%04X", sw and 0xFFFF) else null

      // TagLostException được SCUBA bọc lại thành CardServiceException.
      val rootCause = generateSequence(throwable.cause) { it.cause }
        .firstOrNull { it is android.nfc.TagLostException }
      if (rootCause != null) {
        return NfcPassportException(ErrorCode.TAG_LOST, "Thẻ rời khỏi vùng đọc", swHex, throwable)
      }

      if (sw != 0 && MRZ_MISMATCH_STATUS_WORDS.contains(sw and 0xFFFF)) {
        return when (stage) {
          Stage.PACE -> NfcPassportException(
            ErrorCode.INVALID_MRZ_KEY,
            "PACE bị chip từ chối (SW=$swHex) — nhiều khả năng MRZ không khớp",
            swHex, throwable
          )
          Stage.BAC -> NfcPassportException(
            ErrorCode.INVALID_MRZ_KEY,
            "BAC bị chip từ chối (SW=$swHex) — nhiều khả năng MRZ không khớp",
            swHex, throwable
          )
          else -> NfcPassportException(
            ErrorCode.COMMUNICATION_ERROR,
            "Chip từ chối lệnh (SW=$swHex)",
            swHex, throwable
          )
        }
      }

      val code = when (stage) {
        Stage.PACE -> ErrorCode.PACE_FAILED
        Stage.BAC -> ErrorCode.BAC_FAILED
        Stage.SELECT_APPLET -> ErrorCode.NOT_AN_EMRTD
        else -> ErrorCode.COMMUNICATION_ERROR
      }
      return NfcPassportException(
        code,
        throwable.message ?: "Lỗi giao tiếp với chip${if (swHex != null) " (SW=$swHex)" else ""}",
        swHex,
        throwable
      )
    }

    if (throwable is android.nfc.TagLostException) {
      return NfcPassportException(ErrorCode.TAG_LOST, "Thẻ rời khỏi vùng đọc", null, throwable)
    }

    if (throwable is IOException) {
      return NfcPassportException(
        ErrorCode.COMMUNICATION_ERROR,
        throwable.message ?: "Lỗi I/O khi giao tiếp với chip",
        null,
        throwable
      )
    }

    val code = when (stage) {
      Stage.PARSE -> ErrorCode.PARSE_ERROR
      Stage.PASSIVE_AUTH -> ErrorCode.AUTHENTICATION_FAILED
      else -> ErrorCode.UNKNOWN
    }
    return NfcPassportException(code, throwable.message ?: throwable.toString(), null, throwable)
  }

  enum class Stage { CONNECT, SELECT_APPLET, PACE, BAC, READ, PARSE, CHIP_AUTH, ACTIVE_AUTH, PASSIVE_AUTH }
}
