import Foundation

/// Mã lỗi khớp 1-1 với `NfcPassportErrorCode` phía JavaScript và với
/// `ErrorCode` phía Android.
enum NfcPassportErrorCode: String {
  case notSupported = "NOT_SUPPORTED"
  case nfcDisabled = "NFC_DISABLED"
  case cancelled = "CANCELLED"
  case timeout = "TIMEOUT"
  case tagLost = "TAG_LOST"
  case notAnEmrtd = "NOT_AN_EMRTD"
  case invalidMrzKey = "INVALID_MRZ_KEY"
  case paceFailed = "PACE_FAILED"
  case bacFailed = "BAC_FAILED"
  case communicationError = "COMMUNICATION_ERROR"
  case parseError = "PARSE_ERROR"
  case authenticationFailed = "AUTHENTICATION_FAILED"
  case invalidArgument = "INVALID_ARGUMENT"
  case sessionBusy = "SESSION_BUSY"
  case unknown = "UNKNOWN"
}

struct NfcPassportError: Error {
  let code: NfcPassportErrorCode
  let message: String
  let statusWord: String?

  init(code: NfcPassportErrorCode, message: String, statusWord: String? = nil) {
    self.code = code
    self.message = message
    self.statusWord = statusWord
  }

  var userInfo: [String: Any] {
    var info: [String: Any] = ["nativeCode": code.rawValue]
    if let statusWord = statusWord { info["statusWord"] = statusWord }
    return info
  }

  /// Thông điệp hiển thị trên NFC sheet của iOS khi phiên kết thúc bằng lỗi.
  var sessionMessage: String {
    switch code {
    case .invalidMrzKey:
      return "Thông tin không khớp với thẻ. Kiểm tra lại số CCCD, ngày sinh, ngày hết hạn."
    case .tagLost:
      return "Mất kết nối với thẻ. Giữ thẻ áp sát máy đến khi đọc xong."
    case .notAnEmrtd:
      return "Thẻ này không phải CCCD gắn chip."
    case .timeout:
      return "Hết thời gian chờ."
    default:
      return message
    }
  }

  /// Chuyển status word của chip thành lỗi có ngữ nghĩa.
  static func fromStatusWord(_ sw: UInt16, context: String) -> NfcPassportError {
    let hex = String(format: "%04X", sw)
    switch sw {
    case 0x6300, 0x6982, 0x6983:
      return NfcPassportError(
        code: .invalidMrzKey,
        message: "\(context): chip từ chối xác thực (SW=\(hex))",
        statusWord: hex
      )
    case 0x6A82:
      return NfcPassportError(
        code: .communicationError,
        message: "\(context): không tìm thấy file (SW=\(hex))",
        statusWord: hex
      )
    case 0x6A86, 0x6A80:
      return NfcPassportError(
        code: .communicationError,
        message: "\(context): tham số lệnh không hợp lệ (SW=\(hex))",
        statusWord: hex
      )
    case 0x6D00, 0x6E00:
      return NfcPassportError(
        code: .notAnEmrtd,
        message: "\(context): chip không hỗ trợ lệnh này (SW=\(hex))",
        statusWord: hex
      )
    default:
      return NfcPassportError(
        code: .communicationError,
        message: "\(context): chip trả về SW=\(hex)",
        statusWord: hex
      )
    }
  }
}
