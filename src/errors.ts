import { NfcPassportErrorCode } from './types';

/** Lỗi thống nhất cho cả hai nền tảng. */
export class NfcPassportError extends Error {
  readonly code: NfcPassportErrorCode;
  /** Mã lỗi native gốc (SW1SW2, NSError code…) nếu có. */
  readonly nativeCode?: string;
  /** Status word cuối cùng nhận từ chip, ví dụ `6982`. */
  readonly statusWord?: string;

  constructor(
    code: NfcPassportErrorCode,
    message: string,
    extra?: { nativeCode?: string; statusWord?: string; cause?: unknown }
  ) {
    super(message);
    this.name = 'NfcPassportError';
    this.code = code;
    this.nativeCode = extra?.nativeCode;
    this.statusWord = extra?.statusWord;
    if (extra?.cause !== undefined) {
      (this as { cause?: unknown }).cause = extra.cause;
    }
    Object.setPrototypeOf(this, NfcPassportError.prototype);
  }
}

const KNOWN_CODES = new Set<string>(Object.values(NfcPassportErrorCode));

/**
 * Chuyển rejection từ native (đã có shape `{ code, message, userInfo }` do
 * `Promise.reject(code, message, throwable)` của React Native) thành
 * `NfcPassportError`.
 */
export function normalizeNativeError(error: unknown): NfcPassportError {
  if (error instanceof NfcPassportError) return error;

  const err = error as
    | {
        code?: string;
        message?: string;
        userInfo?: { statusWord?: string; nativeCode?: string };
      }
    | undefined;

  const rawCode = err?.code ?? '';
  const code = KNOWN_CODES.has(rawCode)
    ? (rawCode as NfcPassportErrorCode)
    : NfcPassportErrorCode.UNKNOWN;

  return new NfcPassportError(code, err?.message ?? 'Lỗi không xác định', {
    nativeCode: err?.userInfo?.nativeCode ?? (code === rawCode ? undefined : rawCode),
    statusWord: err?.userInfo?.statusWord,
    cause: error,
  });
}

/** Thông điệp tiếng Việt gợi ý cho người dùng cuối, theo từng mã lỗi. */
export function userMessageFor(code: NfcPassportErrorCode): string {
  switch (code) {
    case NfcPassportErrorCode.NOT_SUPPORTED:
      return 'Thiết bị không hỗ trợ đọc NFC.';
    case NfcPassportErrorCode.NFC_DISABLED:
      return 'NFC đang tắt. Vui lòng bật NFC trong Cài đặt.';
    case NfcPassportErrorCode.CANCELLED:
      return 'Đã huỷ quét thẻ.';
    case NfcPassportErrorCode.TIMEOUT:
      return 'Hết thời gian chờ. Vui lòng thử lại.';
    case NfcPassportErrorCode.TAG_LOST:
      return 'Mất kết nối với thẻ. Giữ thẻ áp sát máy đến khi đọc xong.';
    case NfcPassportErrorCode.NOT_AN_EMRTD:
      return 'Thẻ này không phải CCCD gắn chip hoặc hộ chiếu điện tử.';
    case NfcPassportErrorCode.INVALID_MRZ_KEY:
      return 'Thông tin trên thẻ không khớp. Kiểm tra lại số CCCD, ngày sinh và ngày hết hạn.';
    case NfcPassportErrorCode.PACE_FAILED:
    case NfcPassportErrorCode.BAC_FAILED:
      return 'Không thiết lập được kênh bảo mật với chip. Vui lòng thử lại.';
    case NfcPassportErrorCode.COMMUNICATION_ERROR:
      return 'Lỗi giao tiếp với chip. Giữ thẻ cố định và thử lại.';
    case NfcPassportErrorCode.AUTHENTICATION_FAILED:
      return 'Không xác thực được tính toàn vẹn dữ liệu trên thẻ.';
    case NfcPassportErrorCode.SESSION_BUSY:
      return 'Đang có một phiên quét khác. Vui lòng đợi hoặc huỷ phiên hiện tại.';
    case NfcPassportErrorCode.PARSE_ERROR:
    case NfcPassportErrorCode.INVALID_ARGUMENT:
    case NfcPassportErrorCode.UNKNOWN:
    default:
      return 'Đã xảy ra lỗi khi đọc thẻ. Vui lòng thử lại.';
  }
}
