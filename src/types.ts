/**
 * Public type definitions for react-native-nfc-passport.
 *
 * Tài liệu tham chiếu:
 *  - ICAO Doc 9303 Part 3  (Specifications Common to all MRTDs — LDS, DG layout)
 *  - ICAO Doc 9303 Part 10 (Logical Data Structure)
 *  - ICAO Doc 9303 Part 11 (Security Mechanisms — BAC, PACE, CA, AA, PA)
 */

/** Các DataGroup mà SDK có thể đọc mà không cần Terminal Authentication. */
export type DataGroupId =
  | 'COM'
  | 'DG1'
  | 'DG2'
  | 'DG5'
  | 'DG7'
  | 'DG11'
  | 'DG12'
  | 'DG13'
  | 'DG14'
  | 'DG15'
  | 'SOD';

/**
 * Khoá truy cập chip.
 *
 * - `mrz`: khoá dẫn xuất từ MRZ (BAC / PACE-MRZ). Đây là cách dùng cho CCCD.
 * - `can`: Card Access Number, chỉ dùng được với PACE. Một số thẻ in CAN 6 chữ số
 *   ở mặt trước; CCCD Việt Nam hiện không in CAN nên thực tế luôn dùng `mrz`.
 */
export type AccessKey =
  | { type: 'mrz'; mrz: MrzKeyInput }
  | { type: 'can'; can: string };

/**
 * Thông tin MRZ tối thiểu để dẫn xuất khoá.
 *
 * Có thể truyền theo 2 cách:
 *  1. Ba trường rời rạc (đã tách sẵn từ OCR).
 *  2. Chuỗi MRZ thô (`rawMrz`) — SDK sẽ tự parse TD1/TD2/TD3 và tách trường.
 *
 * Với CCCD Việt Nam (định dạng TD1, 3 dòng × 30 ký tự):
 *  - `documentNumber` là **12 chữ số** trên thẻ. Do trường document number của TD1
 *    chỉ có 9 ký tự, ICAO 9303 cho phép tràn phần còn lại sang optional data;
 *    khi dẫn xuất khoá vẫn dùng đủ 12 chữ số (xem `buildMrzKey`).
 *  - `dateOfBirth` / `dateOfExpiry` theo định dạng `YYMMDD`.
 */
export type MrzKeyInput =
  | {
      documentNumber: string;
      dateOfBirth: string;
      dateOfExpiry: string;
      rawMrz?: undefined;
    }
  | {
      rawMrz: string;
      documentNumber?: undefined;
      dateOfBirth?: undefined;
      dateOfExpiry?: undefined;
    };

/** Tuỳ chọn hiển thị cho system NFC sheet của iOS. */
export interface IosSessionMessages {
  /** Hiển thị khi mở session, trước khi chạm thẻ. */
  alertMessage?: string;
  /** Hiển thị khi đã bắt được thẻ và đang thiết lập secure messaging. */
  connectingMessage?: string;
  /** Prefix cho tiến trình đọc, ví dụ "Đang đọc dữ liệu". */
  readingMessage?: string;
  /** Hiển thị khi thành công, ngay trước khi sheet đóng. */
  successMessage?: string;
}

/** Tuỳ chọn cho một phiên quét. */
export interface ScanOptions {
  /** Khoá truy cập chip. */
  accessKey: AccessKey;

  /**
   * Danh sách DataGroup cần đọc. Mặc định: `['DG1', 'DG2', 'DG13', 'DG14', 'DG15']`.
   * `COM` và `SOD` luôn được đọc khi bật `passiveAuthentication`.
   *
   * Lưu ý: DG3 (vân tay) và DG4 (mống mắt) yêu cầu Extended Access Control
   * (Terminal Authentication + chứng thư CVCA) nên **không** được hỗ trợ.
   */
  dataGroups?: DataGroupId[];

  /**
   * Ưu tiên PACE, tự động fallback sang BAC nếu chip không hỗ trợ PACE
   * hoặc PACE thất bại. Mặc định `true`.
   */
  usePace?: boolean;

  /** Cho phép fallback sang BAC khi PACE lỗi. Mặc định `true`. */
  allowBacFallback?: boolean;

  /** Chạy Chip Authentication (chống clone chip). Mặc định `true`. */
  chipAuthentication?: boolean;

  /** Chạy Active Authentication (DG15). Mặc định `true`. */
  activeAuthentication?: boolean;

  /**
   * Chạy Passive Authentication: đọc EF.SOD, đối chiếu hash các DG và kiểm tra
   * chữ ký của Document Signer. Mặc định `true`.
   */
  passiveAuthentication?: boolean;

  /**
   * Danh sách chứng thư CSCA (PEM hoặc DER-base64) để kiểm tra đầy đủ chuỗi tin cậy
   * trong Passive Authentication. Nếu bỏ trống, SDK chỉ kiểm tra hash DG và chữ ký
   * SOD bằng chính DSC nhúng trong SOD (không chứng minh được tính tin cậy của DSC).
   */
  cscaCertificates?: string[];

  /** Trả về ảnh chân dung DG2 dưới dạng base64. Mặc định `true`. */
  includeImages?: boolean;

  /** Trả về bytes thô của từng DG (hex) để debug / lưu trữ. Mặc định `false`. */
  includeRawData?: boolean;

  /** Timeout toàn phiên (ms). Mặc định 60000. */
  timeout?: number;

  /** Thông điệp hiển thị trên NFC sheet của iOS. */
  ios?: IosSessionMessages;
}

/** Dữ liệu MRZ đã parse từ DG1. */
export interface Dg1MrzInfo {
  /** Toàn bộ MRZ đọc từ chip, các dòng nối bằng `\n`. */
  raw: string;
  /** `TD1` | `TD2` | `TD3`. */
  format: string;
  documentCode: string;
  issuingState: string;
  documentNumber: string;
  /** Họ, viết hoa không dấu. */
  primaryIdentifier: string;
  /** Tên đệm + tên, viết hoa không dấu. */
  secondaryIdentifier: string;
  nationality: string;
  /** `YYMMDD`. */
  dateOfBirth: string;
  /** `M` | `F` | `<`. */
  gender: string;
  /** `YYMMDD`. */
  dateOfExpiry: string;
  optionalData1: string;
  optionalData2: string;
}

/**
 * Thông tin cá nhân trích từ DG13.
 *
 * DG13 là "Optional details" do quốc gia phát hành tự định nghĩa — ICAO không
 * chuẩn hoá nội dung. Cấu trúc dưới đây bám theo bố cục DG13 của CCCD Việt Nam.
 * Mọi trường đều optional vì bố cục có thể thay đổi giữa các đợt phát hành;
 * luôn kèm `rawFields` để ứng dụng tự xử lý khi mapping không khớp.
 */
export interface VnCccdPersonalInfo {
  /** Số CCCD (12 chữ số). */
  idNumber?: string;
  /** Số CMND 9 chữ số cũ, nếu có. */
  oldIdNumber?: string;
  /** Họ và tên đầy đủ, có dấu tiếng Việt. */
  fullName?: string;
  /** `DD/MM/YYYY`. */
  dateOfBirth?: string;
  /** `Nam` | `Nữ`. */
  gender?: string;
  nationality?: string;
  /** Dân tộc. */
  ethnicity?: string;
  /** Tôn giáo. */
  religion?: string;
  /** Quê quán. */
  placeOfOrigin?: string;
  /** Nơi thường trú. */
  placeOfResidence?: string;
  /** Đặc điểm nhận dạng. */
  personalIdentification?: string;
  /** `DD/MM/YYYY`. */
  dateOfIssue?: string;
  /** `DD/MM/YYYY`. */
  dateOfExpiry?: string;
  fatherName?: string;
  motherName?: string;
  spouseName?: string;
  /**
   * Toàn bộ chuỗi UTF-8 đọc được từ DG13 theo đúng thứ tự xuất hiện.
   * Dùng trường này khi mapping ở trên không khớp với thẻ của bạn.
   */
  rawFields: string[];
}

/** Ảnh chân dung trích từ DG2. */
export interface FaceImage {
  /** Base64 (không có prefix `data:`). */
  base64: string;
  /** `image/jpeg` sau khi transcode, hoặc mime gốc nếu không decode được. */
  mimeType: string;
  width: number;
  height: number;
  /**
   * `true` nếu native đã transcode được sang JPEG. Khi `false`, `base64` là bytes
   * gốc (thường là JPEG 2000) và ứng dụng cần decoder riêng để hiển thị.
   */
  transcoded: boolean;
}

/** Kết quả các bước xác thực bảo mật. */
export interface SecurityResult {
  /** Giao thức đã thiết lập secure messaging: `PACE` hoặc `BAC`. */
  accessProtocol: 'PACE' | 'BAC';
  /** OID của PACE nếu dùng PACE, ví dụ `0.4.0.127.0.7.2.2.4.2.4`. */
  paceOid?: string;
  /** Thuật toán mã hoá của secure messaging: `DESede` hoặc `AES`. */
  secureMessagingCipher: string;
  chipAuthentication: AuthStepResult;
  activeAuthentication: AuthStepResult;
  passiveAuthentication: PassiveAuthResult;
}

export interface AuthStepResult {
  /** `true` nếu bước này đã chạy và thành công. */
  succeeded: boolean;
  /** `true` nếu bước này bị bỏ qua (không được yêu cầu, hoặc chip không hỗ trợ). */
  skipped: boolean;
  reason?: string;
}

export interface PassiveAuthResult extends AuthStepResult {
  /** Hash của từng DG trong SOD khớp với hash tính lại từ dữ liệu đọc được. */
  dataGroupHashesValid: boolean;
  /** Chữ ký SOD hợp lệ với public key của Document Signer. */
  sodSignatureValid: boolean;
  /** DSC verify được tới một CSCA do ứng dụng cung cấp. */
  documentSignerTrusted: boolean;
  /** Danh sách DG không khớp hash, nếu có. */
  mismatchedDataGroups: string[];
}

/** Thông tin trích từ EF.SOD. */
export interface SodInfo {
  digestAlgorithm: string;
  signatureAlgorithm: string;
  /** Hash từng DG do SOD công bố, hex viết thường. */
  dataGroupHashes: Record<string, string>;
  documentSigner?: {
    subject: string;
    issuer: string;
    serialNumber: string;
    /** ISO 8601. */
    notBefore: string;
    /** ISO 8601. */
    notAfter: string;
  };
}

/** Kết quả đầy đủ của một phiên quét. */
export interface PassportData {
  /** MRZ đọc từ chip (DG1). Luôn có nếu DG1 nằm trong `dataGroups`. */
  mrz?: Dg1MrzInfo;
  /** Thông tin cá nhân tiếng Việt (DG13). */
  personal?: VnCccdPersonalInfo;
  /** Ảnh chân dung (DG2). */
  faceImage?: FaceImage;
  /** Ảnh chữ ký / dấu (DG7), nếu thẻ có. */
  signatureImage?: FaceImage;
  security: SecurityResult;
  sod?: SodInfo;
  /** Bytes thô của từng DG, hex viết thường. Chỉ có khi `includeRawData: true`. */
  raw?: Partial<Record<DataGroupId, string>>;
  /** Thời điểm đọc xong, ISO 8601. */
  readAt: string;
  /** Tổng thời gian đọc (ms). */
  durationMs: number;
}

/** Các bước trong tiến trình đọc, dùng để hiển thị UI. */
export type ScanStep =
  | 'waiting_for_tag'
  | 'tag_connected'
  | 'reading_card_access'
  | 'pace'
  | 'bac'
  | 'selecting_applet'
  | 'chip_authentication'
  | 'reading_datagroup'
  | 'active_authentication'
  | 'passive_authentication'
  | 'done';

export interface ScanProgressEvent {
  step: ScanStep;
  /** 0..1 */
  progress: number;
  /** DataGroup đang đọc, khi `step === 'reading_datagroup'`. */
  dataGroup?: DataGroupId;
  /** Thông điệp thân thiện với người dùng (tiếng Việt). */
  message?: string;
}

/** Mã lỗi ổn định, giống nhau trên cả hai nền tảng. */
export enum NfcPassportErrorCode {
  /** Thiết bị không có phần cứng NFC hoặc iOS < 13. */
  NOT_SUPPORTED = 'NOT_SUPPORTED',
  /** Android: NFC bị tắt trong Cài đặt. */
  NFC_DISABLED = 'NFC_DISABLED',
  /** Người dùng huỷ, hoặc `cancel()` được gọi. */
  CANCELLED = 'CANCELLED',
  /** Hết thời gian chờ thẻ / hết timeout phiên. */
  TIMEOUT = 'TIMEOUT',
  /** Thẻ rời khỏi vùng đọc giữa chừng. */
  TAG_LOST = 'TAG_LOST',
  /** Thẻ không phải eMRTD (không select được AID A0000002471001). */
  NOT_AN_EMRTD = 'NOT_AN_EMRTD',
  /** MRZ sai → BAC/PACE bị chip từ chối (SW 6300 / 6982). */
  INVALID_MRZ_KEY = 'INVALID_MRZ_KEY',
  /** PACE thất bại vì lý do khác MRZ sai. */
  PACE_FAILED = 'PACE_FAILED',
  /** BAC thất bại. */
  BAC_FAILED = 'BAC_FAILED',
  /** Lỗi giao tiếp APDU / secure messaging. */
  COMMUNICATION_ERROR = 'COMMUNICATION_ERROR',
  /** Đọc được nhưng parse dữ liệu lỗi. */
  PARSE_ERROR = 'PARSE_ERROR',
  /** Passive Authentication thất bại (dữ liệu có thể đã bị sửa). */
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  /** Tham số truyền vào không hợp lệ. */
  INVALID_ARGUMENT = 'INVALID_ARGUMENT',
  /** Đang có một phiên quét khác chạy. */
  SESSION_BUSY = 'SESSION_BUSY',
  UNKNOWN = 'UNKNOWN',
}

/** Trạng thái NFC của thiết bị. */
export interface NfcStatus {
  /** Phần cứng có hỗ trợ đọc thẻ ISO 14443 / ISO 7816 không. */
  supported: boolean;
  /** Android: NFC đang bật. iOS: luôn `true` khi `supported`. */
  enabled: boolean;
}
