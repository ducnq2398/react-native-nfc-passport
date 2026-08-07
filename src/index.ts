import { NativeEventEmitter, NativeModules, Platform } from 'react-native';
import NativeNfcPassport from './NativeNfcPassport';
import { NfcPassportError, normalizeNativeError, userMessageFor } from './errors';
import { buildMrzKey } from './mrz';
import {
  NfcPassportErrorCode,
  type DataGroupId,
  type NfcStatus,
  type PassportData,
  type ScanOptions,
  type ScanProgressEvent,
} from './types';

const LINKING_ERROR =
  `Không tìm thấy native module "NfcPassport".\n` +
  `- Chạy lại 'pod install' (iOS) hoặc rebuild app (Android)\n` +
  `- Đảm bảo bạn đã rebuild sau khi cài package, Fast Refresh là không đủ\n` +
  `- Thư viện không hoạt động trên Expo Go (cần development build)`;

const PROGRESS_EVENT = 'NfcPassport:progress';

function requireModule() {
  if (NativeNfcPassport == null) {
    throw new NfcPassportError(NfcPassportErrorCode.NOT_SUPPORTED, LINKING_ERROR);
  }
  return NativeNfcPassport;
}

/**
 * `NativeEventEmitter` cần một native module thật để đăng ký listener trên
 * kiến trúc cũ. Trên New Architecture, TurboModule đã tự lo phần này.
 */
const emitter = new NativeEventEmitter(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (NativeNfcPassport as any) ?? NativeModules.NfcPassport
);

export interface EventSubscription {
  remove(): void;
}

const DEFAULT_DATA_GROUPS: DataGroupId[] = ['DG1', 'DG2', 'DG13', 'DG14', 'DG15'];

const DEFAULT_IOS_MESSAGES = {
  alertMessage:
    'Đặt mặt sau điện thoại lên vị trí chip của thẻ CCCD và giữ yên.',
  connectingMessage: 'Đang kết nối với chip…',
  readingMessage: 'Đang đọc dữ liệu',
  successMessage: 'Đọc thẻ thành công',
};

/** Phần cứng thiết bị có hỗ trợ đọc chip eMRTD không. */
export async function isSupported(): Promise<boolean> {
  try {
    return await requireModule().isSupported();
  } catch {
    return false;
  }
}

/** Android: NFC đang bật trong Cài đặt. iOS: bằng `isSupported()`. */
export async function isEnabled(): Promise<boolean> {
  try {
    return await requireModule().isEnabled();
  } catch {
    return false;
  }
}

export async function getStatus(): Promise<NfcStatus> {
  const [supported, enabled] = await Promise.all([isSupported(), isEnabled()]);
  return { supported, enabled };
}

/** Android: mở Settings để người dùng bật NFC. iOS: trả về `false`. */
export async function openNfcSettings(): Promise<boolean> {
  try {
    return await requireModule().openNfcSettings();
  } catch {
    return false;
  }
}

/** Lắng nghe tiến trình đọc để cập nhật UI. */
export function addProgressListener(
  listener: (event: ScanProgressEvent) => void
): EventSubscription {
  return emitter.addListener(PROGRESS_EVENT, listener);
}

/**
 * Cập nhật dòng chữ trên NFC sheet của iOS trong lúc quét (no-op trên Android).
 * Thường dùng bên trong `addProgressListener` nếu muốn văn bản tuỳ biến.
 */
export function setSessionMessage(message: string): void {
  if (Platform.OS !== 'ios') return;
  try {
    requireModule().setSessionMessage(message);
  } catch {
    // Session đã đóng — bỏ qua.
  }
}

/**
 * Quét và đọc chip CCCD.
 *
 * ```ts
 * const data = await scan({
 *   accessKey: {
 *     type: 'mrz',
 *     mrz: { documentNumber: '001199012345', dateOfBirth: '900115', dateOfExpiry: '400114' },
 *   },
 * });
 * ```
 *
 * @throws {NfcPassportError} với `code` thuộc {@link NfcPassportErrorCode}.
 */
export async function scan(options: ScanOptions): Promise<PassportData> {
  const mod = requireModule();

  if (options?.accessKey == null) {
    throw new NfcPassportError(
      NfcPassportErrorCode.INVALID_ARGUMENT,
      'Thiếu `accessKey`'
    );
  }

  // Chuẩn hoá khoá truy cập ở JS để lỗi MRZ được phát hiện trước khi mở NFC session.
  let accessKey: Record<string, unknown>;
  if (options.accessKey.type === 'can') {
    const can = String(options.accessKey.can ?? '').trim();
    if (!/^\d{6}$/.test(can)) {
      throw new NfcPassportError(
        NfcPassportErrorCode.INVALID_ARGUMENT,
        'CAN phải gồm đúng 6 chữ số'
      );
    }
    accessKey = { type: 'can', can };
  } else {
    accessKey = { type: 'mrz', ...buildMrzKey(options.accessKey.mrz) };
  }

  const payload = {
    accessKey,
    dataGroups: options.dataGroups ?? DEFAULT_DATA_GROUPS,
    usePace: options.usePace ?? true,
    allowBacFallback: options.allowBacFallback ?? true,
    chipAuthentication: options.chipAuthentication ?? true,
    activeAuthentication: options.activeAuthentication ?? true,
    passiveAuthentication: options.passiveAuthentication ?? true,
    cscaCertificates: options.cscaCertificates ?? [],
    includeImages: options.includeImages ?? true,
    includeRawData: options.includeRawData ?? false,
    rawEncoding: options.rawEncoding ?? 'base64',
    timeout: options.timeout ?? 60000,
    ios: { ...DEFAULT_IOS_MESSAGES, ...(options.ios ?? {}) },
  };

  try {
    return (await mod.startScan(payload)) as PassportData;
  } catch (error) {
    throw normalizeNativeError(error);
  }
}

/** Huỷ phiên quét đang chạy. */
export async function cancel(): Promise<boolean> {
  try {
    return await requireModule().cancel();
  } catch {
    return false;
  }
}

export { NfcPassportError, userMessageFor, normalizeNativeError };
export {
  buildMrzKey,
  buildMrzInformation,
  parseMrz,
  computeCheckDigit,
  verifyCheckDigit,
} from './mrz';
export type { ParsedMrz, MrzKeyFields } from './mrz';
export * from './types';

export default {
  isSupported,
  isEnabled,
  getStatus,
  openNfcSettings,
  addProgressListener,
  setSessionMessage,
  scan,
  cancel,
};
