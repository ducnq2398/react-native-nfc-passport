import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';
import type { UnsafeObject } from 'react-native/Libraries/Types/CodegenTypes';

/**
 * TurboModule spec — codegen sinh ra:
 *  - Android: `com.nfcpassport.NativeNfcPassportSpec` (abstract class)
 *  - iOS:     `NativeNfcPassportSpec` (Obj-C protocol trong RNNfcPassportSpec)
 *
 * Payload dùng `UnsafeObject` vì cấu trúc kết quả là cây lồng nhau, codegen
 * không mô tả được bằng kiểu tĩnh. Ràng buộc kiểu thật nằm ở `src/index.ts`.
 */
export interface Spec extends TurboModule {
  /** Phần cứng có đọc được thẻ ISO 14443 / ISO 7816 không. */
  isSupported(): Promise<boolean>;

  /** Android: NFC đang bật. iOS: trả về giá trị của `isSupported`. */
  isEnabled(): Promise<boolean>;

  /** Android: mở màn hình cài đặt NFC. iOS: no-op, trả về `false`. */
  openNfcSettings(): Promise<boolean>;

  /**
   * Bắt đầu một phiên quét. Resolve khi đọc xong toàn bộ DataGroup được yêu cầu.
   * Trên Android, phiên bắt đầu ở chế độ reader-mode và chờ tag; trên iOS,
   * hệ thống hiển thị NFC sheet.
   */
  startScan(options: UnsafeObject): Promise<UnsafeObject>;

  /** Huỷ phiên đang chạy. Promise của `startScan` sẽ reject với `CANCELLED`. */
  cancel(): Promise<boolean>;

  /**
   * Cập nhật dòng chữ trên NFC sheet của iOS trong lúc đang quét.
   * Android: no-op.
   */
  setSessionMessage(message: string): void;

  // Bắt buộc cho NativeEventEmitter trên cả hai kiến trúc.
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.get<Spec>('NfcPassport');
