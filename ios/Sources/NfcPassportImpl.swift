import CoreNFC
import Foundation

/// Điểm vào mà lớp bridge Objective-C++ gọi tới. Quản lý vòng đời
/// `NFCTagReaderSession` và uỷ quyền phần đọc cho `PassportReader`.
/// `@unchecked Sendable`: mọi state thay đổi được đều nằm sau serial queue
/// `queue`; riêng `onProgress` chỉ được gán một lần khi native module khởi tạo
/// và xoá khi teardown.
@objc(NfcPassportImpl)
public final class NfcPassportImpl: NSObject, @unchecked Sendable {

  @objc public static let shared = NfcPassportImpl()

  /// Được `NfcPassport` (Obj-C) gán để phát sự kiện tiến trình lên JS.
  @objc public var onProgress: ((NSDictionary) -> Void)?

  private let queue = DispatchQueue(label: "com.nfcpassport.session")
  private var readerSession: NFCTagReaderSession?
  private var options: ScanOptions?
  private var resolveBlock: ((Any?) -> Void)?
  private var rejectBlock: ((String, String, NSDictionary?) -> Void)?
  private var settled = false

  private override init() {
    super.init()
  }

  // MARK: - API

  @objc public func isSupported() -> Bool {
    NFCTagReaderSession.readingAvailable
  }

  @objc public func startScan(
    _ optionsDictionary: NSDictionary,
    resolve: @escaping (Any?) -> Void,
    reject: @escaping (String, String, NSDictionary?) -> Void
  ) {
    guard NFCTagReaderSession.readingAvailable else {
      reject(
        NfcPassportErrorCode.notSupported.rawValue,
        "Thiết bị không hỗ trợ đọc thẻ NFC (cần iPhone 7 trở lên, iOS 15+)",
        nil
      )
      return
    }

    let parsed: ScanOptions
    do {
      parsed = try ScanOptions(dictionary: optionsDictionary as? [String: Any] ?? [:])
    } catch let error as NfcPassportError {
      reject(error.code.rawValue, error.message, error.userInfo as NSDictionary)
      return
    } catch {
      reject(NfcPassportErrorCode.invalidArgument.rawValue, error.localizedDescription, nil)
      return
    }

    let started: Bool = queue.sync {
      guard readerSession == nil else {
        reject(NfcPassportErrorCode.sessionBusy.rawValue, "Đang có một phiên quét khác", nil)
        return false
      }

      options = parsed
      resolveBlock = resolve
      rejectBlock = reject
      settled = false

      guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: queue)
      else {
        reject(NfcPassportErrorCode.notSupported.rawValue, "Không khởi tạo được phiên NFC", nil)
        clearLocked()
        return false
      }
      session.alertMessage = parsed.alertMessage
      readerSession = session
      session.begin()
      return true
    }

    if started {
      emitProgress(step: "waiting_for_tag", progress: 0, dataGroup: nil, message: parsed.alertMessage)
    }
  }

  @discardableResult
  @objc public func cancel() -> Bool {
    queue.sync { () -> Bool in
      guard let session = readerSession, !settled else { return false }
      session.invalidate()
      finishLocked(
        error: NfcPassportError(code: .cancelled, message: "Phiên quét đã bị huỷ")
      )
      return true
    }
  }

  @objc public func setSessionMessage(_ message: String) {
    queue.async { [weak self] in
      self?.readerSession?.alertMessage = message
    }
  }

  // MARK: - Kết thúc phiên

  /// Phải gọi bên trong `queue`.
  private func finishLocked(result: [String: Any]? = nil, error: NfcPassportError? = nil) {
    guard !settled else { return }
    settled = true

    let resolve = resolveBlock
    let reject = rejectBlock
    clearLocked()

    DispatchQueue.main.async {
      if let result = result {
        resolve?(result)
      } else {
        let error = error ?? NfcPassportError(code: .unknown, message: "Lỗi không xác định")
        reject?(error.code.rawValue, error.message, error.userInfo as NSDictionary)
      }
    }
  }

  private func clearLocked() {
    readerSession = nil
    options = nil
    resolveBlock = nil
    rejectBlock = nil
  }

  private func emitProgress(step: String, progress: Double, dataGroup: String?, message: String?) {
    var payload: [String: Any] = ["step": step, "progress": progress]
    if let dataGroup = dataGroup { payload["dataGroup"] = dataGroup }
    if let message = message { payload["message"] = message }
    DispatchQueue.main.async { [weak self] in
      self?.onProgress?(payload as NSDictionary)
    }
  }
}

// MARK: - NFCTagReaderSessionDelegate

extension NfcPassportImpl: NFCTagReaderSessionDelegate {

  public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
    emitProgress(step: "waiting_for_tag", progress: 0.02, dataGroup: nil, message: nil)
  }

  public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
    queue.async { [weak self] in
      guard let self = self else { return }
      let mapped: NfcPassportError
      if let readerError = error as? NFCReaderError {
        mapped = TagSession.map(readerError)
      } else {
        mapped = NfcPassportError(code: .unknown, message: error.localizedDescription)
      }
      self.finishLocked(error: mapped)
    }
  }

  public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
    guard let options = options else {
      session.invalidate(errorMessage: "Phiên không hợp lệ")
      return
    }

    guard tags.count == 1 else {
      session.alertMessage = "Phát hiện nhiều thẻ. Chỉ để một thẻ trong vùng đọc."
      session.restartPolling()
      return
    }

    guard case let .iso7816(iso7816Tag) = tags[0] else {
      // CoreNFC chỉ trả về `.iso7816` khi nó SELECT được một AID có trong khoá
      // `com.apple.developer.nfc.readersession.iso7816.select-identifiers` của
      // **Info.plist** (khoá này có tiền tố com.apple.developer nhưng không phải
      // entitlement). Thiếu AID A0000002471001 ở đó là nguyên nhân áp đảo của
      // triệu chứng "sheet mở nhưng chạm thẻ không có gì xảy ra" — báo rõ thay
      // vì lặng lẽ restartPolling() để người tích hợp không phải đoán.
      let error = NfcPassportError(
        code: .notAnEmrtd,
        message: "Thẻ không được nhận là ISO 7816. Kiểm tra Info.plist đã có khoá "
          + "com.apple.developer.nfc.readersession.iso7816.select-identifiers "
          + "chứa AID A0000002471001 chưa, và thẻ có đúng là CCCD gắn chip không."
      )
      session.invalidate(errorMessage: "Thẻ này không phải CCCD gắn chip.")
      queue.async { [weak self] in self?.finishLocked(error: error) }
      return
    }

    session.alertMessage = options.connectingMessage
    emitProgress(step: "tag_connected", progress: 0.05, dataGroup: nil, message: options.connectingMessage)

    Task { [weak self] in
      guard let self = self else { return }
      do {
        try await session.connect(to: tags[0])

        let tagSession = TagSession(tag: iso7816Tag)
        let reader = PassportReader(options: options) { step, progress, dataGroup, message in
          self.emitProgress(step: step, progress: progress, dataGroup: dataGroup, message: message)
          if let message = message {
            session.alertMessage = message
          }
        }

        let result = try await reader.read(session: tagSession)

        session.alertMessage = options.successMessage
        session.invalidate()
        self.emitProgress(step: "done", progress: 1.0, dataGroup: nil, message: options.successMessage)
        self.queue.async { self.finishLocked(result: result) }
      } catch {
        let mapped: NfcPassportError
        if let passportError = error as? NfcPassportError {
          mapped = passportError
        } else if let readerError = error as? NFCReaderError {
          mapped = TagSession.map(readerError)
        } else {
          mapped = NfcPassportError(code: .unknown, message: error.localizedDescription)
        }
        session.invalidate(errorMessage: mapped.sessionMessage)
        self.queue.async { self.finishLocked(error: mapped) }
      }
    }
  }
}
