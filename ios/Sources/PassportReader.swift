import Foundation

/// Tuỳ chọn một phiên quét, chuẩn hoá từ payload JavaScript.
struct ScanOptions {
  var useCAN = false
  var can = ""
  var documentNumber = ""
  var dateOfBirth = ""
  var dateOfExpiry = ""
  var dataGroups: Set<String> = ["DG1", "DG2", "DG13", "DG14", "DG15"]
  var usePACE = true
  var allowBACFallback = true
  var chipAuthentication = true
  var activeAuthentication = true
  var passiveAuthentication = true
  var cscaCertificates: [String] = []
  var includeImages = true
  var includeRawData = false
  var alertMessage = ""
  var connectingMessage = ""
  var readingMessage = ""
  var successMessage = ""

  init(dictionary: [String: Any]) throws {
    guard let accessKey = dictionary["accessKey"] as? [String: Any] else {
      throw NfcPassportError(code: .invalidArgument, message: "Thiếu `accessKey`")
    }
    useCAN = (accessKey["type"] as? String) == "can"
    can = accessKey["can"] as? String ?? ""
    documentNumber = (accessKey["documentNumber"] as? String ?? "").uppercased()
    dateOfBirth = accessKey["dateOfBirth"] as? String ?? ""
    dateOfExpiry = accessKey["dateOfExpiry"] as? String ?? ""

    if useCAN {
      guard can.count == 6 else {
        throw NfcPassportError(code: .invalidArgument, message: "CAN phải gồm 6 chữ số")
      }
    } else {
      guard !documentNumber.isEmpty, dateOfBirth.count == 6, dateOfExpiry.count == 6 else {
        throw NfcPassportError(
          code: .invalidArgument,
          message: "MRZ không hợp lệ: cần documentNumber, dateOfBirth (YYMMDD), dateOfExpiry (YYMMDD)"
        )
      }
    }

    if let groups = dictionary["dataGroups"] as? [String], !groups.isEmpty {
      dataGroups = Set(groups.map { $0.uppercased() })
    }
    usePACE = dictionary["usePace"] as? Bool ?? true
    allowBACFallback = dictionary["allowBacFallback"] as? Bool ?? true
    chipAuthentication = dictionary["chipAuthentication"] as? Bool ?? true
    activeAuthentication = dictionary["activeAuthentication"] as? Bool ?? true
    passiveAuthentication = dictionary["passiveAuthentication"] as? Bool ?? true
    cscaCertificates = dictionary["cscaCertificates"] as? [String] ?? []
    includeImages = dictionary["includeImages"] as? Bool ?? true
    includeRawData = dictionary["includeRawData"] as? Bool ?? false

    let ios = dictionary["ios"] as? [String: Any] ?? [:]
    alertMessage = ios["alertMessage"] as? String
      ?? "Đặt mặt sau điện thoại lên vị trí chip của thẻ CCCD và giữ yên."
    connectingMessage = ios["connectingMessage"] as? String ?? "Đang kết nối với chip…"
    readingMessage = ios["readingMessage"] as? String ?? "Đang đọc dữ liệu"
    successMessage = ios["successMessage"] as? String ?? "Đọc thẻ thành công"
  }
}

/// Toàn bộ quy trình đọc chip eMRTD/CCCD trên iOS.
///
/// Thứ tự bám theo ICAO 9303 Part 11: PACE (fallback BAC) → SELECT applet →
/// Chip Authentication → đọc DataGroup → Active Authentication → Passive
/// Authentication. Chip Authentication chạy trước khi đọc các DG lớn để mọi dữ
/// liệu đều đi qua bộ khoá phiên mà chip đã chứng minh quyền sở hữu.
struct PassportReader {

  typealias ProgressHandler = (_ step: String, _ progress: Double, _ dataGroup: String?, _ message: String?) -> Void

  private static let fileIds: [String: UInt16] = [
    "COM": 0x011E, "DG1": 0x0101, "DG2": 0x0102, "DG5": 0x0105, "DG7": 0x0107,
    "DG11": 0x010B, "DG12": 0x010C, "DG13": 0x010D, "DG14": 0x010E,
    "DG15": 0x010F, "SOD": 0x011D,
  ]
  private static let dataGroupNumbers: [String: Int] = [
    "DG1": 1, "DG2": 2, "DG5": 5, "DG7": 7, "DG11": 11, "DG12": 12,
    "DG13": 13, "DG14": 14, "DG15": 15,
  ]
  /// File nhỏ trước để UI phản hồi sớm; DG2 (lớn nhất) sau cùng.
  private static let readOrder = ["COM", "DG1", "DG13", "DG11", "DG12", "DG15", "DG5", "DG7", "DG2"]
  private static let efCardAccess: UInt16 = 0x011C

  let options: ScanOptions
  let progress: ProgressHandler

  func read(session: TagSession) async throws -> [String: Any] {
    let startedAt = Date()
    var files = [String: Data]()

    // ------------------------------------------------ 1. Secure Messaging
    let access = try await establishSecureMessaging(session: session)

    // ------------------------------------------------ 2. Chip Authentication
    var chipAuthResult = stepResult(succeeded: false, skipped: true, reason: "Không được yêu cầu")
    if options.chipAuthentication {
      progress("chip_authentication", 0.30, nil, "Đang xác thực chip…")
      do {
        let dg14 = try await session.readFile(fid: PassportReader.fileIds["DG14"]!)
        files["DG14"] = dg14
        session.secureMessaging = try await ChipAuthentication.perform(session: session, dg14: dg14)
        chipAuthResult = stepResult(succeeded: true, skipped: false, reason: nil)
      } catch let error as NfcPassportError {
        if error.code == .tagLost { throw error }
        chipAuthResult = stepResult(succeeded: false, skipped: false, reason: error.message)
      }
    }

    // ------------------------------------------------ 3. Đọc DataGroup
    try await readFiles(session: session, into: &files)

    // ------------------------------------------------ 4. Active Authentication
    var activeAuthResult = stepResult(succeeded: false, skipped: true, reason: "Không được yêu cầu")
    if options.activeAuthentication {
      if let dg15 = files["DG15"] {
        progress("active_authentication", 0.88, nil, "Đang kiểm tra tính nguyên bản của chip…")
        let outcome = await ActiveAuthentication.perform(session: session, dg15: dg15)
        activeAuthResult = stepResult(
          succeeded: outcome.succeeded, skipped: outcome.skipped, reason: outcome.reason
        )
      } else {
        activeAuthResult = stepResult(succeeded: false, skipped: true, reason: "Thẻ không có DG15")
      }
    }

    // ------------------------------------------------ 5. Passive Authentication
    var passiveDictionary: [String: Any] = [
      "succeeded": false, "skipped": true, "reason": "Không được yêu cầu",
      "dataGroupHashesValid": false, "sodSignatureValid": false,
      "documentSignerTrusted": false, "mismatchedDataGroups": [String](),
    ]
    var sodFile: SODFile?
    if options.passiveAuthentication {
      progress("passive_authentication", 0.94, nil, "Đang kiểm tra chữ ký số…")
      if let sodBytes = files["SOD"], let parsed = SODParser.parse(sodBytes) {
        sodFile = parsed
        var dataGroups = [Int: Data]()
        for (name, bytes) in files {
          if let number = PassportReader.dataGroupNumbers[name] { dataGroups[number] = bytes }
        }
        passiveDictionary = PassiveAuthentication.verify(
          sod: parsed,
          dataGroups: dataGroups,
          cscaCertificates: options.cscaCertificates
        ).dictionary
      } else {
        passiveDictionary["skipped"] = false
        passiveDictionary["reason"] = "Không đọc/parse được EF.SOD"
      }
    }

    return buildResult(
      files: files,
      access: access,
      chipAuth: chipAuthResult,
      activeAuth: activeAuthResult,
      passive: passiveDictionary,
      sod: sodFile,
      duration: Date().timeIntervalSince(startedAt) * 1000
    )
  }

  // MARK: - Secure Messaging

  private struct AccessResult {
    let protocolName: String
    let paceOID: String?
    let cipher: String
  }

  private func establishSecureMessaging(session: TagSession) async throws -> AccessResult {
    var paceOID: String?

    if options.usePACE {
      progress("reading_card_access", 0.10, nil, "Đang đọc thông số bảo mật…")
      paceOID = try await attemptPACE(session: session)
    }

    progress("selecting_applet", 0.24, nil, "Đang mở ứng dụng eMRTD…")
    try await session.selectEmrtdApplet()

    if let oid = paceOID {
      let cipherName = oid.hasSuffix(".1") ? "DESede" : "AES"
      return AccessResult(protocolName: "PACE", paceOID: oid, cipher: cipherName)
    }

    guard options.allowBACFallback else {
      throw NfcPassportError(code: .paceFailed, message: "PACE thất bại và fallback BAC đang bị tắt")
    }
    guard !options.useCAN else {
      throw NfcPassportError(
        code: .paceFailed,
        message: "CAN chỉ dùng được với PACE, nhưng PACE không khả dụng trên thẻ này"
      )
    }

    progress("bac", 0.26, nil, "Đang thiết lập kênh bảo mật (BAC)…")
    session.secureMessaging = try await BAC.perform(
      session: session,
      documentNumber: options.documentNumber,
      dateOfBirth: options.dateOfBirth,
      dateOfExpiry: options.dateOfExpiry
    )
    return AccessResult(protocolName: "BAC", paceOID: nil, cipher: "DESede")
  }

  /// Trả về OID PACE nếu thành công; `nil` nghĩa là thẻ không hỗ trợ hoặc PACE
  /// hỏng vì lý do không phải sai khoá (khi đó fallback BAC vẫn có ý nghĩa).
  private func attemptPACE(session: TagSession) async throws -> String? {
    let cardAccess: Data
    do {
      cardAccess = try await session.readFile(fid: PassportReader.efCardAccess)
    } catch {
      return nil // Không có EF.CardAccess ⇒ thẻ chỉ hỗ trợ BAC.
    }

    let infos = PACEInfo.parse(securityInfos: cardAccess).filter { $0.isECDHGenericMapping }
    guard !infos.isEmpty else { return nil }

    let password: PACEPassword = options.useCAN
      ? .can(options.can)
      : .mrz(
          documentNumber: options.documentNumber,
          dateOfBirth: options.dateOfBirth,
          dateOfExpiry: options.dateOfExpiry
        )

    var lastError: NfcPassportError?
    for info in infos {
      progress("pace", 0.16, nil, "Đang thiết lập kênh bảo mật (PACE)…")
      do {
        session.secureMessaging = try await PACE.perform(
          session: session, info: info, password: password
        )
        return info.oid
      } catch let error as NfcPassportError {
        // Khoá sai thì BAC cũng sẽ hỏng — báo ngay để người dùng sửa MRZ.
        if error.code == .invalidMrzKey { throw error }
        lastError = error
        session.secureMessaging = nil
      }
    }

    if !options.allowBACFallback, let error = lastError { throw error }
    return nil
  }

  // MARK: - Đọc file

  private func readFiles(session: TagSession, into files: inout [String: Data]) async throws {
    var wanted = options.dataGroups
    if options.passiveAuthentication {
      wanted.insert("SOD")
      wanted.insert("COM")
    }
    wanted.remove("DG14") // đã đọc ở bước Chip Authentication

    var plan = PassportReader.readOrder.filter { wanted.contains($0) }
    if wanted.contains("SOD") { plan.append("SOD") }

    for (index, name) in plan.enumerated() {
      guard let fid = PassportReader.fileIds[name] else { continue }
      if files[name] != nil { continue }

      let fraction = 0.32 + 0.54 * (Double(index) / Double(max(plan.count, 1)))
      progress("reading_datagroup", fraction, name, "\(options.readingMessage) \(name)…")

      do {
        files[name] = try await session.readFile(fid: fid)
      } catch let error as NfcPassportError {
        // Mất thẻ là lỗi thật; file không tồn tại trên thẻ thì bỏ qua.
        if error.code == .tagLost || error.code == .cancelled { throw error }
      }
    }
  }

  // MARK: - Kết quả

  private func stepResult(succeeded: Bool, skipped: Bool, reason: String?) -> [String: Any] {
    var out: [String: Any] = ["succeeded": succeeded, "skipped": skipped]
    if let reason = reason { out["reason"] = reason }
    return out
  }

  private func buildResult(
    files: [String: Data],
    access: AccessResult,
    chipAuth: [String: Any],
    activeAuth: [String: Any],
    passive: [String: Any],
    sod: SODFile?,
    duration: Double
  ) -> [String: Any] {
    var result = [String: Any]()

    if let dg1 = files["DG1"], let mrz = DG1Parser.parse(dg1) {
      result["mrz"] = mrz.dictionary
    }
    if let dg13 = files["DG13"] {
      result["personal"] = DG13Parser.parse(dg13).dictionary
    }
    if options.includeImages {
      if let dg2 = files["DG2"], let image = ImageDataGroupParser.parseFace(dg2) {
        result["faceImage"] = imageDictionary(ImageTranscoder.toJPEG(image))
      }
      if let dg7 = files["DG7"], let image = ImageDataGroupParser.parseDisplayedImage(dg7) {
        result["signatureImage"] = imageDictionary(ImageTranscoder.toJPEG(image))
      }
    }

    var security: [String: Any] = [
      "accessProtocol": access.protocolName,
      "secureMessagingCipher": access.cipher,
      "chipAuthentication": chipAuth,
      "activeAuthentication": activeAuth,
      "passiveAuthentication": passive,
    ]
    if let oid = access.paceOID { security["paceOid"] = oid }
    result["security"] = security

    if let sod = sod {
      result["sod"] = sod.dictionary
    }
    if options.includeRawData {
      var raw = [String: String]()
      for (name, bytes) in files { raw[name] = bytes.hexString }
      result["raw"] = raw
    }

    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    result["readAt"] = formatter.string(from: Date())
    result["durationMs"] = duration
    return result
  }

  private func imageDictionary(_ image: ImageTranscoder.Result) -> [String: Any] {
    [
      "base64": image.base64,
      "mimeType": image.mimeType,
      "width": image.width,
      "height": image.height,
      "transcoded": image.transcoded,
    ]
  }
}
