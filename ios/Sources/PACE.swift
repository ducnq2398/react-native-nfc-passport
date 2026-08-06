import Foundation

/// Một `PACEInfo` đọc từ EF.CardAccess (ICAO 9303 Part 11 §9.2.1).
struct PACEInfo {
  let oid: String
  let version: Int
  let parameterId: Int?

  private static let idPACEPrefix = "0.4.0.127.0.7.2.2.4."

  /// Bộ mã hoá dùng cho Secure Messaging sau khi PACE thành công.
  var cipher: SMCipher? {
    guard oid.hasPrefix(PACEInfo.idPACEPrefix) else { return nil }
    let suffix = oid.dropFirst(PACEInfo.idPACEPrefix.count).split(separator: ".")
    guard let cipherId = suffix.last.flatMap({ Int($0) }) else { return nil }
    switch cipherId {
    case 1: return .desEDE
    case 2: return .aes128
    case 3: return .aes192
    case 4: return .aes256
    default: return nil
    }
  }

  /// `true` nếu là biến thể ECDH Generic Mapping — biến thể duy nhất được cài đặt.
  var isECDHGenericMapping: Bool {
    oid.hasPrefix(PACEInfo.idPACEPrefix + "2.")
  }

  /// Parse SET OF SecurityInfo (EF.CardAccess hoặc DG14).
  static func parse(securityInfos data: Data) -> [PACEInfo] {
    let roots = ASN1.parse(data)
    let sequences = ASN1.findSequences(withOIDPrefix: idPACEPrefix, in: roots)
    return sequences.compactMap { node in
      guard let oidNode = node.children.first,
            let oid = ASN1.decodeOID(oidNode.value)
      else { return nil }
      let version = node.children.count > 1 ? (ASN1.decodeInteger(node.children[1].value) ?? 2) : 2
      let parameterId = node.children.count > 2 ? ASN1.decodeInteger(node.children[2].value) : nil
      return PACEInfo(oid: oid, version: version, parameterId: parameterId)
    }
  }
}

/// Mật khẩu dùng cho PACE.
enum PACEPassword {
  case mrz(documentNumber: String, dateOfBirth: String, dateOfExpiry: String)
  case can(String)

  /// Tham chiếu mật khẩu trong MSE:Set AT (ICAO 9303 Part 11 Table 4).
  var reference: UInt8 {
    switch self {
    case .mrz: return 0x01
    case .can: return 0x02
    }
  }

  /// π — dữ liệu đầu vào của KDF.
  var seed: Data {
    switch self {
    case let .mrz(documentNumber, dateOfBirth, dateOfExpiry):
      let info = BAC.mrzInformation(
        documentNumber: documentNumber,
        dateOfBirth: dateOfBirth,
        dateOfExpiry: dateOfExpiry
      )
      return Crypto.hash(.sha1, Data(info.utf8))
    case let .can(can):
      return Data(can.utf8)
    }
  }
}

/// PACE với Generic Mapping trên ECDH — ICAO 9303 Part 11 §4.4.
///
/// Các bộ tham số MODP-DH (parameterId 0/1/2) **không** được hỗ trợ; khi gặp,
/// hàm ném lỗi để tầng trên fallback sang BAC. Thẻ CCCD Việt Nam dùng đường cong
/// elliptic nên nhánh này không được kích hoạt trong thực tế.
enum PACE {

  static func perform(
    session: TagSession,
    info: PACEInfo,
    password: PACEPassword
  ) async throws -> SecureMessaging {

    guard info.isECDHGenericMapping else {
      throw NfcPassportError(
        code: .paceFailed,
        message: "Chỉ hỗ trợ PACE-ECDH-GM, thẻ yêu cầu \(info.oid)"
      )
    }
    guard let cipher = info.cipher else {
      throw NfcPassportError(code: .paceFailed, message: "OID PACE không nhận diện được: \(info.oid)")
    }
    guard let parameterId = info.parameterId,
          let nid = ECGroup.nid(forStandardizedParameterId: parameterId),
          let group = ECGroup(nid: nid)
    else {
      throw NfcPassportError(
        code: .paceFailed,
        message: "Không hỗ trợ bộ tham số miền \(info.parameterId.map(String.init) ?? "mặc định")"
      )
    }

    // --- Kπ ---
    let kPi = Crypto.deriveKey(keySeed: password.seed, counter: 3, cipher: cipher)

    // --- MSE:Set AT ---
    try await sendMSESetAT(session: session, oid: info.oid, passwordReference: password.reference)

    // --- Bước 1: nonce đã mã hoá ---
    let encryptedNonce = try await generalAuthenticate(
      session: session,
      data: ASN1.encode(tag: 0x7C, value: Data()),
      expectedTag: 0x80,
      isLast: false
    )
    let nonce = try decryptNonce(encryptedNonce, key: kPi, cipher: cipher)

    // --- Bước 2: Generic Mapping ---
    guard let mappingKeyPair = group.generateKeyPair(),
          let mappingPublic = group.encode(mappingKeyPair.publicPoint)
    else {
      throw NfcPassportError(code: .paceFailed, message: "Không sinh được khoá tạm thời cho mapping")
    }

    let piccMappingRaw = try await generalAuthenticate(
      session: session,
      data: ASN1.encode(tag: 0x7C, value: ASN1.encode(tag: 0x81, value: mappingPublic)),
      expectedTag: 0x82,
      isLast: false
    )
    guard let piccMappingPoint = group.point(from: piccMappingRaw),
          let h = group.multiply(piccMappingPoint, by: mappingKeyPair.privateScalar),
          let generator = group.generator,
          let sTimesG = group.multiply(generator, by: nonce),
          let mappedGenerator = group.add(sTimesG, h),
          let mappedGroup = group.withGenerator(mappedGenerator)
    else {
      throw NfcPassportError(code: .paceFailed, message: "Generic Mapping thất bại")
    }

    // --- Bước 3: trao đổi khoá trên generator mới ---
    guard let ephemeral = mappedGroup.generateKeyPair(),
          let ephemeralPublic = mappedGroup.encode(ephemeral.publicPoint)
    else {
      throw NfcPassportError(code: .paceFailed, message: "Không sinh được khoá tạm thời cho ECDH")
    }

    let piccPublicRaw = try await generalAuthenticate(
      session: session,
      data: ASN1.encode(tag: 0x7C, value: ASN1.encode(tag: 0x83, value: ephemeralPublic)),
      expectedTag: 0x84,
      isLast: false
    )
    guard let piccPublicPoint = mappedGroup.point(from: piccPublicRaw),
          let sharedPoint = mappedGroup.multiply(piccPublicPoint, by: ephemeral.privateScalar),
          let sharedSecret = mappedGroup.affineX(sharedPoint)
    else {
      throw NfcPassportError(code: .paceFailed, message: "Tính khoá chia sẻ ECDH thất bại")
    }

    let ksEnc = Crypto.deriveKey(keySeed: sharedSecret, counter: 1, cipher: cipher)
    let ksMac = Crypto.deriveKey(keySeed: sharedSecret, counter: 2, cipher: cipher)

    // --- Bước 4: xác thực lẫn nhau ---
    let tokenPCD = try authenticationToken(
      oid: info.oid, publicKey: piccPublicRaw, key: ksMac, cipher: cipher
    )
    let tokenPICC = try await generalAuthenticate(
      session: session,
      data: ASN1.encode(tag: 0x7C, value: ASN1.encode(tag: 0x85, value: tokenPCD)),
      expectedTag: 0x86,
      isLast: true
    )
    let expectedPICC = try authenticationToken(
      oid: info.oid, publicKey: ephemeralPublic, key: ksMac, cipher: cipher
    )
    guard tokenPICC == expectedPICC else {
      throw NfcPassportError(
        code: .paceFailed,
        message: "Token xác thực của chip không khớp — kênh PACE không tin cậy"
      )
    }

    // SSC bắt đầu từ 0 sau PACE (ICAO 9303 Part 11 §9.8.6.3).
    return SecureMessaging(cipher: cipher, ksEnc: ksEnc, ksMac: ksMac)
  }

  // MARK: - Các bước APDU

  private static func sendMSESetAT(
    session: TagSession,
    oid: String,
    passwordReference: UInt8
  ) async throws {
    guard let oidBytes = ASN1.encodeOID(oid) else {
      throw NfcPassportError(code: .paceFailed, message: "OID PACE không mã hoá được")
    }
    // '80' = cryptographic mechanism reference, '83' = password reference.
    let data = ASN1.encode(tag: 0x80, value: oidBytes)
      + ASN1.encode(tag: 0x83, value: Data([passwordReference]))

    let response = try await session.send(
      CommandAPDU(cla: 0x00, ins: 0x22, p1: 0xC1, p2: 0xA4, data: data, ne: -1)
    )
    guard response.isSuccess else {
      let mapped = NfcPassportError.fromStatusWord(response.sw, context: "MSE:Set AT (PACE)")
      if mapped.code == .invalidMrzKey { throw mapped }
      throw NfcPassportError(code: .paceFailed, message: mapped.message, statusWord: mapped.statusWord)
    }
  }

  /// Gửi một bước GENERAL AUTHENTICATE và trả về value của tag mong đợi.
  private static func generalAuthenticate(
    session: TagSession,
    data: Data,
    expectedTag: UInt8,
    isLast: Bool
  ) async throws -> Data {
    // Command chaining: mọi bước trừ bước cuối dùng CLA '10'.
    let response = try await session.send(
      CommandAPDU(cla: isLast ? 0x00 : 0x10, ins: 0x86, p1: 0x00, p2: 0x00, data: data, ne: 256)
    )
    guard response.isSuccess else {
      let mapped = NfcPassportError.fromStatusWord(response.sw, context: "GENERAL AUTHENTICATE")
      if mapped.code == .invalidMrzKey { throw mapped }
      throw NfcPassportError(code: .paceFailed, message: mapped.message, statusWord: mapped.statusWord)
    }

    let nodes = ASN1.parse(response.data)
    guard let dynamicData = nodes.first(where: { $0.identifier == 0x7C }) else {
      throw NfcPassportError(code: .paceFailed, message: "Phản hồi PACE thiếu Dynamic Authentication Data")
    }
    guard let element = dynamicData.children.first(where: { $0.identifier == expectedTag }) else {
      throw NfcPassportError(
        code: .paceFailed,
        message: String(format: "Phản hồi PACE thiếu tag '%02X'", expectedTag)
      )
    }
    return element.value
  }

  private static func decryptNonce(_ encrypted: Data, key: Data, cipher: SMCipher) throws -> Data {
    let iv = Data(repeating: 0, count: cipher.blockSize)
    switch cipher {
    case .desEDE:
      return try Crypto.tripleDESCBC(encrypted, key: key, iv: iv, encrypt: false)
    default:
      return try Crypto.aesCBC(encrypted, key: key, iv: iv, encrypt: false)
    }
  }

  /// Token xác thực = MAC trên `7F49 { 06 OID, 86 publicPoint }`.
  private static func authenticationToken(
    oid: String,
    publicKey: Data,
    key: Data,
    cipher: SMCipher
  ) throws -> Data {
    guard let oidBytes = ASN1.encodeOID(oid) else {
      throw NfcPassportError(code: .paceFailed, message: "OID PACE không mã hoá được")
    }
    let body = ASN1.encode(tag: 0x06, value: oidBytes) + ASN1.encode(tag: 0x86, value: publicKey)
    let encoded = ASN1.encode(tag: 0x7F49, value: body)

    switch cipher {
    case .desEDE:
      return try Crypto.retailMAC(encoded, key: key)
    default:
      return Data(try Crypto.aesCMAC(encoded, key: key).prefix(8))
    }
  }
}
