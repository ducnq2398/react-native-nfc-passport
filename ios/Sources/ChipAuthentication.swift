import Foundation

/// `ChipAuthenticationPublicKeyInfo` trong DG14 (ICAO 9303 Part 11 §9.2.5).
struct CAPublicKeyInfo {
  let oid: String
  let keyId: Int?
  /// DER của `SubjectPublicKeyInfo`.
  let subjectPublicKeyInfo: Data
}

/// `ChipAuthenticationInfo` trong DG14 (§9.2.4).
struct CAInfo {
  let oid: String
  let version: Int
  let keyId: Int?
}

/// Chip Authentication — ICAO 9303 Part 11 §6.2.
///
/// Chứng minh chip nắm giữ private key tương ứng với public key trong DG14 (đã
/// được SOD ký), tức là chống được việc sao chép dữ liệu sang chip khác. Thành
/// công thì Secure Messaging được thay bằng bộ khoá phiên mới.
enum ChipAuthentication {

  private static let idPKPrefix = "0.4.0.127.0.7.2.2.1."
  private static let idCAPrefix = "0.4.0.127.0.7.2.2.3."

  // MARK: - Parse DG14

  static func parsePublicKeyInfos(dg14: Data) -> [CAPublicKeyInfo] {
    let roots = ASN1.parse(dg14)
    return ASN1.findSequences(withOIDPrefix: idPKPrefix, in: roots).compactMap { node in
      guard let oidNode = node.children.first,
            let oid = ASN1.decodeOID(oidNode.value),
            node.children.count >= 2
      else { return nil }
      let spki = node.children[1].encoded
      let keyId = node.children.count > 2 ? ASN1.decodeInteger(node.children[2].value) : nil
      return CAPublicKeyInfo(oid: oid, keyId: keyId, subjectPublicKeyInfo: spki)
    }
  }

  static func parseCAInfos(dg14: Data) -> [CAInfo] {
    let roots = ASN1.parse(dg14)
    return ASN1.findSequences(withOIDPrefix: idCAPrefix, in: roots).compactMap { node in
      guard let oidNode = node.children.first,
            let oid = ASN1.decodeOID(oidNode.value)
      else { return nil }
      let version = node.children.count > 1 ? (ASN1.decodeInteger(node.children[1].value) ?? 1) : 1
      let keyId = node.children.count > 2 ? ASN1.decodeInteger(node.children[2].value) : nil
      return CAInfo(oid: oid, version: version, keyId: keyId)
    }
  }

  static func cipher(forCAOID oid: String) -> SMCipher? {
    guard oid.hasPrefix(idCAPrefix) else { return nil }
    switch oid.split(separator: ".").last.flatMap({ Int($0) }) {
    case 1: return .desEDE
    case 2: return .aes128
    case 3: return .aes192
    case 4: return .aes256
    default: return nil
    }
  }

  /// Khi DG14 không kèm `ChipAuthenticationInfo`, suy ra OID từ loại khoá.
  /// AES-CBC-CMAC-128 là mặc định của mọi thẻ phát hành gần đây.
  static func inferCAOID(isEC: Bool) -> String {
    isEC ? "0.4.0.127.0.7.2.2.3.2.2" : "0.4.0.127.0.7.2.2.3.1.2"
  }

  // MARK: - Giao thức

  /// Thực hiện CA và trả về Secure Messaging mới, hoặc ném lỗi nếu thất bại.
  static func perform(session: TagSession, dg14: Data) async throws -> SecureMessaging {
    let publicKeyInfos = parsePublicKeyInfos(dg14: dg14)
    guard let publicKeyInfo = publicKeyInfos.first else {
      throw NfcPassportError(code: .parseError, message: "DG14 không có ChipAuthenticationPublicKeyInfo")
    }
    guard case let .ec(group, chipPointData) = SubjectPublicKeyInfoParser.parse(publicKeyInfo.subjectPublicKeyInfo) else {
      // Chip Authentication trên khoá DH (không phải EC) rất hiếm và không được
      // cài đặt; tầng trên sẽ ghi nhận bước này là thất bại chứ không dừng đọc.
      throw NfcPassportError(code: .parseError, message: "Chỉ hỗ trợ Chip Authentication trên khoá ECDH")
    }

    let caInfos = parseCAInfos(dg14: dg14)
    let caInfo = caInfos.first { $0.keyId == nil || $0.keyId == publicKeyInfo.keyId } ?? caInfos.first
    let oid = caInfo?.oid ?? inferCAOID(isEC: true)
    guard let smCipher = cipher(forCAOID: oid) else {
      throw NfcPassportError(code: .parseError, message: "OID Chip Authentication không nhận diện được: \(oid)")
    }

    guard let chipPoint = group.point(from: chipPointData),
          let ephemeral = group.generateKeyPair(),
          let ephemeralPublic = group.encode(ephemeral.publicPoint)
    else {
      throw NfcPassportError(code: .communicationError, message: "Không sinh được khoá tạm thời cho CA")
    }

    if smCipher == .desEDE {
      // CA v1 với 3DES dùng MSE:Set KAT, không có GENERAL AUTHENTICATE.
      var data = ASN1.encode(tag: 0x91, value: ephemeralPublic)
      if let keyId = publicKeyInfo.keyId {
        data += ASN1.encode(tag: 0x84, value: integerData(keyId))
      }
      let response = try await session.send(
        CommandAPDU(cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA6, data: data, ne: -1)
      )
      guard response.isSuccess else {
        throw NfcPassportError.fromStatusWord(response.sw, context: "MSE:Set KAT (CA)")
      }
    } else {
      var setAT = ASN1.encode(tag: 0x80, value: ASN1.encodeOID(oid) ?? Data())
      if let keyId = publicKeyInfo.keyId {
        setAT += ASN1.encode(tag: 0x84, value: integerData(keyId))
      }
      let mse = try await session.send(
        CommandAPDU(cla: 0x00, ins: 0x22, p1: 0x41, p2: 0xA4, data: setAT, ne: -1)
      )
      guard mse.isSuccess else {
        throw NfcPassportError.fromStatusWord(mse.sw, context: "MSE:Set AT (CA)")
      }

      let authData = ASN1.encode(tag: 0x7C, value: ASN1.encode(tag: 0x80, value: ephemeralPublic))
      let response = try await session.send(
        CommandAPDU(cla: 0x00, ins: 0x86, p1: 0x00, p2: 0x00, data: authData, ne: 256)
      )
      guard response.isSuccess else {
        throw NfcPassportError.fromStatusWord(response.sw, context: "GENERAL AUTHENTICATE (CA)")
      }
    }

    guard let sharedPoint = group.multiply(chipPoint, by: ephemeral.privateScalar),
          let sharedSecret = group.affineX(sharedPoint)
    else {
      throw NfcPassportError(code: .communicationError, message: "Tính khoá chia sẻ CA thất bại")
    }

    let ksEnc = Crypto.deriveKey(keySeed: sharedSecret, counter: 1, cipher: smCipher)
    let ksMac = Crypto.deriveKey(keySeed: sharedSecret, counter: 2, cipher: smCipher)
    return SecureMessaging(cipher: smCipher, ksEnc: ksEnc, ksMac: ksMac)
  }

  private static func integerData(_ value: Int) -> Data {
    var bytes = [UInt8]()
    var remaining = value
    repeat {
      bytes.insert(UInt8(remaining & 0xFF), at: 0)
      remaining >>= 8
    } while remaining > 0
    return Data(bytes)
  }
}
