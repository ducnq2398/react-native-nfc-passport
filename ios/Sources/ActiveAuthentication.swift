import Foundation
import Security

/// Active Authentication — ICAO 9303 Part 11 §6.1.
///
/// Chip ký một challenge ngẫu nhiên bằng private key ứng với public key trong
/// DG15. Chữ ký RSA theo ISO/IEC 9796-2 Digital Signature Scheme 1 có khôi phục
/// một phần thông điệp; thuật toán băm được suy ra từ byte trailer.
enum ActiveAuthentication {

  struct Outcome {
    let succeeded: Bool
    let skipped: Bool
    let reason: String?
  }

  /// Bảng hash-id trong trailer 2 byte của ISO/IEC 9796-2.
  private static let digestByTrailerId: [UInt8: Crypto.Digest] = [
    0x33: .sha1,
    0x34: .sha256,
    0x35: .sha512,
    0x36: .sha384,
    0x38: .sha224,
  ]

  static func perform(session: TagSession, dg15: Data) async -> Outcome {
    // DG15 ::= [APPLICATION 15] SubjectPublicKeyInfo
    guard let container = ASN1.parse(dg15).first, container.identifier == 0x6F,
          let parsed = SubjectPublicKeyInfoParser.parse(container.value)
    else {
      return Outcome(succeeded: false, skipped: false, reason: "Không parse được DG15")
    }

    guard case let .rsa(pkcs1) = parsed else {
      return Outcome(
        succeeded: false,
        skipped: true,
        reason: "Active Authentication trên khoá EC chưa được hỗ trợ trên iOS"
      )
    }

    let challenge = Crypto.randomBytes(8)
    let response: ResponseAPDU
    do {
      response = try await session.send(
        CommandAPDU(cla: 0x00, ins: 0x88, p1: 0x00, p2: 0x00, data: challenge, ne: 256)
      )
    } catch {
      return Outcome(succeeded: false, skipped: false, reason: "INTERNAL AUTHENTICATE thất bại: \(error)")
    }
    guard response.isSuccess, !response.data.isEmpty else {
      return Outcome(
        succeeded: false,
        skipped: false,
        reason: "INTERNAL AUTHENTICATE trả về SW=\(response.swHex)"
      )
    }

    guard let publicKey = makeRSAKey(pkcs1: pkcs1) else {
      return Outcome(succeeded: false, skipped: false, reason: "Không dựng được khoá RSA từ DG15")
    }

    guard let recovered = rawRSA(publicKey: publicKey, signature: response.data) else {
      return Outcome(succeeded: false, skipped: false, reason: "Không giải được chữ ký RSA")
    }

    let valid = verifyISO9796_2(recovered: recovered, challenge: challenge)
    return Outcome(
      succeeded: valid,
      skipped: false,
      reason: valid ? nil : "Chữ ký Active Authentication không hợp lệ"
    )
  }

  // MARK: - RSA

  private static func makeRSAKey(pkcs1: Data) -> SecKey? {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    ]
    return SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, nil)
  }

  /// `m = s^e mod n`. `rsaEncryptionRaw` với khoá công khai chính là phép luỹ
  /// thừa mô-đun thô, đúng thứ cần cho ISO 9796-2.
  private static func rawRSA(publicKey: SecKey, signature: Data) -> Data? {
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionRaw) else { return nil }
    var error: Unmanaged<CFError>?
    guard let result = SecKeyCreateEncryptedData(
      publicKey, .rsaEncryptionRaw, signature as CFData, &error
    ) else { return nil }
    return result as Data
  }

  private static func verifyISO9796_2(recovered: Data, challenge: Data) -> Bool {
    guard let header = recovered.first, header == 0x6A || header == 0x4A else { return false }
    guard let trailer = recovered.last else { return false }

    let digest: Crypto.Digest
    let trailerLength: Int
    switch trailer {
    case 0xBC:
      digest = .sha1
      trailerLength = 1
    case 0xCC:
      guard recovered.count >= 2 else { return false }
      let id = recovered[recovered.index(recovered.endIndex, offsetBy: -2)]
      guard let mapped = digestByTrailerId[id] else { return false }
      digest = mapped
      trailerLength = 2
    default:
      return false
    }

    let digestLength = digest.length
    let m1End = recovered.count - digestLength - trailerLength
    guard m1End > 1 else { return false }

    let base = recovered.startIndex
    let m1 = Data(recovered[recovered.index(base, offsetBy: 1)..<recovered.index(base, offsetBy: m1End)])
    let expected = Data(
      recovered[
        recovered.index(base, offsetBy: m1End)
          ..< recovered.index(base, offsetBy: m1End + digestLength)
      ]
    )

    let computed = Crypto.hash(digest, m1 + challenge)
    return computed == expected
  }
}
