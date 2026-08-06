import Foundation

/// Public key đã parse từ `SubjectPublicKeyInfo` (RFC 5280).
enum ParsedPublicKey {
  /// Đường cong elliptic: nhóm + điểm dạng uncompressed.
  case ec(group: ECGroup, point: Data)
  /// RSA: DER của `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`.
  case rsa(pkcs1: Data)
}

enum SubjectPublicKeyInfoParser {

  private static let idECPublicKey = "1.2.840.10045.2.1"
  private static let idRSAEncryption = "1.2.840.113549.1.1.1"
  private static let idPrimeField = "1.2.840.10045.1.1"

  /// - Parameter der: DER của `SubjectPublicKeyInfo`.
  static func parse(_ der: Data) -> ParsedPublicKey? {
    guard let spki = ASN1.parse(der).first, spki.identifier == 0x30,
          spki.children.count >= 2,
          let algorithm = spki.children.first, algorithm.identifier == 0x30,
          let algorithmOIDNode = algorithm.children.first,
          let algorithmOID = ASN1.decodeOID(algorithmOIDNode.value)
    else { return nil }

    // BIT STRING: byte đầu là số bit thừa, luôn 0 với khoá công khai.
    guard let bitString = spki.children.last, bitString.identifier == 0x03,
          bitString.value.count > 1
    else { return nil }
    let keyBytes = Data(bitString.value.dropFirst())

    switch algorithmOID {
    case idRSAEncryption:
      return .rsa(pkcs1: keyBytes)

    case idECPublicKey:
      guard algorithm.children.count >= 2 else { return nil }
      let parameters = algorithm.children[1]
      guard let group = ecGroup(from: parameters) else { return nil }
      return .ec(group: group, point: keyBytes)

    default:
      return nil
    }
  }

  /// `ECParameters` có thể là OID đường cong có tên hoặc SEQUENCE tham số đầy đủ.
  private static func ecGroup(from parameters: ASN1Node) -> ECGroup? {
    if parameters.identifier == 0x06 {
      guard let oid = ASN1.decodeOID(parameters.value),
            let nid = ECGroup.nid(forCurveOID: oid)
      else { return nil }
      return ECGroup(nid: nid)
    }

    guard parameters.identifier == 0x30, parameters.children.count >= 5 else { return nil }
    let items = parameters.children

    // items[0] = version, items[1] = fieldID, items[2] = curve,
    // items[3] = base point, items[4] = order, items[5] = cofactor (optional)
    guard items[1].identifier == 0x30,
          items[1].children.count >= 2,
          let fieldTypeOID = ASN1.decodeOID(items[1].children[0].value),
          fieldTypeOID == idPrimeField
    else { return nil }

    let primeP = stripLeadingZero(items[1].children[1].value)
    guard items[2].identifier == 0x30, items[2].children.count >= 2 else { return nil }
    let a = items[2].children[0].value
    let b = items[2].children[1].value
    let base = items[3].value
    let order = stripLeadingZero(items[4].value)
    let cofactor = items.count > 5 ? stripLeadingZero(items[5].value) : Data([0x01])

    return ECGroup(primeP: primeP, a: a, b: b, generator: base, order: order, cofactor: cofactor)
  }

  /// INTEGER của DER có thể mang byte 0x00 ở đầu để giữ dấu dương.
  private static func stripLeadingZero(_ data: Data) -> Data {
    guard let first = data.first, first == 0x00, data.count > 1 else { return data }
    return Data(data.dropFirst())
  }
}
