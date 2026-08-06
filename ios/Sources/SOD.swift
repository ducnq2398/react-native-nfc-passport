import Foundation
import Security

/// EF.SOD đã parse — CMS SignedData bọc LDSSecurityObject.
struct SODFile {
  let digestAlgorithm: Crypto.Digest
  let digestAlgorithmName: String
  let signatureAlgorithmOID: String
  /// Hash từng DataGroup do SOD công bố (số DG → hash).
  let dataGroupHashes: [Int: Data]
  /// DER của `LDSSecurityObject` (eContent).
  let eContent: Data
  /// DER của chứng thư Document Signer, nếu có.
  let documentSignerDER: Data?

  let signerDigestAlgorithm: Crypto.Digest
  /// DER của signedAttrs đã đổi tag thành SET — chính là dữ liệu được ký.
  let signedData: Data
  let signature: Data
  /// Giá trị của attribute `messageDigest` trong signedAttrs.
  let messageDigestAttribute: Data?

  var dictionary: [String: Any] {
    var hashes = [String: String]()
    for (number, hash) in dataGroupHashes {
      hashes["DG\(number)"] = hash.hexString
    }
    var out: [String: Any] = [
      "digestAlgorithm": digestAlgorithmName,
      "signatureAlgorithm": signatureAlgorithmOID,
      "dataGroupHashes": hashes,
    ]
    if let der = documentSignerDER, let info = X509.describe(der) {
      out["documentSigner"] = info
    }
    return out
  }
}

enum SODParser {

  private static let oidSignedData = "1.2.840.113549.1.7.2"
  private static let oidMessageDigest = "1.2.840.113549.1.9.4"

  static func parse(_ sodBytes: Data) -> SODFile? {
    // EF.SOD ::= [APPLICATION 23] ContentInfo
    let roots = ASN1.parse(sodBytes)
    let contentInfoNode = roots.first(where: { $0.identifier == 0x77 })
      .flatMap { ASN1.parse($0.value).first } ?? roots.first
    guard let contentInfo = contentInfoNode, contentInfo.identifier == 0x30,
          let contentTypeNode = contentInfo.children.first,
          ASN1.decodeOID(contentTypeNode.value) == oidSignedData,
          contentInfo.children.count >= 2,
          let signedData = contentInfo.children[1].children.first,
          signedData.identifier == 0x30
    else { return nil }

    let items = signedData.children
    // version(0), digestAlgorithms(1), encapContentInfo(2), [0] certs, [1] crls, signerInfos
    guard items.count >= 3 else { return nil }

    // --- eContent → LDSSecurityObject ---
    let encapContentInfo = items[2]
    guard let eContentWrapper = encapContentInfo.children.last,
          let eContentOctets = eContentWrapper.children.first ?? ASN1.parse(eContentWrapper.value).first
    else { return nil }
    let eContent = eContentOctets.value

    guard let lds = ASN1.parse(eContent).first, lds.identifier == 0x30, lds.children.count >= 3
    else { return nil }
    guard let hashAlgorithmOID = lds.children[1].children.first.flatMap({ ASN1.decodeOID($0.value) }),
          let digest = Crypto.Digest.from(name: hashAlgorithmOID)
    else { return nil }

    var hashes = [Int: Data]()
    for entry in lds.children[2].children where entry.identifier == 0x30 && entry.children.count >= 2 {
      if let number = ASN1.decodeInteger(entry.children[0].value) {
        hashes[number] = entry.children[1].value
      }
    }

    // --- Chứng thư Document Signer ---
    var documentSignerDER: Data?
    for item in items where item.isContextSpecific && item.tagNumber == 0 {
      if let certificate = item.children.first(where: { $0.identifier == 0x30 }) {
        documentSignerDER = certificate.encoded
        break
      }
    }

    // --- SignerInfo ---
    guard let signerInfos = items.last(where: { $0.identifier == 0x31 }),
          let signerInfo = signerInfos.children.first(where: { $0.identifier == 0x30 })
    else { return nil }
    let signerItems = signerInfo.children
    guard signerItems.count >= 5 else { return nil }

    // version(0), sid(1), digestAlgorithm(2), [0] signedAttrs?, sigAlg, signature
    let signerDigestOID = signerItems[2].children.first.flatMap { ASN1.decodeOID($0.value) } ?? ""
    let signerDigest = Crypto.Digest.from(name: signerDigestOID) ?? digest

    var signedAttrsNode: ASN1Node?
    var signatureAlgorithmOID = ""
    var signature = Data()
    for (index, node) in signerItems.enumerated() where index >= 3 {
      if node.isContextSpecific, node.tagNumber == 0 {
        signedAttrsNode = node
      } else if node.identifier == 0x30, signatureAlgorithmOID.isEmpty {
        signatureAlgorithmOID = node.children.first.flatMap { ASN1.decodeOID($0.value) } ?? ""
      } else if node.identifier == 0x04 {
        signature = node.value
      }
    }

    var messageDigestAttribute: Data?
    var toBeSigned = eContent
    if let signedAttrs = signedAttrsNode {
      // Chữ ký được tính trên signedAttrs mã hoá lại với tag SET (0x31),
      // không phải tag ngữ cảnh [0] như khi truyền đi (RFC 5652 §5.4).
      toBeSigned = Data([0x31]) + ASN1.encodeLength(signedAttrs.value.count) + signedAttrs.value
      for attribute in signedAttrs.children where attribute.identifier == 0x30 {
        guard let oidNode = attribute.children.first,
              ASN1.decodeOID(oidNode.value) == oidMessageDigest,
              let valueSet = attribute.children.last,
              let octet = valueSet.children.first
        else { continue }
        messageDigestAttribute = octet.value
      }
    }

    return SODFile(
      digestAlgorithm: digest,
      digestAlgorithmName: digest.rawValue,
      signatureAlgorithmOID: signatureAlgorithmOID,
      dataGroupHashes: hashes,
      eContent: eContent,
      documentSignerDER: documentSignerDER,
      signerDigestAlgorithm: signerDigest,
      signedData: toBeSigned,
      signature: signature,
      messageDigestAttribute: messageDigestAttribute
    )
  }
}

/// Passive Authentication — ICAO 9303 Part 11 §5.1.
enum PassiveAuthentication {

  struct Result {
    var succeeded = false
    var dataGroupHashesValid = false
    var sodSignatureValid = false
    var documentSignerTrusted = false
    var mismatchedDataGroups: [String] = []
    var reason: String?

    var dictionary: [String: Any] {
      var out: [String: Any] = [
        "succeeded": succeeded,
        "skipped": false,
        "dataGroupHashesValid": dataGroupHashesValid,
        "sodSignatureValid": sodSignatureValid,
        "documentSignerTrusted": documentSignerTrusted,
        "mismatchedDataGroups": mismatchedDataGroups,
      ]
      if let reason = reason { out["reason"] = reason }
      return out
    }
  }

  static func verify(
    sod: SODFile,
    dataGroups: [Int: Data],
    cscaCertificates: [String]
  ) -> Result {
    var result = Result()
    var reasons = [String]()

    // --- 1. Hash các DataGroup ---
    var checked = 0
    for (number, expected) in sod.dataGroupHashes {
      guard let raw = dataGroups[number] else { continue }
      checked += 1
      if Crypto.hash(sod.digestAlgorithm, raw) != expected {
        result.mismatchedDataGroups.append("DG\(number)")
      }
    }
    result.dataGroupHashesValid = checked > 0 && result.mismatchedDataGroups.isEmpty
    if checked == 0 { reasons.append("Không có DataGroup nào để đối chiếu hash") }
    if !result.mismatchedDataGroups.isEmpty {
      reasons.append("Hash không khớp: \(result.mismatchedDataGroups.joined(separator: ", "))")
    }

    // --- 2. Chữ ký CMS ---
    if let expectedDigest = sod.messageDigestAttribute {
      let actual = Crypto.hash(sod.signerDigestAlgorithm, sod.eContent)
      if actual != expectedDigest {
        reasons.append("messageDigest trong signedAttrs không khớp với eContent")
      }
    }

    if let certDER = sod.documentSignerDER,
       let certificate = SecCertificateCreateWithData(nil, certDER as CFData),
       let publicKey = SecCertificateCopyKey(certificate) {
      result.sodSignatureValid = verifySignature(
        publicKey: publicKey,
        signedData: sod.signedData,
        signature: sod.signature,
        signatureAlgorithmOID: sod.signatureAlgorithmOID,
        digest: sod.signerDigestAlgorithm
      )
      if !result.sodSignatureValid {
        reasons.append("Chữ ký EF.SOD không hợp lệ hoặc dùng thuật toán iOS không hỗ trợ")
      }

      // --- 3. Chuỗi tin cậy tới CSCA ---
      if !cscaCertificates.isEmpty {
        result.documentSignerTrusted = isTrusted(
          certificate: certificate,
          anchors: cscaCertificates
        )
        if !result.documentSignerTrusted {
          reasons.append("DSC không khớp với CSCA nào được cung cấp")
        }
      }
    } else {
      reasons.append("EF.SOD không chứa chứng thư Document Signer")
    }

    result.succeeded = result.dataGroupHashesValid && result.sodSignatureValid
      && (cscaCertificates.isEmpty || result.documentSignerTrusted)
    result.reason = reasons.isEmpty ? nil : reasons.joined(separator: "; ")
    return result
  }

  private static func verifySignature(
    publicKey: SecKey,
    signedData: Data,
    signature: Data,
    signatureAlgorithmOID: String,
    digest: Crypto.Digest
  ) -> Bool {
    for algorithm in candidateAlgorithms(oid: signatureAlgorithmOID, digest: digest) {
      guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else { continue }
      var error: Unmanaged<CFError>?
      if SecKeyVerifySignature(
        publicKey, algorithm, signedData as CFData, signature as CFData, &error
      ) {
        return true
      }
    }
    return false
  }

  /// Ánh xạ OID thuật toán chữ ký sang `SecKeyAlgorithm`. Với `rsaEncryption`
  /// chung chung, thuật toán băm lấy từ `digestAlgorithm` của SignerInfo.
  private static func candidateAlgorithms(
    oid: String,
    digest: Crypto.Digest
  ) -> [SecKeyAlgorithm] {
    switch oid {
    case "1.2.840.113549.1.1.5": return [.rsaSignatureMessagePKCS1v15SHA1]
    case "1.2.840.113549.1.1.11": return [.rsaSignatureMessagePKCS1v15SHA256]
    case "1.2.840.113549.1.1.12": return [.rsaSignatureMessagePKCS1v15SHA384]
    case "1.2.840.113549.1.1.13": return [.rsaSignatureMessagePKCS1v15SHA512]
    case "1.2.840.113549.1.1.14": return [.rsaSignatureMessagePKCS1v15SHA224]
    case "1.2.840.10045.4.1": return [.ecdsaSignatureMessageX962SHA1]
    case "1.2.840.10045.4.3.1": return [.ecdsaSignatureMessageX962SHA224]
    case "1.2.840.10045.4.3.2": return [.ecdsaSignatureMessageX962SHA256]
    case "1.2.840.10045.4.3.3": return [.ecdsaSignatureMessageX962SHA384]
    case "1.2.840.10045.4.3.4": return [.ecdsaSignatureMessageX962SHA512]
    case "1.2.840.113549.1.1.10": // RSASSA-PSS
      switch digest {
      case .sha1: return [.rsaSignatureMessagePSSSHA1]
      case .sha224: return [.rsaSignatureMessagePSSSHA224]
      case .sha256: return [.rsaSignatureMessagePSSSHA256]
      case .sha384: return [.rsaSignatureMessagePSSSHA384]
      case .sha512: return [.rsaSignatureMessagePSSSHA512]
      }
    default:
      // rsaEncryption (1.2.840.113549.1.1.1) và các trường hợp còn lại.
      switch digest {
      case .sha1: return [.rsaSignatureMessagePKCS1v15SHA1, .ecdsaSignatureMessageX962SHA1]
      case .sha224: return [.rsaSignatureMessagePKCS1v15SHA224, .ecdsaSignatureMessageX962SHA224]
      case .sha256: return [.rsaSignatureMessagePKCS1v15SHA256, .ecdsaSignatureMessageX962SHA256]
      case .sha384: return [.rsaSignatureMessagePKCS1v15SHA384, .ecdsaSignatureMessageX962SHA384]
      case .sha512: return [.rsaSignatureMessagePKCS1v15SHA512, .ecdsaSignatureMessageX962SHA512]
      }
    }
  }

  private static func isTrusted(certificate: SecCertificate, anchors: [String]) -> Bool {
    let anchorCertificates = anchors.compactMap { source -> SecCertificate? in
      guard let der = X509.der(fromPEMOrBase64: source) else { return nil }
      return SecCertificateCreateWithData(nil, der as CFData)
    }
    guard !anchorCertificates.isEmpty else { return false }

    var trust: SecTrust?
    let policy = SecPolicyCreateBasicX509()
    guard SecTrustCreateWithCertificates([certificate] as CFArray, policy, &trust) == errSecSuccess,
          let trust = trust
    else { return false }

    SecTrustSetAnchorCertificates(trust, anchorCertificates as CFArray)
    SecTrustSetAnchorCertificatesOnly(trust, true)
    // CSCA và DSC của eMRTD thường đã hết hạn so với thời điểm quét mà vẫn hợp lệ
    // cho tài liệu đã ký; bỏ qua ràng buộc thời gian là hành vi chuẩn của PA.
    SecTrustSetVerifyDate(trust, Date(timeIntervalSince1970: 0) as CFDate)

    var error: CFError?
    return SecTrustEvaluateWithError(trust, &error)
  }
}

/// Trích thông tin hiển thị từ chứng thư X.509.
enum X509 {

  static func der(fromPEMOrBase64 source: String) -> Data? {
    if source.contains("-----BEGIN") {
      let body = source
        .components(separatedBy: "-----BEGIN CERTIFICATE-----").last?
        .components(separatedBy: "-----END CERTIFICATE-----").first?
        .replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
      return body.flatMap { Data(base64Encoded: $0) }
    }
    let clean = source.replacingOccurrences(of: "\\s", with: "", options: .regularExpression)
    return Data(base64Encoded: clean)
  }

  private static let shortNames: [String: String] = [
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "SERIALNUMBER",
    "1.2.840.113549.1.9.1": "E",
  ]

  static func describe(_ der: Data) -> [String: Any]? {
    guard let certificate = ASN1.parse(der).first,
          let tbs = certificate.children.first,
          tbs.identifier == 0x30
    else { return nil }

    var items = tbs.children
    // Trường version là [0] EXPLICIT và optional.
    if let first = items.first, first.isContextSpecific, first.tagNumber == 0 {
      items = Array(items.dropFirst())
    }
    guard items.count >= 6 else { return nil }

    let serial = items[0].value.hexString
    let issuer = name(from: items[2])
    let validity = items[3]
    let subject = name(from: items[4])

    var out: [String: Any] = [
      "subject": subject,
      "issuer": issuer,
      "serialNumber": serial,
    ]
    if validity.children.count >= 2 {
      out["notBefore"] = time(from: validity.children[0]) ?? ""
      out["notAfter"] = time(from: validity.children[1]) ?? ""
    }
    return out
  }

  private static func name(from node: ASN1Node) -> String {
    var parts = [String]()
    for rdn in node.children {
      for attribute in rdn.children where attribute.children.count >= 2 {
        guard let oid = ASN1.decodeOID(attribute.children[0].value),
              let value = String(data: attribute.children[1].value, encoding: .utf8)
        else { continue }
        parts.append("\(shortNames[oid] ?? oid)=\(value)")
      }
    }
    return parts.joined(separator: ", ")
  }

  /// UTCTime (`YYMMDDHHMMSSZ`) hoặc GeneralizedTime (`YYYYMMDDHHMMSSZ`) → ISO 8601.
  private static func time(from node: ASN1Node) -> String? {
    guard let text = String(data: node.value, encoding: .utf8) else { return nil }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(identifier: "UTC")
    formatter.dateFormat = node.identifier == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
    guard let date = formatter.date(from: text) else { return text }

    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime]
    return iso.string(from: date)
  }
}
