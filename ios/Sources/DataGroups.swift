import Foundation
import ImageIO
import UIKit

// MARK: - DG1 / MRZ

struct MRZData {
  var raw: String = ""
  var format: String = "UNKNOWN"
  var documentCode: String = ""
  var issuingState: String = ""
  var documentNumber: String = ""
  var primaryIdentifier: String = ""
  var secondaryIdentifier: String = ""
  var nationality: String = ""
  var dateOfBirth: String = ""
  var gender: String = "<"
  var dateOfExpiry: String = ""
  var optionalData1: String = ""
  var optionalData2: String = ""

  var dictionary: [String: Any] {
    [
      "raw": raw, "format": format, "documentCode": documentCode,
      "issuingState": issuingState, "documentNumber": documentNumber,
      "primaryIdentifier": primaryIdentifier, "secondaryIdentifier": secondaryIdentifier,
      "nationality": nationality, "dateOfBirth": dateOfBirth, "gender": gender,
      "dateOfExpiry": dateOfExpiry, "optionalData1": optionalData1,
      "optionalData2": optionalData2,
    ]
  }
}

enum DG1Parser {

  /// DG1 ::= [APPLICATION 1] { '5F1F' MRZ }
  static func parse(_ dg1: Data) -> MRZData? {
    guard let container = ASN1.parse(dg1).first, container.identifier == 0x61,
          let mrzNode = container.children.first,
          let text = String(data: mrzNode.value, encoding: .utf8)
    else { return nil }
    return parseMRZString(text)
  }

  static func parseMRZString(_ text: String) -> MRZData {
    let compact = text.uppercased().filter { $0.isLetter || $0.isNumber || $0 == "<" }
    var result = MRZData()

    func clean(_ value: Substring) -> String {
      value.replacingOccurrences(of: "<", with: " ")
        .trimmingCharacters(in: .whitespaces)
        .replacingOccurrences(of: "  +", with: " ", options: .regularExpression)
    }
    func names(_ field: Substring) -> (String, String) {
      let parts = field.components(separatedBy: "<<")
      let primary = clean(Substring(parts.first ?? ""))
      let secondary = clean(Substring(parts.count > 1 ? parts[1] : ""))
      return (primary, secondary)
    }
    func slice(_ source: String, _ from: Int, _ to: Int) -> Substring {
      let start = source.index(source.startIndex, offsetBy: min(from, source.count))
      let end = source.index(source.startIndex, offsetBy: min(to, source.count))
      return source[start..<end]
    }

    switch compact.count {
    case 90: // TD1 — 3 × 30, định dạng của CCCD Việt Nam
      let l1 = String(slice(compact, 0, 30))
      let l2 = String(slice(compact, 30, 60))
      let l3 = String(slice(compact, 60, 90))
      result.raw = [l1, l2, l3].joined(separator: "\n")
      result.format = "TD1"
      result.documentCode = clean(slice(l1, 0, 2))
      result.issuingState = clean(slice(l1, 2, 5))

      let first9 = String(slice(l1, 5, 14))
      let checkDigit = String(slice(l1, 14, 15))
      let optional1 = String(slice(l1, 15, 30))
      if checkDigit == "<", let terminator = optional1.firstIndex(of: "<") {
        // Số giấy tờ dài hơn 9 ký tự tràn sang optional data (ICAO 9303 Part 5).
        let extension_ = String(optional1[optional1.startIndex..<terminator])
        result.documentNumber = first9 + String(extension_.dropLast())
        result.optionalData1 = clean(Substring(optional1[terminator...].dropFirst()))
      } else {
        result.documentNumber = first9.replacingOccurrences(of: "<", with: "")
        result.optionalData1 = clean(Substring(optional1))
      }

      result.dateOfBirth = String(slice(l2, 0, 6))
      result.gender = String(slice(l2, 7, 8))
      result.dateOfExpiry = String(slice(l2, 8, 14))
      result.nationality = clean(slice(l2, 15, 18))
      result.optionalData2 = clean(slice(l2, 18, 29))
      (result.primaryIdentifier, result.secondaryIdentifier) = names(slice(l3, 0, 30))

    case 72, 88: // TD2 (2 × 36) và TD3 (2 × 44)
      let lineLength = compact.count / 2
      let l1 = String(slice(compact, 0, lineLength))
      let l2 = String(slice(compact, lineLength, compact.count))
      result.raw = [l1, l2].joined(separator: "\n")
      result.format = lineLength == 44 ? "TD3" : "TD2"
      result.documentCode = clean(slice(l1, 0, 2))
      result.issuingState = clean(slice(l1, 2, 5))
      (result.primaryIdentifier, result.secondaryIdentifier) = names(slice(l1, 5, lineLength))
      result.documentNumber = String(slice(l2, 0, 9)).replacingOccurrences(of: "<", with: "")
      result.nationality = clean(slice(l2, 10, 13))
      result.dateOfBirth = String(slice(l2, 13, 19))
      result.gender = String(slice(l2, 20, 21))
      result.dateOfExpiry = String(slice(l2, 21, 27))
      result.optionalData1 = clean(slice(l2, 28, lineLength == 44 ? 42 : 35))

    default:
      result.raw = compact
    }

    return result
  }
}

// MARK: - Ảnh sinh trắc (DG2 / DG5 / DG7)

struct BiometricImage {
  let data: Data
  let mimeType: String
  let width: Int
  let height: Int
}

enum ImageDataGroupParser {

  /// DG2 ::= [APPLICATION 21] CBEFF chứa bản ghi ISO/IEC 19794-5.
  static func parseFace(_ dg2: Data) -> BiometricImage? {
    let roots = ASN1.parse(dg2)
    // Khối dữ liệu sinh trắc mang tag '5F2E' (primitive) hoặc '7F2E' (constructed).
    guard let block = findBiometricDataBlock(roots) else { return nil }
    return parseISO19794_5(block)
  }

  /// DG7 ::= [APPLICATION 7] { '02' count, '5F43' ảnh chữ ký }
  static func parseDisplayedImage(_ data: Data) -> BiometricImage? {
    let roots = ASN1.parse(data)
    guard let container = roots.first else { return nil }
    for child in container.children where child.identifier == 0x5F {
      if !child.value.isEmpty {
        return BiometricImage(
          data: child.value,
          mimeType: sniffMimeType(child.value),
          width: 0,
          height: 0
        )
      }
    }
    return nil
  }

  private static func findBiometricDataBlock(_ nodes: [ASN1Node]) -> Data? {
    for node in nodes {
      // '5F2E' → identifier 0x5F + tagNumber 0x2E; '7F2E' → 0x7F + 0x2E.
      if (node.identifier == 0x5F || node.identifier == 0x7F), node.tagNumber == 0x2E {
        return node.value
      }
      if let found = findBiometricDataBlock(node.children) { return found }
    }
    return nil
  }

  /// Bản ghi Face Image của ISO/IEC 19794-5.
  private static func parseISO19794_5(_ record: Data) -> BiometricImage? {
    let bytes = [UInt8](record)
    // 'F' 'A' 'C' 0x00 + version 4 byte + độ dài 4 byte + số ảnh 2 byte.
    guard bytes.count > 14,
          bytes[0] == 0x46, bytes[1] == 0x41, bytes[2] == 0x43
    else {
      // Một số thẻ đặt thẳng JPEG/JP2 vào block, không có header CBEFF.
      return BiometricImage(data: record, mimeType: sniffMimeType(record), width: 0, height: 0)
    }

    var offset = 14
    guard bytes.count > offset + 20 else { return nil }

    // Facial Information Block: 20 byte, trong đó byte 4-5 là số feature point.
    let featurePointCount = Int(bytes[offset + 4]) << 8 | Int(bytes[offset + 5])
    offset += 20
    offset += featurePointCount * 8

    // Image Information Block: 12 byte.
    guard bytes.count > offset + 12 else { return nil }
    let imageDataType = bytes[offset + 1]
    let width = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
    let height = Int(bytes[offset + 4]) << 8 | Int(bytes[offset + 5])
    offset += 12

    guard offset < bytes.count else { return nil }
    let imageData = Data(bytes[offset...])
    // 0 = JPEG, 1 = JPEG 2000.
    let mimeType = imageDataType == 0 ? "image/jpeg" : "image/jp2"
    return BiometricImage(
      data: imageData,
      mimeType: mimeType == "image/jpeg" ? sniffMimeType(imageData) : mimeType,
      width: width,
      height: height
    )
  }

  static func sniffMimeType(_ data: Data) -> String {
    let bytes = [UInt8](data.prefix(12))
    if bytes.count >= 3, bytes[0] == 0xFF, bytes[1] == 0xD8 { return "image/jpeg" }
    if bytes.count >= 12,
       bytes[4] == 0x6A, bytes[5] == 0x50, bytes[6] == 0x20, bytes[7] == 0x20 { return "image/jp2" }
    if bytes.count >= 4, bytes[0] == 0xFF, bytes[1] == 0x4F, bytes[2] == 0xFF, bytes[3] == 0x51 {
      return "image/jp2"
    }
    if bytes.count >= 4, bytes[0] == 0x89, bytes[1] == 0x50 { return "image/png" }
    return "application/octet-stream"
  }
}

// MARK: - Chuyển ảnh sang JPEG

enum ImageTranscoder {

  struct Result {
    let base64: String
    let mimeType: String
    let width: Int
    let height: Int
    let transcoded: Bool
  }

  /// Cố gắng decode bằng ImageIO rồi mã hoá lại thành JPEG để React Native hiển
  /// thị được. Nếu thất bại (thường do JPEG 2000 trên các bản iOS không hỗ trợ),
  /// trả nguyên bytes gốc kèm mime để ứng dụng tự xử lý.
  static func toJPEG(_ image: BiometricImage) -> Result {
    if let source = CGImageSourceCreateWithData(image.data as CFData, nil),
       let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil) {
      let uiImage = UIImage(cgImage: cgImage)
      if let jpeg = uiImage.jpegData(compressionQuality: 0.9) {
        return Result(
          base64: jpeg.base64EncodedString(),
          mimeType: "image/jpeg",
          width: cgImage.width,
          height: cgImage.height,
          transcoded: true
        )
      }
    }
    return Result(
      base64: image.data.base64EncodedString(),
      mimeType: image.mimeType,
      width: image.width,
      height: image.height,
      transcoded: false
    )
  }
}
