import Foundation

/// Parser DG13 cho CCCD gắn chip Việt Nam.
///
/// ICAO 9303 để DG13 ("Optional details") cho quốc gia phát hành tự định nghĩa,
/// không có đặc tả công khai cho Việt Nam. Cách làm giống hệt phía Android để
/// hai nền tảng trả về cùng một kết quả:
///  1. Duyệt cây TLV, gom mọi leaf decode được thành UTF-8 in được → `rawFields`.
///  2. Gán tên trường bằng con trỏ tuần tự với các mốc neo nhận diện chắc chắn.
///
/// `rawFields` luôn đáng tin; các trường có tên là suy luận theo bố cục quan sát được.
struct VNPersonalInfo {
  var idNumber: String?
  var oldIdNumber: String?
  var fullName: String?
  var dateOfBirth: String?
  var gender: String?
  var nationality: String?
  var ethnicity: String?
  var religion: String?
  var placeOfOrigin: String?
  var placeOfResidence: String?
  var personalIdentification: String?
  var dateOfIssue: String?
  var dateOfExpiry: String?
  var fatherName: String?
  var motherName: String?
  var spouseName: String?
  var rawFields: [String] = []

  var dictionary: [String: Any] {
    var out: [String: Any] = ["rawFields": rawFields]
    let mapping: [(String, String?)] = [
      ("idNumber", idNumber), ("oldIdNumber", oldIdNumber), ("fullName", fullName),
      ("dateOfBirth", dateOfBirth), ("gender", gender), ("nationality", nationality),
      ("ethnicity", ethnicity), ("religion", religion), ("placeOfOrigin", placeOfOrigin),
      ("placeOfResidence", placeOfResidence),
      ("personalIdentification", personalIdentification),
      ("dateOfIssue", dateOfIssue), ("dateOfExpiry", dateOfExpiry),
      ("fatherName", fatherName), ("motherName", motherName), ("spouseName", spouseName),
    ]
    for (key, value) in mapping where value != nil {
      out[key] = value!
    }
    return out
  }
}

enum DG13Parser {

  private static let id12 = try! NSRegularExpression(pattern: "^\\d{12}$")
  private static let id9 = try! NSRegularExpression(pattern: "^\\d{9}$")
  private static let dateCompact = try! NSRegularExpression(pattern: "^(\\d{2})(\\d{2})(\\d{4})$")
  private static let dateSlash = try! NSRegularExpression(pattern: "^(\\d{2})[/-](\\d{2})[/-](\\d{4})$")
  private static let genders: Set<String> = ["nam", "nữ", "nu"]

  static func parse(_ dg13: Data) -> VNPersonalInfo {
    let strings = extractStrings(dg13)
    return mapFields(strings)
  }

  // MARK: - Bước 1: gom chuỗi

  static func extractStrings(_ dg13: Data) -> [String] {
    let roots = ASN1.parse(dg13)
    let content = roots.first(where: { $0.identifier == 0x6D })?.value ?? dg13

    var out = [String]()
    collect(ASN1.parse(content), into: &out)
    if out.isEmpty {
      out = scanUTF8Runs(content)
    }
    return out
  }

  private static func collect(_ nodes: [ASN1Node], into out: inout [String]) {
    for node in nodes {
      if node.constructed, !node.children.isEmpty {
        collect(node.children, into: &out)
      } else if let text = decodeText(node.value) {
        out.append(text)
      }
    }
  }

  /// Chỉ chấp nhận UTF-8 hợp lệ và toàn ký tự in được.
  private static func decodeText(_ data: Data) -> String? {
    guard !data.isEmpty, data.count <= 4096,
          let text = String(data: data, encoding: .utf8)
    else { return nil }
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }
    guard !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    else { return nil }
    guard trimmed.contains(where: { $0.isLetter || $0.isNumber }) else { return nil }
    return trimmed.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
  }

  /// Fallback khi nội dung không phải TLV hợp lệ: quét các đoạn UTF-8 liên tiếp.
  private static func scanUTF8Runs(_ data: Data) -> [String] {
    var out = [String]()
    let bytes = [UInt8](data)
    var start = 0
    for index in 0...bytes.count {
      let isTextByte: Bool
      if index == bytes.count {
        isTextByte = false
      } else {
        let byte = bytes[index]
        isTextByte = (byte >= 0x20 && byte <= 0x7E) || byte >= 0x80
      }
      if !isTextByte {
        if index - start >= 2, let text = decodeText(Data(bytes[start..<index])), text.count >= 2 {
          out.append(text)
        }
        start = index + 1
      }
    }
    return out
  }

  // MARK: - Bước 2: gán tên trường

  private final class Cursor {
    private let items: [String]
    private var index = 0
    init(_ items: [String]) { self.items = items }

    func take(_ predicate: (String) -> Bool) -> String? {
      guard index < items.count else { return nil }
      let value = items[index]
      guard predicate(value) else { return nil }
      index += 1
      return value
    }
  }

  private static func matches(_ regex: NSRegularExpression, _ value: String) -> Bool {
    let range = NSRange(value.startIndex..., in: value)
    return regex.firstMatch(in: value, range: range) != nil
  }

  private static func isDate(_ value: String) -> Bool {
    matches(dateCompact, value) || matches(dateSlash, value)
  }

  private static func formatDate(_ value: String) -> String {
    let digits = value.filter { $0.isNumber }
    guard digits.count == 8 else { return value }
    let day = digits.prefix(2)
    let month = digits.dropFirst(2).prefix(2)
    let year = digits.suffix(4)
    return "\(day)/\(month)/\(year)"
  }

  private static func mapFields(_ strings: [String]) -> VNPersonalInfo {
    let cursor = Cursor(strings)
    var info = VNPersonalInfo()

    info.idNumber = cursor.take { matches(id12, $0) }
    info.oldIdNumber = cursor.take { matches(id9, $0) }
    info.fullName = cursor.take { !isDate($0) && !genders.contains($0.lowercased()) }
    info.dateOfBirth = cursor.take { isDate($0) }.map(formatDate)
    info.gender = cursor.take { genders.contains($0.lowercased()) }
    info.nationality = cursor.take { $0.range(of: "Việt Nam", options: .caseInsensitive) != nil }

    // Dân tộc / tôn giáo là từ đơn; địa chỉ thì có dấu phẩy.
    info.ethnicity = cursor.take { !isDate($0) && !$0.contains(",") }
    info.religion = cursor.take { !isDate($0) && !$0.contains(",") }

    info.placeOfOrigin = cursor.take { !isDate($0) }
    info.placeOfResidence = cursor.take { !isDate($0) }
    info.personalIdentification = cursor.take { !isDate($0) }

    info.dateOfIssue = cursor.take { isDate($0) }.map(formatDate)
    info.dateOfExpiry = cursor.take { isDate($0) }.map(formatDate)

    info.fatherName = cursor.take { !isDate($0) && !matches(id9, $0) }
    info.motherName = cursor.take { !isDate($0) && !matches(id9, $0) }
    info.spouseName = cursor.take { !isDate($0) && !matches(id9, $0) }

    if info.oldIdNumber == nil {
      info.oldIdNumber = strings.last { matches(id9, $0) }
    }
    if info.idNumber == nil {
      info.idNumber = strings.first { matches(id12, $0) }
    }
    info.rawFields = strings
    return info
  }
}
