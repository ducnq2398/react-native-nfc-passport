import Foundation

/// Parser DG13 cho CCCD gắn chip (mẫu 2021) và thẻ Căn cước (mẫu 2024) Việt Nam.
///
/// ICAO 9303 để DG13 ("Optional details") cho quốc gia phát hành tự định nghĩa,
/// không có đặc tả công khai cho Việt Nam. Cách làm giống hệt phía Android để
/// hai nền tảng trả về cùng một kết quả:
///  1. Duyệt cây TLV, gom mọi leaf decode được thành UTF-8 in được → `rawFields`.
///  2. Nếu DG13 có dạng `SEQUENCE { INTEGER chỉ_số, giá_trị… }` thì gán tên
///     trường theo chỉ số (`fieldsByIndex`) — không bị lệch khi một trường rỗng,
///     vốn hay gặp ở thẻ mẫu 2024 (bỏ đặc điểm nhận dạng, vợ/chồng, CMND cũ…).
///  3. Nếu không nhận ra cấu trúc có chỉ số, lùi về con trỏ tuần tự với các mốc
///     neo nhận diện chắc chắn.
///
/// `rawFields` và `fieldsByIndex` luôn đáng tin; các trường có tên là suy luận.
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
  /// `CCCD` (mẫu 2021) hoặc `CAN_CUOC` (mẫu 2024), suy từ ngày cấp.
  var cardType: String?
  var rawFields: [String] = []
  var fieldsByIndex: [Int: [String]] = [:]

  var dictionary: [String: Any] {
    var out: [String: Any] = ["rawFields": rawFields]
    if !fieldsByIndex.isEmpty {
      out["fieldsByIndex"] = Dictionary(
        uniqueKeysWithValues: fieldsByIndex.map { (String($0.key), $0.value) }
      )
    }
    let mapping: [(String, String?)] = [
      ("idNumber", idNumber), ("oldIdNumber", oldIdNumber), ("fullName", fullName),
      ("dateOfBirth", dateOfBirth), ("gender", gender), ("nationality", nationality),
      ("ethnicity", ethnicity), ("religion", religion), ("placeOfOrigin", placeOfOrigin),
      ("placeOfResidence", placeOfResidence),
      ("personalIdentification", personalIdentification),
      ("dateOfIssue", dateOfIssue), ("dateOfExpiry", dateOfExpiry),
      ("fatherName", fatherName), ("motherName", motherName), ("spouseName", spouseName),
      ("cardType", cardType),
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

  /// Số trường có chỉ số tối thiểu để tin rằng DG13 theo bố cục có chỉ số.
  private static let minIndexedFields = 5

  static func parse(_ dg13: Data) -> VNPersonalInfo {
    let content = unwrap(dg13)
    let strings = extractStrings(content)
    let indexed = extractIndexedFields(content)

    var info = indexed.count >= minIndexedFields
      ? mapIndexedFields(indexed, strings: strings)
      : mapFields(strings)
    info.rawFields = strings
    info.fieldsByIndex = indexed
    info.cardType = cardType(dateOfIssue: info.dateOfIssue)
    return info
  }

  /// DG13 được bọc trong tag '6D'; nếu không thấy thì dùng thẳng nội dung.
  private static func unwrap(_ dg13: Data) -> Data {
    // Cố tình KHÔNG viết `roots.first(where:)?.value ?? dg13`: với biểu thức đó
    // Swift chọn overload `(T?, T?) -> T?` của `??` và suy ra kiểu `Data?`.
    // Dạng `if let` lấy kiểu trực tiếp từ `dg13` nên không có chỗ cho suy luận sai.
    if let container = ASN1.parse(dg13).first(where: { $0.identifier == 0x6D }) {
      return container.value
    }
    return dg13
  }

  // MARK: - Bước 1: gom chuỗi

  static func extractStrings(_ content: Data) -> [String] {
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

  // MARK: - Bước 2: trường có chỉ số

  /// Tìm mọi `SEQUENCE { INTEGER chỉ_số, giá_trị… }` và gom giá trị theo chỉ số.
  /// Giá trị rỗng được giữ lại dưới dạng `""` để không làm lệch vị trí (ví dụ
  /// trường 13 = [tên cha, tên mẹ] khi một trong hai để trống).
  static func extractIndexedFields(_ content: Data) -> [Int: [String]] {
    var out = [Int: [String]]()
    collectIndexed(ASN1.parse(content), into: &out)
    return out
  }

  private static func collectIndexed(_ nodes: [ASN1Node], into out: inout [Int: [String]]) {
    for node in nodes where node.constructed {
      if node.identifier == 0x30,
         let first = node.children.first, first.identifier == 0x02,
         let index = ASN1.decodeInteger(first.value), index > 0 {
        if out[index] == nil {
          var values = [String]()
          collectValues(Array(node.children.dropFirst()), into: &values)
          out[index] = values
        }
      } else {
        collectIndexed(node.children, into: &out)
      }
    }
  }

  private static func collectValues(_ nodes: [ASN1Node], into out: inout [String]) {
    for node in nodes {
      if node.constructed {
        // SEQUENCE rỗng vẫn chiếm một chỗ (ví dụ cha hoặc mẹ để trống).
        if node.children.isEmpty {
          out.append("")
        } else {
          collectValues(node.children, into: &out)
        }
      } else {
        out.append(decodeText(node.value) ?? "")
      }
    }
  }

  /// Bố cục quan sát được trên CCCD 2021; thẻ Căn cước 2024 giữ nguyên chỉ số,
  /// nhưng trường 8 in trên mặt thẻ là "Nơi đăng ký khai sinh" và trường 9 là
  /// "Nơi cư trú", đồng thời nhiều trường có thể rỗng.
  private static func mapIndexedFields(_ fields: [Int: [String]], strings: [String]) -> VNPersonalInfo {
    func value(_ index: Int, _ position: Int = 0) -> String? {
      guard let values = fields[index], position < values.count else { return nil }
      let text = values[position]
      return text.isEmpty ? nil : text
    }
    func date(_ index: Int) -> String? {
      value(index).map { isDate($0) ? formatDate($0) : $0 }
    }

    var info = VNPersonalInfo()
    info.idNumber = value(1)
    info.fullName = value(2)
    info.dateOfBirth = date(3)
    info.gender = value(4)
    info.nationality = value(5)
    info.ethnicity = value(6)
    info.religion = value(7)
    info.placeOfOrigin = value(8)
    info.placeOfResidence = value(9)
    info.personalIdentification = value(10)
    info.dateOfIssue = date(11)
    info.dateOfExpiry = date(12)
    info.fatherName = value(13, 0)
    info.motherName = value(13, 1)
    info.spouseName = value(14)
    // Trường 15 là số giấy tờ cũ: CMND 9 số, hoặc số CCCD 12 số khi đổi sang thẻ mới.
    info.oldIdNumber = value(15).flatMap { candidate in
      matches(id9, candidate) || matches(id12, candidate) ? candidate : nil
    }

    if info.idNumber.map({ !matches(id12, $0) }) ?? true,
       let fallback = strings.first(where: { matches(id12, $0) }) {
      info.idNumber = fallback
    }
    return info
  }

  /// Thẻ Căn cước mẫu mới được cấp từ 01/07/2024 (Luật Căn cước 2023).
  private static func cardType(dateOfIssue: String?) -> String? {
    guard let digits = dateOfIssue?.filter({ $0.isNumber }), digits.count == 8,
          let day = Int(digits.prefix(2)),
          let month = Int(digits.dropFirst(2).prefix(2)),
          let year = Int(digits.suffix(4))
    else { return nil }
    let issued = year * 10_000 + month * 100 + day
    return issued >= 2024_07_01 ? "CAN_CUOC" : "CCCD"
  }

  // MARK: - Bước 3: gán tên trường tuần tự (fallback)

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
    return info
  }
}
