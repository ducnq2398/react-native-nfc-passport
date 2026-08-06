import Foundation

/// Một node BER/DER đã parse. `encoded` giữ nguyên toàn bộ TLV để có thể băm
/// hoặc mã hoá lại mà không phải dựng lại cấu trúc.
struct ASN1Node {
  /// Byte identifier đầu tiên (đã gồm class + constructed + tag number thấp).
  let identifier: UInt8
  /// Tag number đầy đủ (hỗ trợ tag nhiều byte).
  let tagNumber: UInt32
  let constructed: Bool
  let value: Data
  let children: [ASN1Node]
  let encoded: Data

  var isContextSpecific: Bool { identifier & 0xC0 == 0x80 }
  var isApplication: Bool { identifier & 0xC0 == 0x40 }

  /// Tag rút gọn dùng để so khớp nhanh với tag 1 byte (ví dụ `0x30`, `0x77`).
  var shortTag: UInt8 { identifier }
}

enum ASN1Error: Error {
  case malformed(String)
}

enum ASN1 {

  // MARK: - Parsing

  /// Parse dãy TLV liền kề. Bỏ qua byte đệm `0x00`/`0xFF` giữa các phần tử.
  static func parse(_ data: Data) -> [ASN1Node] {
    var nodes = [ASN1Node]()
    var offset = data.startIndex

    while offset < data.endIndex {
      let identifier = data[offset]
      if identifier == 0x00 || identifier == 0xFF {
        offset = data.index(after: offset)
        continue
      }

      var cursor = data.index(after: offset)
      var tagNumber = UInt32(identifier & 0x1F)
      if identifier & 0x1F == 0x1F {
        tagNumber = 0
        while cursor < data.endIndex {
          let byte = data[cursor]
          cursor = data.index(after: cursor)
          tagNumber = (tagNumber << 7) | UInt32(byte & 0x7F)
          if byte & 0x80 == 0 { break }
        }
      }

      guard cursor < data.endIndex else { break }
      let firstLengthByte = data[cursor]
      cursor = data.index(after: cursor)
      var length = 0
      if firstLengthByte & 0x80 == 0 {
        length = Int(firstLengthByte)
      } else {
        let byteCount = Int(firstLengthByte & 0x7F)
        guard byteCount > 0, byteCount <= 4,
              data.index(cursor, offsetBy: byteCount, limitedBy: data.endIndex) != nil
        else { break }
        for _ in 0..<byteCount {
          length = (length << 8) | Int(data[cursor])
          cursor = data.index(after: cursor)
        }
      }

      guard length >= 0,
            let valueEnd = data.index(cursor, offsetBy: length, limitedBy: data.endIndex)
      else { break }

      let value = Data(data[cursor..<valueEnd])
      let constructed = identifier & 0x20 != 0
      let children = constructed ? parse(value) : []
      nodes.append(
        ASN1Node(
          identifier: identifier,
          tagNumber: tagNumber,
          constructed: constructed,
          value: value,
          children: children,
          encoded: Data(data[offset..<valueEnd])
        )
      )
      offset = valueEnd
    }

    return nodes
  }

  /// Tìm node đầu tiên có identifier cho trước ở mọi độ sâu (duyệt theo chiều sâu).
  static func findFirst(_ nodes: [ASN1Node], identifier: UInt8) -> ASN1Node? {
    for node in nodes {
      if node.identifier == identifier { return node }
      if let found = findFirst(node.children, identifier: identifier) { return found }
    }
    return nil
  }

  /// Tìm SEQUENCE đầu tiên bắt đầu bằng OID cho trước — dùng để định vị các
  /// SecurityInfo trong DG14 / EF.CardAccess.
  static func findSequences(withOIDPrefix prefix: String, in nodes: [ASN1Node]) -> [ASN1Node] {
    var result = [ASN1Node]()
    for node in nodes {
      if node.identifier == 0x30,
         let first = node.children.first,
         first.identifier == 0x06,
         let oid = decodeOID(first.value),
         oid.hasPrefix(prefix) {
        result.append(node)
      }
      result.append(contentsOf: findSequences(withOIDPrefix: prefix, in: node.children))
    }
    return result
  }

  // MARK: - Decoding primitives

  /// OID → chuỗi dạng chấm (`0.4.0.127.0.7.2.2.4.2.4`).
  static func decodeOID(_ data: Data) -> String? {
    guard !data.isEmpty else { return nil }
    let bytes = [UInt8](data)
    var components = [UInt64]()
    let first = UInt64(bytes[0])
    components.append(first / 40)
    components.append(first % 40)

    var current: UInt64 = 0
    var index = 1
    while index < bytes.count {
      let byte = bytes[index]
      current = (current << 7) | UInt64(byte & 0x7F)
      if byte & 0x80 == 0 {
        components.append(current)
        current = 0
      }
      index += 1
    }
    return components.map(String.init).joined(separator: ".")
  }

  static func decodeInteger(_ data: Data) -> Int? {
    guard !data.isEmpty, data.count <= 8 else { return nil }
    var value = 0
    for byte in data { value = (value << 8) | Int(byte) }
    return value
  }

  // MARK: - Encoding

  static func encodeLength(_ length: Int) -> Data {
    if length < 0x80 { return Data([UInt8(length)]) }
    var bytes = [UInt8]()
    var remaining = length
    while remaining > 0 {
      bytes.insert(UInt8(remaining & 0xFF), at: 0)
      remaining >>= 8
    }
    return Data([UInt8(0x80 | bytes.count)]) + Data(bytes)
  }

  /// Dựng một TLV với tag 1 hoặc 2 byte.
  static func encode(tag: UInt32, value: Data) -> Data {
    var tagBytes = Data()
    if tag > 0xFF {
      tagBytes.append(UInt8((tag >> 8) & 0xFF))
      tagBytes.append(UInt8(tag & 0xFF))
    } else {
      tagBytes.append(UInt8(tag & 0xFF))
    }
    return tagBytes + encodeLength(value.count) + value
  }

  static func encodeOID(_ oid: String) -> Data? {
    let parts = oid.split(separator: ".").compactMap { UInt64($0) }
    guard parts.count >= 2 else { return nil }
    var bytes = [UInt8]()
    bytes.append(UInt8(parts[0] * 40 + parts[1]))
    for component in parts.dropFirst(2) {
      var stack = [UInt8]()
      var value = component
      repeat {
        stack.insert(UInt8(value & 0x7F), at: 0)
        value >>= 7
      } while value > 0
      for i in 0..<(stack.count - 1) { stack[i] |= 0x80 }
      bytes.append(contentsOf: stack)
    }
    return Data(bytes)
  }
}
