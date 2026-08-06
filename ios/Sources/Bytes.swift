import Foundation

extension Data {

  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }

  init?(hexString: String) {
    let clean = hexString.filter { !$0.isWhitespace }
    guard clean.count % 2 == 0 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(clean.count / 2)
    var index = clean.startIndex
    while index < clean.endIndex {
      let next = clean.index(index, offsetBy: 2)
      guard let byte = UInt8(clean[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }

  func xored(with other: Data) -> Data {
    let count = Swift.min(self.count, other.count)
    var out = Data(capacity: count)
    for i in 0..<count {
      out.append(self[self.startIndex + i] ^ other[other.startIndex + i])
    }
    return out
  }

  /// ISO/IEC 9797-1 padding method 2: nối `0x80` rồi `0x00` cho đủ block.
  func padded(blockSize: Int) -> Data {
    var out = self
    out.append(0x80)
    while out.count % blockSize != 0 {
      out.append(0x00)
    }
    return out
  }

  /// Gỡ padding method 2: bỏ các `0x00` ở cuối rồi bỏ đúng một `0x80`.
  func unpadded() -> Data? {
    var cursor = endIndex
    while cursor > startIndex, self[index(before: cursor)] == 0x00 {
      cursor = index(before: cursor)
    }
    guard cursor > startIndex, self[index(before: cursor)] == 0x80 else { return nil }
    return Data(self[startIndex..<index(before: cursor)])
  }

  /// Cắt hoặc đệm 0 ở đầu để đạt đúng độ dài (dùng cho toạ độ EC).
  func leftPadded(to length: Int) -> Data {
    if count >= length { return suffix(length) }
    return Data(repeating: 0, count: length - count) + self
  }
}

extension UInt64 {
  /// Big-endian 8 byte — dùng cho Send Sequence Counter.
  var bigEndianData: Data {
    var value = bigEndian
    return Data(bytes: &value, count: MemoryLayout<UInt64>.size)
  }
}

extension UInt32 {
  var bigEndianData: Data {
    var value = bigEndian
    return Data(bytes: &value, count: MemoryLayout<UInt32>.size)
  }
}
