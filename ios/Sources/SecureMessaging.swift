import Foundation

/// Cấu trúc một lệnh APDU trước khi bọc Secure Messaging.
struct CommandAPDU {
  var cla: UInt8
  var ins: UInt8
  var p1: UInt8
  var p2: UInt8
  var data: Data = Data()
  /// Số byte mong đợi. `-1` = không có Le, `256` = Le ngắn tối đa.
  var ne: Int = -1
}

struct ResponseAPDU {
  let data: Data
  let sw1: UInt8
  let sw2: UInt8

  var sw: UInt16 { (UInt16(sw1) << 8) | UInt16(sw2) }
  var isSuccess: Bool { sw == 0x9000 }
  var swHex: String { String(format: "%04X", sw) }
}

/// Secure Messaging theo ICAO 9303 Part 11 §9.8.
///
/// Hỗ trợ cả hai bộ thuật toán:
///  - 3DES + Retail MAC (BAC, PACE-3DES) — SSC 8 byte, IV = 0.
///  - AES-CBC + AES-CMAC (PACE-AES, sau Chip Authentication) — SSC 16 byte,
///    IV = E(KSenc, SSC).
final class SecureMessaging {

  let cipher: SMCipher
  private let ksEnc: Data
  private let ksMac: Data
  /// Send Sequence Counter, big-endian, độ dài bằng block size của cipher.
  private var ssc: Data

  init(cipher: SMCipher, ksEnc: Data, ksMac: Data, initialSSC: Data? = nil) {
    self.cipher = cipher
    self.ksEnc = ksEnc
    self.ksMac = ksMac
    self.ssc = initialSSC ?? Data(repeating: 0, count: cipher.blockSize)
  }

  // MARK: - SSC

  private func incrementSSC() {
    var bytes = [UInt8](ssc)
    var index = bytes.count - 1
    while index >= 0 {
      if bytes[index] == 0xFF {
        bytes[index] = 0x00
        index -= 1
      } else {
        bytes[index] += 1
        break
      }
    }
    ssc = Data(bytes)
  }

  // MARK: - Primitives

  private func encrypt(_ data: Data) throws -> Data {
    switch cipher {
    case .desEDE:
      return try Crypto.tripleDESCBC(data, key: ksEnc, iv: Data(repeating: 0, count: 8), encrypt: true)
    default:
      let iv = try Crypto.aesECBEncrypt(ssc, key: ksEnc)
      return try Crypto.aesCBC(data, key: ksEnc, iv: iv, encrypt: true)
    }
  }

  private func decrypt(_ data: Data) throws -> Data {
    switch cipher {
    case .desEDE:
      return try Crypto.tripleDESCBC(data, key: ksEnc, iv: Data(repeating: 0, count: 8), encrypt: false)
    default:
      let iv = try Crypto.aesECBEncrypt(ssc, key: ksEnc)
      return try Crypto.aesCBC(data, key: ksEnc, iv: iv, encrypt: false)
    }
  }

  private func mac(_ data: Data) throws -> Data {
    switch cipher {
    case .desEDE:
      return try Crypto.retailMAC(data, key: ksMac)
    default:
      // ICAO cắt CMAC xuống 8 byte đầu.
      return Data(try Crypto.aesCMAC(data, key: ksMac).prefix(8))
    }
  }

  // MARK: - Wrap / Unwrap

  /// Bọc một lệnh thành APDU được bảo vệ (CLA |= 0x0C).
  func wrap(_ command: CommandAPDU) throws -> CommandAPDU {
    incrementSSC()

    let blockSize = cipher.blockSize
    let maskedCLA = command.cla | 0x0C
    let header = Data([maskedCLA, command.ins, command.p1, command.p2])
    let paddedHeader = header.padded(blockSize: blockSize)

    var do87 = Data()
    if !command.data.isEmpty {
      let cryptogram = try encrypt(command.data.padded(blockSize: blockSize))
      // 0x01 = "padding-content indicator" theo ISO 7816-4.
      let value = Data([0x01]) + cryptogram
      do87 = Data([0x87]) + ASN1.encodeLength(value.count) + value
    }

    var do97 = Data()
    if command.ne >= 0 {
      if command.ne > 256 {
        do97 = Data([0x97, 0x02, UInt8((command.ne >> 8) & 0xFF), UInt8(command.ne & 0xFF)])
      } else {
        do97 = Data([0x97, 0x01, UInt8(command.ne == 256 ? 0x00 : command.ne)])
      }
    }

    // N = SSC || M. Retail MAC và AES-CMAC đều tự lo phần padding của N.
    let n = ssc + paddedHeader + do87 + do97
    let do8E = Data([0x8E, 0x08]) + (try mac(n))

    let payload = do87 + do97 + do8E
    return CommandAPDU(
      cla: maskedCLA,
      ins: command.ins,
      p1: command.p1,
      p2: command.p2,
      data: payload,
      ne: 256
    )
  }

  /// Gỡ bọc phản hồi và kiểm tra checksum.
  func unwrap(_ response: ResponseAPDU) throws -> ResponseAPDU {
    incrementSSC()

    guard !response.data.isEmpty else {
      // Phản hồi chỉ có status word (ví dụ lỗi trước khi tới lớp SM).
      return response
    }

    var do87 = Data()
    var do87Data = Data()
    var do99 = Data()
    var receivedMAC = Data()

    var offset = response.data.startIndex
    let end = response.data.endIndex

    while offset < end {
      let tag = response.data[offset]
      var cursor = response.data.index(after: offset)
      guard cursor < end else { break }

      var length = Int(response.data[cursor])
      cursor = response.data.index(after: cursor)
      if length & 0x80 != 0 {
        let byteCount = length & 0x7F
        guard byteCount > 0, byteCount <= 3,
              let limit = response.data.index(cursor, offsetBy: byteCount, limitedBy: end)
        else { break }
        length = 0
        while cursor < limit {
          length = (length << 8) | Int(response.data[cursor])
          cursor = response.data.index(after: cursor)
        }
      }
      guard let valueEnd = response.data.index(cursor, offsetBy: length, limitedBy: end) else { break }
      let value = Data(response.data[cursor..<valueEnd])
      let full = Data(response.data[offset..<valueEnd])

      switch tag {
      case 0x87:
        do87 = full
        // Byte đầu là padding-content indicator.
        do87Data = value.count > 1 ? Data(value.dropFirst()) : Data()
      case 0x99:
        do99 = full
      case 0x8E:
        receivedMAC = value
      default:
        break
      }
      offset = valueEnd
    }

    guard !receivedMAC.isEmpty else {
      throw NfcPassportError(code: .communicationError, message: "Phản hồi thiếu checksum DO'8E'")
    }

    let n = ssc + do87 + do99
    let expectedMAC = try mac(n)
    guard expectedMAC == receivedMAC else {
      throw NfcPassportError(
        code: .communicationError,
        message: "Checksum Secure Messaging không khớp — kênh bảo mật đã hỏng"
      )
    }

    var plain = Data()
    if !do87Data.isEmpty {
      let decrypted = try decrypt(do87Data)
      guard let unpadded = decrypted.unpadded() else {
        throw NfcPassportError(code: .communicationError, message: "Padding phản hồi không hợp lệ")
      }
      plain = unpadded
    }

    // Status word thật nằm trong DO'99'.
    if do99.count >= 4 {
      return ResponseAPDU(data: plain, sw1: do99[do99.startIndex + 2], sw2: do99[do99.startIndex + 3])
    }
    return ResponseAPDU(data: plain, sw1: response.sw1, sw2: response.sw2)
  }
}
