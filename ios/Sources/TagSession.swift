import CoreNFC
import Foundation

/// Lớp truyền APDU tới chip, tự động bọc/gỡ Secure Messaging khi đã thiết lập.
final class TagSession {

  /// AID của ứng dụng eMRTD (ICAO 9303 Part 10).
  static let emrtdAID = Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])

  /// Số byte đọc mỗi lần. Giữ nhỏ hơn 256 để chừa chỗ cho phần bọc Secure
  /// Messaging (DO'87' + DO'99' + DO'8E') trong một phản hồi APDU ngắn.
  private static let maxReadLength = 0xDF

  private let tag: NFCISO7816Tag
  var secureMessaging: SecureMessaging?

  init(tag: NFCISO7816Tag) {
    self.tag = tag
  }

  // MARK: - Transport

  @discardableResult
  func send(_ command: CommandAPDU) async throws -> ResponseAPDU {
    let outgoing = try secureMessaging?.wrap(command) ?? command
    var response = try await transmit(outgoing)

    // 0x6CXX: Le sai, chip cho biết độ dài đúng.
    if response.sw1 == 0x6C, secureMessaging == nil {
      var retry = outgoing
      retry.ne = Int(response.sw2)
      response = try await transmit(retry)
    }

    // 0x61XX: còn dữ liệu, lấy tiếp bằng GET RESPONSE.
    while response.sw1 == 0x61 {
      let getResponse = CommandAPDU(cla: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00, ne: Int(response.sw2))
      let more = try await transmit(getResponse)
      response = ResponseAPDU(data: response.data + more.data, sw1: more.sw1, sw2: more.sw2)
    }

    if let sm = secureMessaging {
      return try sm.unwrap(response)
    }
    return response
  }

  private func transmit(_ command: CommandAPDU) async throws -> ResponseAPDU {
    let apdu = NFCISO7816APDU(
      instructionClass: command.cla,
      instructionCode: command.ins,
      p1Parameter: command.p1,
      p2Parameter: command.p2,
      data: command.data,
      expectedResponseLength: command.ne
    )
    do {
      let (data, sw1, sw2) = try await tag.sendCommand(apdu: apdu)
      return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    } catch let error as NFCReaderError {
      throw TagSession.map(error)
    }
  }

  static func map(_ error: NFCReaderError) -> NfcPassportError {
    switch error.code {
    case .readerTransceiveErrorTagConnectionLost,
         .readerTransceiveErrorTagResponseError,
         .readerTransceiveErrorRetryExceeded:
      return NfcPassportError(code: .tagLost, message: "Mất kết nối với thẻ")
    case .readerSessionInvalidationErrorUserCanceled:
      return NfcPassportError(code: .cancelled, message: "Người dùng huỷ phiên quét")
    case .readerSessionInvalidationErrorSessionTimeout:
      return NfcPassportError(code: .timeout, message: "Hết thời gian chờ thẻ")
    case .readerSessionInvalidationErrorSystemIsBusy:
      return NfcPassportError(code: .sessionBusy, message: "Hệ thống NFC đang bận")
    default:
      return NfcPassportError(code: .communicationError, message: error.localizedDescription)
    }
  }

  // MARK: - Lệnh cơ bản

  func selectEmrtdApplet() async throws {
    let command = CommandAPDU(
      cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C,
      data: TagSession.emrtdAID, ne: -1
    )
    let response = try await send(command)
    guard response.isSuccess else {
      throw NfcPassportError(
        code: .notAnEmrtd,
        message: "Không mở được ứng dụng eMRTD (SW=\(response.swHex))",
        statusWord: response.swHex
      )
    }
  }

  func selectFile(fid: UInt16) async throws {
    let data = Data([UInt8(fid >> 8), UInt8(fid & 0xFF)])
    let command = CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: data, ne: -1)
    let response = try await send(command)
    guard response.isSuccess else {
      throw NfcPassportError.fromStatusWord(response.sw, context: "SELECT FILE")
    }
  }

  /// Đọc `length` byte từ `offset`. Với offset ≥ 32768 phải dùng biến thể
  /// odd-INS `B1` vì P1P2 chỉ mã hoá được 15 bit.
  private func readBinary(offset: Int, length: Int) async throws -> Data {
    let command: CommandAPDU
    if offset < 0x8000 {
      command = CommandAPDU(
        cla: 0x00, ins: 0xB0,
        p1: UInt8((offset >> 8) & 0x7F),
        p2: UInt8(offset & 0xFF),
        ne: length
      )
    } else {
      // DO'54' chứa offset dạng số nguyên.
      let offsetBytes = Data([
        UInt8((offset >> 24) & 0xFF), UInt8((offset >> 16) & 0xFF),
        UInt8((offset >> 8) & 0xFF), UInt8(offset & 0xFF),
      ])
      command = CommandAPDU(
        cla: 0x00, ins: 0xB1, p1: 0x00, p2: 0x00,
        data: Data([0x54, 0x04]) + offsetBytes,
        ne: length
      )
    }

    let response = try await send(command)
    guard response.isSuccess else {
      throw NfcPassportError.fromStatusWord(response.sw, context: "READ BINARY @\(offset)")
    }

    if offset >= 0x8000 {
      // Phản hồi odd-INS được bọc trong DO'53'.
      let nodes = ASN1.parse(response.data)
      if let discretionary = nodes.first(where: { $0.identifier == 0x53 }) {
        return discretionary.value
      }
    }
    return response.data
  }

  /// Chọn và đọc trọn một EF.
  func readFile(fid: UInt16) async throws -> Data {
    try await selectFile(fid: fid)

    // 4 byte đầu đủ để đọc tag + length của TLV ngoài cùng.
    let header = try await readBinary(offset: 0, length: 4)
    guard header.count >= 2 else {
      throw NfcPassportError(code: .parseError, message: "File \(String(format: "%04X", fid)) rỗng")
    }
    guard let totalLength = TagSession.totalLength(ofTLVHeader: header) else {
      throw NfcPassportError(
        code: .parseError,
        message: "Không đọc được độ dài của file \(String(format: "%04X", fid))"
      )
    }

    var data = header
    while data.count < totalLength {
      let remaining = totalLength - data.count
      let chunk = try await readBinary(
        offset: data.count,
        length: min(remaining, TagSession.maxReadLength)
      )
      if chunk.isEmpty { break }
      data.append(chunk)
    }
    return Data(data.prefix(totalLength))
  }

  /// Tổng độ dài TLV (header + value) suy ra từ vài byte đầu.
  static func totalLength(ofTLVHeader header: Data) -> Int? {
    let bytes = [UInt8](header)
    guard bytes.count >= 2 else { return nil }

    var index = 1
    if bytes[0] & 0x1F == 0x1F {
      // Tag nhiều byte.
      while index < bytes.count, bytes[index] & 0x80 != 0 { index += 1 }
      index += 1
    }
    guard index < bytes.count else { return nil }

    let first = bytes[index]
    index += 1
    if first & 0x80 == 0 {
      return index + Int(first)
    }
    let byteCount = Int(first & 0x7F)
    guard byteCount > 0, byteCount <= 4, index + byteCount <= bytes.count else { return nil }
    var length = 0
    for i in 0..<byteCount {
      length = (length << 8) | Int(bytes[index + i])
    }
    return index + byteCount + length
  }
}
