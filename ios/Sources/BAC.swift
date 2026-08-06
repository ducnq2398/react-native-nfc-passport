import Foundation

/// Basic Access Control — ICAO 9303 Part 11 §4.3.
enum BAC {

  /// `MRZ_information = documentNumber||cd || dateOfBirth||cd || dateOfExpiry||cd`
  ///
  /// Số giấy tờ ngắn hơn 9 ký tự được đệm `<`; số dài hơn 9 (CCCD 12 chữ số)
  /// được dùng nguyên vẹn — cùng quy tắc với JMRTD để hai nền tảng khớp nhau.
  static func mrzInformation(documentNumber: String, dateOfBirth: String, dateOfExpiry: String) -> String {
    let paddedNumber = documentNumber.count < 9
      ? documentNumber.padding(toLength: 9, withPad: "<", startingAt: 0)
      : documentNumber
    return paddedNumber + checkDigit(paddedNumber)
      + dateOfBirth + checkDigit(dateOfBirth)
      + dateOfExpiry + checkDigit(dateOfExpiry)
  }

  static func checkDigit(_ input: String) -> String {
    let weights = [7, 3, 1]
    var sum = 0
    for (index, character) in input.uppercased().enumerated() {
      let value: Int
      switch character {
      case "<": value = 0
      case "0"..."9": value = Int(String(character)) ?? 0
      case "A"..."Z": value = Int(character.asciiValue! - 55)
      default: value = 0
      }
      sum += value * weights[index % 3]
    }
    return String(sum % 10)
  }

  /// Kseed cho BAC: 16 byte đầu của SHA-1(MRZ_information).
  static func keySeed(mrzInformation: String) -> Data {
    let digest = Crypto.hash(.sha1, Data(mrzInformation.utf8))
    return Data(digest.prefix(16))
  }

  /// Thực hiện BAC và trả về Secure Messaging đã sẵn sàng.
  static func perform(
    session: TagSession,
    documentNumber: String,
    dateOfBirth: String,
    dateOfExpiry: String
  ) async throws -> SecureMessaging {
    let mrzInfo = mrzInformation(
      documentNumber: documentNumber,
      dateOfBirth: dateOfBirth,
      dateOfExpiry: dateOfExpiry
    )
    let seed = keySeed(mrzInformation: mrzInfo)
    let kEnc = Crypto.deriveKey(keySeed: seed, counter: 1, cipher: .desEDE)
    let kMac = Crypto.deriveKey(keySeed: seed, counter: 2, cipher: .desEDE)

    // --- GET CHALLENGE ---
    let challengeResponse = try await session.send(
      CommandAPDU(cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, ne: 8)
    )
    guard challengeResponse.isSuccess, challengeResponse.data.count == 8 else {
      throw NfcPassportError.fromStatusWord(challengeResponse.sw, context: "GET CHALLENGE")
    }
    let rndICC = challengeResponse.data

    // --- EXTERNAL AUTHENTICATE ---
    let rndIFD = Crypto.randomBytes(8)
    let kIFD = Crypto.randomBytes(16)

    let s = rndIFD + rndICC + kIFD
    let eIFD = try Crypto.tripleDESCBC(s, key: kEnc, iv: Data(repeating: 0, count: 8), encrypt: true)
    let mIFD = try Crypto.retailMAC(eIFD, key: kMac)

    let authResponse = try await session.send(
      CommandAPDU(cla: 0x00, ins: 0x82, p1: 0x00, p2: 0x00, data: eIFD + mIFD, ne: 40)
    )
    guard authResponse.isSuccess else {
      let error = NfcPassportError.fromStatusWord(authResponse.sw, context: "BAC")
      // Chip từ chối ⇒ MRZ sai là nguyên nhân áp đảo.
      if error.code == .invalidMrzKey { throw error }
      throw NfcPassportError(
        code: .bacFailed,
        message: error.message,
        statusWord: error.statusWord
      )
    }
    guard authResponse.data.count == 40 else {
      throw NfcPassportError(code: .bacFailed, message: "Phản hồi BAC dài \(authResponse.data.count) byte, cần 40")
    }

    let eICC = Data(authResponse.data.prefix(32))
    let mICC = Data(authResponse.data.suffix(8))
    guard try Crypto.retailMAC(eICC, key: kMac) == mICC else {
      throw NfcPassportError(code: .bacFailed, message: "MAC phản hồi BAC không hợp lệ")
    }

    let r = try Crypto.tripleDESCBC(eICC, key: kEnc, iv: Data(repeating: 0, count: 8), encrypt: false)
    guard r.count == 32 else {
      throw NfcPassportError(code: .bacFailed, message: "Giải mã phản hồi BAC thất bại")
    }
    let echoedRndIFD = Data(r[8..<16])
    guard echoedRndIFD == rndIFD else {
      throw NfcPassportError(code: .bacFailed, message: "Chip trả về RND.IFD không khớp")
    }
    let kICC = Data(r[16..<32])

    // --- Session keys ---
    let sessionSeed = kIFD.xored(with: kICC)
    let ksEnc = Crypto.deriveKey(keySeed: sessionSeed, counter: 1, cipher: .desEDE)
    let ksMac = Crypto.deriveKey(keySeed: sessionSeed, counter: 2, cipher: .desEDE)
    let ssc = Data(rndICC.suffix(4)) + Data(rndIFD.suffix(4))

    return SecureMessaging(cipher: .desEDE, ksEnc: ksEnc, ksMac: ksMac, initialSSC: ssc)
  }
}
