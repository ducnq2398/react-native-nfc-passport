import CommonCrypto
import Foundation

/// Thuật toán mã hoá của Secure Messaging (ICAO 9303 Part 11 §9.8).
enum SMCipher {
  case desEDE      // 3DES với Retail MAC (BAC, PACE-3DES)
  case aes128      // AES-128 với AES-CMAC
  case aes192
  case aes256

  var blockSize: Int {
    switch self {
    case .desEDE: return 8
    default: return 16
    }
  }

  var keyLength: Int {
    switch self {
    case .desEDE: return 16   // K1 || K2, mở rộng thành 24 byte khi dùng 3DES
    case .aes128: return 16
    case .aes192: return 24
    case .aes256: return 32
    }
  }

  /// KDF dùng SHA-1 cho 3DES/AES-128 và SHA-256 cho AES-192/256.
  var kdfDigest: Crypto.Digest {
    switch self {
    case .desEDE, .aes128: return .sha1
    case .aes192, .aes256: return .sha256
    }
  }
}

enum CryptoError: Error {
  case operationFailed(status: Int32)
  case invalidKeyLength
  case invalidInput(String)
}

enum Crypto {

  // MARK: - Digest

  enum Digest: String {
    case sha1 = "SHA-1"
    case sha224 = "SHA-224"
    case sha256 = "SHA-256"
    case sha384 = "SHA-384"
    case sha512 = "SHA-512"

    var length: Int {
      switch self {
      case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
      case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
      case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
      case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
      case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
      }
    }

    /// Nhận cả tên ICAO ("SHA-256"), tên JCA ("SHA256") và OID.
    static func from(name: String) -> Digest? {
      let normalized = name.uppercased().replacingOccurrences(of: "-", with: "")
      switch normalized {
      case "SHA1", "1.3.14.3.2.26": return .sha1
      case "SHA224", "2.16.840.1.101.3.4.2.4": return .sha224
      case "SHA256", "2.16.840.1.101.3.4.2.1": return .sha256
      case "SHA384", "2.16.840.1.101.3.4.2.2": return .sha384
      case "SHA512", "2.16.840.1.101.3.4.2.3": return .sha512
      default: return nil
      }
    }
  }

  static func hash(_ digest: Digest, _ data: Data) -> Data {
    var out = [UInt8](repeating: 0, count: digest.length)
    data.withUnsafeBytes { buffer in
      let base = buffer.baseAddress
      let length = CC_LONG(data.count)
      switch digest {
      case .sha1: _ = CC_SHA1(base, length, &out)
      case .sha224: _ = CC_SHA224(base, length, &out)
      case .sha256: _ = CC_SHA256(base, length, &out)
      case .sha384: _ = CC_SHA384(base, length, &out)
      case .sha512: _ = CC_SHA512(base, length, &out)
      }
    }
    return Data(out)
  }

  // MARK: - Block cipher

  private static func crypt(
    operation: CCOperation,
    algorithm: CCAlgorithm,
    options: CCOptions,
    key: Data,
    iv: Data?,
    data: Data
  ) throws -> Data {
    let blockSize = algorithm == CCAlgorithm(kCCAlgorithmAES) ? kCCBlockSizeAES128 : kCCBlockSizeDES
    var out = Data(count: data.count + blockSize)
    var moved = 0
    let outCount = out.count

    // IV luôn được vật chất hoá thành buffer riêng: không được để con trỏ thoát
    // khỏi phạm vi `withUnsafeBytes`.
    let ivBytes = [UInt8](iv ?? Data())
    let status: CCCryptorStatus = out.withUnsafeMutableBytes { outBuf in
      data.withUnsafeBytes { dataBuf in
        key.withUnsafeBytes { keyBuf in
          ivBytes.withUnsafeBufferPointer { ivBuf -> CCCryptorStatus in
            CCCrypt(
              operation,
              algorithm,
              options,
              keyBuf.baseAddress, key.count,
              iv == nil ? nil : UnsafeRawPointer(ivBuf.baseAddress!),
              dataBuf.baseAddress, data.count,
              outBuf.baseAddress, outCount,
              &moved
            )
          }
        }
      }
    }

    guard status == kCCSuccess else { throw CryptoError.operationFailed(status: status) }
    return out.prefix(moved)
  }

  /// 3DES-CBC. Khoá 16 byte được mở rộng thành K1||K2||K1 theo ICAO.
  static func tripleDESCBC(_ data: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
    let fullKey: Data
    switch key.count {
    case 16: fullKey = key + key.prefix(8)
    case 24: fullKey = key
    default: throw CryptoError.invalidKeyLength
    }
    return try crypt(
      operation: CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
      algorithm: CCAlgorithm(kCCAlgorithm3DES),
      options: 0, // không padding: dữ liệu đã được pad theo ISO 9797-1 method 2
      key: fullKey,
      iv: iv,
      data: data
    )
  }

  static func aesCBC(_ data: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
    try crypt(
      operation: CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
      algorithm: CCAlgorithm(kCCAlgorithmAES),
      options: 0,
      key: key,
      iv: iv,
      data: data
    )
  }

  static func aesECBEncrypt(_ data: Data, key: Data) throws -> Data {
    try crypt(
      operation: CCOperation(kCCEncrypt),
      algorithm: CCAlgorithm(kCCAlgorithmAES),
      options: CCOptions(kCCOptionECBMode),
      key: key,
      iv: nil,
      data: data
    )
  }

  private static func desCBC(_ data: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
    try crypt(
      operation: CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
      algorithm: CCAlgorithm(kCCAlgorithmDES),
      options: 0,
      key: key,
      iv: iv,
      data: data
    )
  }

  // MARK: - MAC

  /// ISO/IEC 9797-1 MAC Algorithm 3 (Retail MAC) với padding method 2.
  /// Dùng cho Secure Messaging 3DES của BAC.
  static func retailMAC(_ data: Data, key: Data) throws -> Data {
    let normalizedKey = Data(key)
    guard normalizedKey.count >= 16 else { throw CryptoError.invalidKeyLength }
    let ka = Data(normalizedKey[0..<8])
    let kb = Data(normalizedKey[8..<16])
    let zeroIV = Data(repeating: 0, count: 8)

    let padded = data.padded(blockSize: 8)
    let cbc = try desCBC(padded, key: ka, iv: zeroIV, encrypt: true)
    guard cbc.count >= 8 else { throw CryptoError.invalidInput("Retail MAC: đầu ra CBC quá ngắn") }
    let last = Data(cbc.suffix(8))

    let decrypted = try desCBC(last, key: kb, iv: zeroIV, encrypt: false)
    return try desCBC(decrypted, key: ka, iv: zeroIV, encrypt: true)
  }

  /// AES-CMAC (NIST SP 800-38B), trả về đủ 16 byte; Secure Messaging cắt 8 byte đầu.
  static func aesCMAC(_ data: Data, key: Data) throws -> Data {
    let blockSize = 16
    let zeroBlock = Data(repeating: 0, count: blockSize)
    let l = try aesECBEncrypt(zeroBlock, key: key)

    func shiftLeft(_ input: Data) -> Data {
      var out = [UInt8](repeating: 0, count: input.count)
      var carry: UInt8 = 0
      for i in stride(from: input.count - 1, through: 0, by: -1) {
        let byte = input[input.startIndex + i]
        out[i] = (byte << 1) | carry
        carry = (byte & 0x80) != 0 ? 1 : 0
      }
      return Data(out)
    }

    let rb: UInt8 = 0x87
    var k1 = shiftLeft(l)
    if (l[l.startIndex] & 0x80) != 0 { k1[k1.count - 1] ^= rb }
    var k2 = shiftLeft(k1)
    if (k1[0] & 0x80) != 0 { k2[k2.count - 1] ^= rb }

    // Chuẩn bị block cuối.
    let blocks: [Data]
    if data.isEmpty {
      var lastBlock = Data([0x80]) + Data(repeating: 0, count: blockSize - 1)
      lastBlock = lastBlock.xored(with: k2)
      blocks = [lastBlock]
    } else {
      let complete = data.count % blockSize == 0
      var chunks = [Data]()
      var offset = data.startIndex
      while offset < data.endIndex {
        let end = data.index(offset, offsetBy: blockSize, limitedBy: data.endIndex) ?? data.endIndex
        chunks.append(Data(data[offset..<end]))
        offset = end
      }
      var lastBlock = chunks.removeLast()
      if complete {
        lastBlock = lastBlock.xored(with: k1)
      } else {
        lastBlock = lastBlock.padded(blockSize: blockSize).xored(with: k2)
      }
      chunks.append(lastBlock)
      blocks = chunks
    }

    var x = zeroBlock
    for block in blocks {
      x = try aesECBEncrypt(x.xored(with: block), key: key)
    }
    return x
  }

  // MARK: - Key derivation

  /// KDF của ICAO 9303 Part 11 §9.7.1: `H(K || [nonce] || counter)`.
  ///
  /// - counter 1 = KSenc, 2 = KSmac, 3 = Kπ (mật khẩu PACE).
  static func deriveKey(
    keySeed: Data,
    nonce: Data? = nil,
    counter: UInt32,
    cipher: SMCipher
  ) -> Data {
    var input = keySeed
    if let nonce = nonce { input += nonce }
    input += counter.bigEndianData
    let digest = Crypto.hash(cipher.kdfDigest, input)
    var key = Data(digest.prefix(cipher.keyLength))
    if cipher == .desEDE {
      key = adjustDESParity(key)
    }
    return key
  }

  /// DES yêu cầu bit thấp nhất của mỗi byte là bit chẵn lẻ lẻ (odd parity).
  static func adjustDESParity(_ key: Data) -> Data {
    Data(key.map { byte -> UInt8 in
      let ones = byte.nonzeroBitCount - (byte & 1 == 1 ? 1 : 0)
      return ones % 2 == 0 ? (byte | 1) : (byte & 0xFE)
    })
  }

  static func randomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
  }
}
