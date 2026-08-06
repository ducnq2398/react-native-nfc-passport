import Foundation
import OpenSSL

/// Số học đường cong elliptic cho PACE và Chip Authentication.
///
/// Security.framework và CryptoKit chỉ hỗ trợ các đường cong NIST, trong khi
/// eMRTD dùng phổ biến họ Brainpool — vì vậy phần này dựa trên OpenSSL. Chỉ cần
/// EC_GROUP / EC_POINT / BIGNUM nên không đụng tới API EC_KEY đã deprecated.
final class ECGroup {

  /// Mã tham số miền chuẩn hoá — ICAO 9303 Part 11 Table 5 / BSI TR-03110.
  static func nid(forStandardizedParameterId id: Int) -> Int32? {
    switch id {
    case 8: return NID_X9_62_prime192v1     // NIST P-192
    case 9: return NID_brainpoolP192r1
    case 10: return NID_secp224r1           // NIST P-224
    case 11: return NID_brainpoolP224r1
    case 12: return NID_X9_62_prime256v1    // NIST P-256
    case 13: return NID_brainpoolP256r1
    case 14: return NID_brainpoolP320r1
    case 15: return NID_secp384r1           // NIST P-384
    case 16: return NID_brainpoolP384r1
    case 17: return NID_brainpoolP512r1
    case 18: return NID_secp521r1           // NIST P-521
    // 0, 1, 2 là các nhóm MODP-DH — không hỗ trợ, xem ghi chú ở PACE.swift.
    default: return nil
    }
  }

  /// OID đường cong có tên → NID của OpenSSL. Dùng khi SubjectPublicKeyInfo
  /// trong DG14 tham chiếu đường cong bằng tên thay vì tham số tường minh.
  static func nid(forCurveOID oid: String) -> Int32? {
    switch oid {
    case "1.2.840.10045.3.1.1": return NID_X9_62_prime192v1
    case "1.3.132.0.33": return NID_secp224r1
    case "1.2.840.10045.3.1.7": return NID_X9_62_prime256v1
    case "1.3.132.0.34": return NID_secp384r1
    case "1.3.132.0.35": return NID_secp521r1
    case "1.3.36.3.3.2.8.1.1.1": return NID_brainpoolP160r1
    case "1.3.36.3.3.2.8.1.1.3": return NID_brainpoolP192r1
    case "1.3.36.3.3.2.8.1.1.5": return NID_brainpoolP224r1
    case "1.3.36.3.3.2.8.1.1.7": return NID_brainpoolP256r1
    case "1.3.36.3.3.2.8.1.1.9": return NID_brainpoolP320r1
    case "1.3.36.3.3.2.8.1.1.11": return NID_brainpoolP384r1
    case "1.3.36.3.3.2.8.1.1.13": return NID_brainpoolP512r1
    default: return nil
    }
  }

  fileprivate let group: OpaquePointer
  fileprivate let ctx: OpaquePointer
  private let ownsGroup: Bool

  /// Số byte của một toạ độ affine trên đường cong này.
  let fieldSize: Int

  init?(nid: Int32) {
    guard let group = EC_GROUP_new_by_curve_name(nid), let ctx = BN_CTX_new() else { return nil }
    self.group = group
    self.ctx = ctx
    self.ownsGroup = true
    self.fieldSize = (Int(EC_GROUP_get_degree(group)) + 7) / 8
  }

  private init(group: OpaquePointer, ctx: OpaquePointer, fieldSize: Int) {
    self.group = group
    self.ctx = ctx
    self.ownsGroup = true
    self.fieldSize = fieldSize
  }

  /// Dựng nhóm từ ECParameters tường minh — DG14 của nhiều thẻ công bố tham số
  /// miền dạng đầy đủ thay vì tham chiếu đường cong có tên.
  init?(primeP: Data, a: Data, b: Data, generator: Data, order: Data, cofactor: Data) {
    guard let ctx = BN_CTX_new() else { return nil }
    guard let pBN = ECGroup.bignum(from: primeP),
          let aBN = ECGroup.bignum(from: a),
          let bBN = ECGroup.bignum(from: b),
          let orderBN = ECGroup.bignum(from: order),
          let cofactorBN = ECGroup.bignum(from: cofactor.isEmpty ? Data([0x01]) : cofactor)
    else {
      BN_CTX_free(ctx)
      return nil
    }
    defer {
      BN_free(pBN)
      BN_free(aBN)
      BN_free(bBN)
      BN_free(orderBN)
      BN_free(cofactorBN)
    }

    guard let group = EC_GROUP_new_curve_GFp(pBN, aBN, bBN, ctx) else {
      BN_CTX_free(ctx)
      return nil
    }
    guard let generatorPoint = EC_POINT_new(group) else {
      EC_GROUP_free(group)
      BN_CTX_free(ctx)
      return nil
    }
    defer { EC_POINT_free(generatorPoint) }

    let decoded = generator.withUnsafeBytes { buffer -> Int32 in
      EC_POINT_oct2point(
        group, generatorPoint,
        buffer.bindMemory(to: UInt8.self).baseAddress, generator.count, ctx
      )
    }
    guard decoded == 1,
          EC_GROUP_set_generator(group, generatorPoint, orderBN, cofactorBN) == 1
    else {
      EC_GROUP_free(group)
      BN_CTX_free(ctx)
      return nil
    }

    self.group = group
    self.ctx = ctx
    self.ownsGroup = true
    self.fieldSize = (Int(EC_GROUP_get_degree(group)) + 7) / 8
  }

  deinit {
    if ownsGroup { EC_GROUP_free(group) }
    BN_CTX_free(ctx)
  }

  // MARK: - Điểm

  /// Giải mã điểm từ dạng octet (uncompressed `04 || X || Y`).
  func point(from data: Data) -> ECPointRef? {
    guard let point = EC_POINT_new(group) else { return nil }
    let ok = data.withUnsafeBytes { buffer -> Int32 in
      EC_POINT_oct2point(group, point, buffer.bindMemory(to: UInt8.self).baseAddress, data.count, ctx)
    }
    guard ok == 1 else {
      EC_POINT_free(point)
      return nil
    }
    return ECPointRef(point: point, group: self)
  }

  /// Mã hoá điểm về dạng uncompressed.
  func encode(_ point: ECPointRef) -> Data? {
    let form = POINT_CONVERSION_UNCOMPRESSED
    let length = EC_POINT_point2oct(group, point.point, form, nil, 0, ctx)
    guard length > 0 else { return nil }
    var buffer = [UInt8](repeating: 0, count: length)
    guard EC_POINT_point2oct(group, point.point, form, &buffer, length, ctx) == length else { return nil }
    return Data(buffer)
  }

  var generator: ECPointRef? {
    guard let g = EC_GROUP_get0_generator(group), let copy = EC_POINT_dup(g, group) else { return nil }
    return ECPointRef(point: copy, group: self)
  }

  var order: Data? {
    guard let bn = BN_new() else { return nil }
    defer { BN_free(bn) }
    guard EC_GROUP_get_order(group, bn, ctx) == 1 else { return nil }
    return ECGroup.data(from: bn)
  }

  /// `result = scalar · point`
  func multiply(_ point: ECPointRef, by scalar: Data) -> ECPointRef? {
    guard let bn = ECGroup.bignum(from: scalar), let result = EC_POINT_new(group) else { return nil }
    defer { BN_free(bn) }
    guard EC_POINT_mul(group, result, nil, point.point, bn, ctx) == 1 else {
      EC_POINT_free(result)
      return nil
    }
    return ECPointRef(point: result, group: self)
  }

  /// `result = a + b`
  func add(_ a: ECPointRef, _ b: ECPointRef) -> ECPointRef? {
    guard let result = EC_POINT_new(group) else { return nil }
    guard EC_POINT_add(group, result, a.point, b.point, ctx) == 1 else {
      EC_POINT_free(result)
      return nil
    }
    return ECPointRef(point: result, group: self)
  }

  /// Toạ độ X affine, đệm về đúng `fieldSize` byte (giá trị chia sẻ của ECDH).
  func affineX(_ point: ECPointRef) -> Data? {
    guard let x = BN_new() else { return nil }
    defer { BN_free(x) }
    guard EC_POINT_get_affine_coordinates(group, point.point, x, nil, ctx) == 1 else { return nil }
    return ECGroup.data(from: x)?.leftPadded(to: fieldSize)
  }

  // MARK: - Khoá tạm thời

  struct KeyPair {
    let privateScalar: Data
    let publicPoint: ECPointRef
  }

  /// Sinh cặp khoá tạm thời trên generator hiện tại của nhóm.
  func generateKeyPair() -> KeyPair? {
    guard let orderBN = BN_new(), let scalar = BN_new() else { return nil }
    defer {
      BN_free(orderBN)
      BN_free(scalar)
    }
    guard EC_GROUP_get_order(group, orderBN, ctx) == 1 else { return nil }

    // Loại bỏ 0 để tránh điểm vô cực.
    repeat {
      guard BN_rand_range(scalar, orderBN) == 1 else { return nil }
    } while BN_is_zero(scalar) == 1

    guard let publicPoint = EC_POINT_new(group) else { return nil }
    guard EC_POINT_mul(group, publicPoint, scalar, nil, nil, ctx) == 1,
          let privateScalar = ECGroup.data(from: scalar)
    else {
      EC_POINT_free(publicPoint)
      return nil
    }
    return KeyPair(
      privateScalar: privateScalar,
      publicPoint: ECPointRef(point: publicPoint, group: self)
    )
  }

  /// Nhóm mới dùng `newGenerator` làm điểm sinh — bước Generic Mapping của PACE.
  func withGenerator(_ newGenerator: ECPointRef) -> ECGroup? {
    guard let copy = EC_GROUP_dup(group),
          let newCtx = BN_CTX_new(),
          let orderBN = BN_new(),
          let cofactorBN = BN_new()
    else { return nil }
    defer {
      BN_free(orderBN)
      BN_free(cofactorBN)
    }
    guard EC_GROUP_get_order(group, orderBN, ctx) == 1,
          EC_GROUP_get_cofactor(group, cofactorBN, ctx) == 1,
          EC_GROUP_set_generator(copy, newGenerator.point, orderBN, cofactorBN) == 1
    else {
      EC_GROUP_free(copy)
      BN_CTX_free(newCtx)
      return nil
    }
    return ECGroup(group: copy, ctx: newCtx, fieldSize: fieldSize)
  }

  // MARK: - BIGNUM helpers

  fileprivate static func bignum(from data: Data) -> OpaquePointer? {
    data.withUnsafeBytes { buffer in
      BN_bin2bn(buffer.bindMemory(to: UInt8.self).baseAddress, Int32(data.count), nil)
    }
  }

  fileprivate static func data(from bn: OpaquePointer) -> Data? {
    // BN_num_bytes là macro nên Swift không import được — tính trực tiếp từ số bit.
    let size = (Int(BN_num_bits(bn)) + 7) / 8
    guard size > 0 else { return Data() }
    var buffer = [UInt8](repeating: 0, count: size)
    guard BN_bn2bin(bn, &buffer) == Int32(size) else { return nil }
    return Data(buffer)
  }
}

/// Một điểm EC gắn với nhóm sinh ra nó (giữ tham chiếu để nhóm không bị giải phóng trước).
final class ECPointRef {
  fileprivate let point: OpaquePointer
  private let owner: ECGroup

  fileprivate init(point: OpaquePointer, group: ECGroup) {
    self.point = point
    self.owner = group
  }

  deinit {
    EC_POINT_free(point)
  }
}
