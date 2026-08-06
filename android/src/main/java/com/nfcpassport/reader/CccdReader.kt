package com.nfcpassport.reader

import android.nfc.tech.IsoDep
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import com.nfcpassport.ErrorCode
import com.nfcpassport.ErrorMapper
import com.nfcpassport.NfcPassportException
import com.nfcpassport.ScanRequest
import com.nfcpassport.parser.Dg13Parser
import com.nfcpassport.util.Hex
import com.nfcpassport.util.ImageDecoder
import net.sf.scuba.data.Gender
import net.sf.scuba.smartcards.CardService
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jmrtd.BACKey
import org.jmrtd.PACEKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG15File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.icao.DG7File
import org.jmrtd.lds.icao.MRZInfo
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * Toàn bộ quy trình đọc chip eMRTD/CCCD trên Android.
 *
 * Thứ tự thực hiện bám theo ICAO 9303 Part 11:
 *   PACE (fallback BAC) → SELECT applet → Chip Authentication → đọc DataGroup
 *   → Active Authentication → Passive Authentication.
 *
 * Chip Authentication được chạy **trước** khi đọc các DG lớn để mọi dữ liệu
 * nhạy cảm đều đi qua session key đã được chip chứng minh quyền sở hữu.
 */
class CccdReader(
  private val request: ScanRequest,
  private val progress: ProgressReporter,
) {

  private companion object {
    // OID chuẩn của Chip Authentication (ICAO 9303 Part 11, TR-03110).
    const val ID_CA_DH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.1.1"
    const val ID_CA_ECDH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.2.1"
    const val ID_CA_DH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.1.2"
    const val ID_CA_ECDH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.2.2"

    val DG_TO_FID: Map<String, Short> = mapOf(
      "COM" to PassportService.EF_COM,
      "DG1" to PassportService.EF_DG1,
      "DG2" to PassportService.EF_DG2,
      "DG5" to PassportService.EF_DG5,
      "DG7" to PassportService.EF_DG7,
      "DG11" to PassportService.EF_DG11,
      "DG12" to PassportService.EF_DG12,
      "DG13" to PassportService.EF_DG13,
      "DG14" to PassportService.EF_DG14,
      "DG15" to PassportService.EF_DG15,
      "SOD" to PassportService.EF_SOD,
    )

    val DG_TO_NUMBER: Map<String, Int> = mapOf(
      "DG1" to 1, "DG2" to 2, "DG5" to 5, "DG7" to 7,
      "DG11" to 11, "DG12" to 12, "DG13" to 13, "DG14" to 14, "DG15" to 15,
    )

    /** Thứ tự đọc: file nhỏ trước để có phản hồi UI sớm, DG2 (lớn nhất) sau cùng. */
    val READ_ORDER = listOf("COM", "DG1", "DG13", "DG11", "DG12", "DG15", "DG5", "DG7", "DG2")
  }

  private val rawFiles = LinkedHashMap<String, ByteArray>()

  fun read(isoDep: IsoDep): WritableMap {
    val startedAt = System.currentTimeMillis()
    installBouncyCastle()

    val cardService = CardService.getInstance(isoDep)
    val service: PassportService
    try {
      cardService.open()
      service = PassportService(
        cardService,
        PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        /* isSFIEnabled = */ false,
        /* shouldCheckMAC = */ false,
      )
      service.open()
    } catch (t: Throwable) {
      throw ErrorMapper.map(t, ErrorMapper.Stage.CONNECT)
    }

    try {
      // ---------------------------------------------- 1. Secure Messaging
      val access = establishSecureMessaging(service)

      // ---------------------------------------------- 2. Chip Authentication
      var chipAuth = StepResult.skipped("Không được yêu cầu")
      if (request.chipAuthentication) {
        progress.report("chip_authentication", 0.30, null, "Đang xác thực chip…")
        chipAuth = runChipAuthentication(service)
      }

      // ---------------------------------------------- 3. Đọc DataGroup
      readRequestedFiles(service)

      // ---------------------------------------------- 4. Active Authentication
      var activeAuth = StepResult.skipped("Không được yêu cầu")
      if (request.activeAuthentication) {
        progress.report("active_authentication", 0.88, null, "Đang kiểm tra tính nguyên bản của chip…")
        activeAuth = runActiveAuthentication(service)
      }

      // ---------------------------------------------- 5. Passive Authentication
      var passive: PassiveAuthenticator.Result? = null
      if (request.passiveAuthentication) {
        progress.report("passive_authentication", 0.94, null, "Đang kiểm tra chữ ký số…")
        passive = runPassiveAuthentication()
      }

      return buildResult(access, chipAuth, activeAuth, passive, System.currentTimeMillis() - startedAt)
    } finally {
      runCatching { service.close() }
    }
  }

  // ------------------------------------------------------ Secure Messaging

  private data class AccessResult(
    val protocol: String,
    val paceOid: String?,
    val cipher: String,
  )

  private fun establishSecureMessaging(service: PassportService): AccessResult {
    val bacKey = BACKey(request.documentNumber, request.dateOfBirth, request.dateOfExpiry)
    var paceOid: String? = null

    if (request.usePace) {
      progress.report("reading_card_access", 0.10, null, "Đang đọc thông số bảo mật…")
      paceOid = tryPace(service, bacKey)
    }

    val paceSucceeded = paceOid != null

    progress.report("selecting_applet", 0.24, null, "Đang mở ứng dụng eMRTD…")
    try {
      service.sendSelectApplet(paceSucceeded)
    } catch (t: Throwable) {
      throw ErrorMapper.map(t, ErrorMapper.Stage.SELECT_APPLET)
    }

    if (paceSucceeded) {
      return AccessResult("PACE", paceOid, cipherFromPaceOid(paceOid!!))
    }

    if (!request.allowBacFallback) {
      throw NfcPassportException(
        ErrorCode.PACE_FAILED,
        "PACE thất bại và fallback BAC đang bị tắt"
      )
    }
    if (request.useCan) {
      throw NfcPassportException(
        ErrorCode.PACE_FAILED,
        "CAN chỉ dùng được với PACE, nhưng PACE không khả dụng trên thẻ này"
      )
    }

    progress.report("bac", 0.26, null, "Đang thiết lập kênh bảo mật (BAC)…")
    try {
      service.doBAC(bacKey)
    } catch (t: Throwable) {
      throw ErrorMapper.map(t, ErrorMapper.Stage.BAC)
    }
    return AccessResult("BAC", null, "DESede")
  }

  /** Trả về OID của PACE nếu thành công, `null` nếu thẻ không hỗ trợ / thất bại. */
  private fun tryPace(service: PassportService, bacKey: BACKey): String? {
    val paceInfos = try {
      val bytes = service.getInputStream(PassportService.EF_CARD_ACCESS).use { it.readBytes() }
      CardAccessFile(ByteArrayInputStream(bytes)).securityInfos.filterIsInstance<PACEInfo>()
    } catch (e: Exception) {
      // Không có EF.CardAccess ⇒ thẻ chỉ hỗ trợ BAC.
      return null
    }

    if (paceInfos.isEmpty()) return null

    val keySpec = try {
      if (request.useCan) PACEKeySpec.createCANKey(request.can)
      else PACEKeySpec.createMRZKey(bacKey)
    } catch (e: Exception) {
      throw NfcPassportException(ErrorCode.INVALID_ARGUMENT, "Không tạo được khoá PACE: ${e.message}", null, e)
    }

    var lastFailure: Throwable? = null
    for (info in paceInfos) {
      progress.report("pace", 0.16, null, "Đang thiết lập kênh bảo mật (PACE)…")
      try {
        service.doPACE(
          keySpec,
          info.objectIdentifier,
          PACEInfo.toParameterSpec(info.parameterId),
          info.parameterId,
        )
        return info.objectIdentifier
      } catch (t: Throwable) {
        lastFailure = t
      }
    }

    // PACE có mặt nhưng thất bại. Nếu chip từ chối vì sai khoá thì fallback BAC
    // cũng sẽ hỏng — báo lỗi ngay để người dùng sửa MRZ thay vì chờ thêm.
    val mapped = lastFailure?.let { ErrorMapper.map(it, ErrorMapper.Stage.PACE) }
    if (mapped?.code == ErrorCode.INVALID_MRZ_KEY) throw mapped
    if (!request.allowBacFallback && mapped != null) throw mapped
    return null
  }

  private fun cipherFromPaceOid(oid: String): String =
    if (oid.contains("3DES") || oid.endsWith(".1.1") || oid.endsWith(".2.1")) "DESede" else "AES"

  // ---------------------------------------------------- Chip Authentication

  private fun runChipAuthentication(service: PassportService): StepResult {
    val dg14Bytes = try {
      readFile(service, "DG14")
    } catch (e: Exception) {
      return StepResult.skipped("Thẻ không có DG14")
    }

    val securityInfos = try {
      DG14File(ByteArrayInputStream(dg14Bytes)).securityInfos
    } catch (e: Exception) {
      return StepResult.failed("Không parse được DG14: ${e.message}")
    }

    val publicKeyInfos = securityInfos.filterIsInstance<ChipAuthenticationPublicKeyInfo>()
    if (publicKeyInfos.isEmpty()) {
      return StepResult.skipped("DG14 không có ChipAuthenticationPublicKeyInfo")
    }
    val caInfos = securityInfos.filterIsInstance<ChipAuthenticationInfo>()

    var lastError: String? = null
    for (publicKeyInfo in publicKeyInfos) {
      val keyId = publicKeyInfo.keyId
      val caInfo = caInfos.firstOrNull { it.keyId == null || it.keyId == keyId }
      val oid = caInfo?.objectIdentifier ?: inferCaOid(publicKeyInfo)
      try {
        service.doEACCA(keyId, oid, publicKeyInfo.objectIdentifier, publicKeyInfo.subjectPublicKey)
        return StepResult.ok()
      } catch (t: Throwable) {
        lastError = t.message
      }
    }
    return StepResult.failed(lastError ?: "Chip Authentication thất bại")
  }

  /**
   * DG14 có thể chỉ công bố public key mà không kèm `ChipAuthenticationInfo`.
   * Khi đó suy ra OID từ loại khoá; AES-CMAC-128 là mặc định của các thẻ hiện đại.
   */
  private fun inferCaOid(publicKeyInfo: ChipAuthenticationPublicKeyInfo): String {
    val isEc = publicKeyInfo.subjectPublicKey is ECPublicKey
    return if (isEc) ID_CA_ECDH_AES_CBC_CMAC_128 else ID_CA_DH_AES_CBC_CMAC_128
  }

  // -------------------------------------------------- Active Authentication

  private fun runActiveAuthentication(service: PassportService): StepResult {
    val dg15Bytes = rawFiles["DG15"] ?: return StepResult.skipped("Thẻ không có DG15")
    val publicKey = try {
      DG15File(ByteArrayInputStream(dg15Bytes)).publicKey
    } catch (e: Exception) {
      return StepResult.failed("Không parse được DG15: ${e.message}")
    }

    val challenge = ByteArray(8).also { SecureRandom().nextBytes(it) }
    val response = try {
      // JMRTD chỉ gửi INTERNAL AUTHENTICATE; digest/signature algorithm ở đây
      // chỉ là gợi ý, việc kiểm chứng do ActiveAuthVerifier đảm nhiệm.
      service.doAA(publicKey, "SHA-256", "SHA256withRSA/ISO9796-2", challenge).response
    } catch (t: Throwable) {
      return StepResult.failed("INTERNAL AUTHENTICATE thất bại: ${t.message}")
    }

    return if (ActiveAuthVerifier.verify(publicKey, challenge, response)) StepResult.ok()
    else StepResult.failed("Chữ ký Active Authentication không hợp lệ")
  }

  // ------------------------------------------------- Passive Authentication

  private fun runPassiveAuthentication(): PassiveAuthenticator.Result {
    val sodBytes = rawFiles["SOD"]
      ?: return PassiveAuthenticator.Result(
        succeeded = false,
        dataGroupHashesValid = false,
        sodSignatureValid = false,
        documentSignerTrusted = false,
        mismatchedDataGroups = emptyList(),
        reason = "Không đọc được EF.SOD",
      )

    val sodFile = try {
      SODFile(ByteArrayInputStream(sodBytes))
    } catch (e: Exception) {
      return PassiveAuthenticator.Result(
        succeeded = false,
        dataGroupHashesValid = false,
        sodSignatureValid = false,
        documentSignerTrusted = false,
        mismatchedDataGroups = emptyList(),
        reason = "Không parse được EF.SOD: ${e.message}",
      )
    }

    val dgBytes = rawFiles.entries
      .mapNotNull { (name, bytes) -> DG_TO_NUMBER[name]?.let { it to bytes } }
      .toMap()

    return PassiveAuthenticator.verify(sodFile, sodBytes, dgBytes, request.cscaCertificates)
  }

  // ----------------------------------------------------------- đọc file

  private fun readRequestedFiles(service: PassportService) {
    val wanted = LinkedHashSet(request.dataGroups)
    if (request.passiveAuthentication) {
      wanted.add("SOD")
      wanted.add("COM")
    }
    // DG14 đã được đọc ở bước Chip Authentication.
    wanted.remove("DG14")

    val ordered = READ_ORDER.filter { wanted.contains(it) } +
      wanted.filter { !READ_ORDER.contains(it) && it != "SOD" }
    val plan = ordered + listOfNotNull("SOD".takeIf { wanted.contains(it) })

    plan.forEachIndexed { index, name ->
      val fraction = 0.32 + 0.54 * (index.toDouble() / plan.size.coerceAtLeast(1))
      progress.report("reading_datagroup", fraction, name, "Đang đọc $name…")
      try {
        readFile(service, name)
      } catch (t: Throwable) {
        val mapped = ErrorMapper.map(t, ErrorMapper.Stage.READ)
        // Mất thẻ hoặc đứt kênh là lỗi thật và phải dừng. Ngược lại, chip trả về
        // một status word cụ thể (6A82 file not found, 6982 chưa đủ quyền…) —
        // nghĩa là file đó không có trên thẻ này, bỏ qua và đọc tiếp.
        val fatal = mapped.code == ErrorCode.TAG_LOST ||
          (mapped.code == ErrorCode.COMMUNICATION_ERROR && mapped.statusWord == null)
        if (fatal) throw mapped
      }
    }
  }

  private fun readFile(service: PassportService, name: String): ByteArray {
    rawFiles[name]?.let { return it }
    val fid = DG_TO_FID[name]
      ?: throw NfcPassportException(ErrorCode.INVALID_ARGUMENT, "DataGroup không hỗ trợ: $name")
    val bytes = service.getInputStream(fid).use { it.readBytes() }
    if (bytes.isEmpty()) {
      throw NfcPassportException(ErrorCode.COMMUNICATION_ERROR, "$name rỗng")
    }
    rawFiles[name] = bytes
    return bytes
  }

  // ------------------------------------------------------------- kết quả

  private data class StepResult(
    val succeeded: Boolean,
    val skipped: Boolean,
    val reason: String?,
  ) {
    companion object {
      fun ok() = StepResult(true, false, null)
      fun failed(reason: String) = StepResult(false, false, reason)
      fun skipped(reason: String) = StepResult(false, true, reason)
    }
  }

  private fun buildResult(
    access: AccessResult,
    chipAuth: StepResult,
    activeAuth: StepResult,
    passive: PassiveAuthenticator.Result?,
    durationMs: Long,
  ): WritableMap {
    val result = Arguments.createMap()

    rawFiles["DG1"]?.let { bytes ->
      runCatching { DG1File(ByteArrayInputStream(bytes)).mrzInfo }
        .getOrNull()?.let { result.putMap("mrz", mapMrzInfo(it)) }
    }

    rawFiles["DG13"]?.let { bytes ->
      runCatching { Dg13Parser.parse(bytes) }
        .getOrNull()?.let { result.putMap("personal", mapPersonalInfo(it)) }
    }

    if (request.includeImages) {
      rawFiles["DG2"]?.let { bytes ->
        runCatching { extractFaceImage(bytes) }.getOrNull()?.let { result.putMap("faceImage", it) }
      }
      rawFiles["DG7"]?.let { bytes ->
        runCatching { extractSignatureImage(bytes) }.getOrNull()
          ?.let { result.putMap("signatureImage", it) }
      }
    }

    result.putMap("security", Arguments.createMap().apply {
      putString("accessProtocol", access.protocol)
      access.paceOid?.let { putString("paceOid", it) }
      putString("secureMessagingCipher", access.cipher)
      putMap("chipAuthentication", mapStep(chipAuth))
      putMap("activeAuthentication", mapStep(activeAuth))
      putMap("passiveAuthentication", Arguments.createMap().apply {
        putBoolean("succeeded", passive?.succeeded ?: false)
        putBoolean("skipped", passive == null)
        passive?.reason?.let { putString("reason", it) }
        if (passive == null) putString("reason", "Không được yêu cầu")
        putBoolean("dataGroupHashesValid", passive?.dataGroupHashesValid ?: false)
        putBoolean("sodSignatureValid", passive?.sodSignatureValid ?: false)
        putBoolean("documentSignerTrusted", passive?.documentSignerTrusted ?: false)
        putArray("mismatchedDataGroups", Arguments.createArray().apply {
          passive?.mismatchedDataGroups?.forEach { pushString(it) }
        })
      })
    })

    rawFiles["SOD"]?.let { bytes ->
      runCatching { mapSod(SODFile(ByteArrayInputStream(bytes))) }
        .getOrNull()?.let { result.putMap("sod", it) }
    }

    if (request.includeRawData) {
      result.putMap("raw", Arguments.createMap().apply {
        rawFiles.forEach { (name, bytes) -> putString(name, Hex.encode(bytes)) }
      })
    }

    result.putString("readAt", iso8601Now())
    result.putDouble("durationMs", durationMs.toDouble())
    return result
  }

  private fun mapStep(step: StepResult): WritableMap = Arguments.createMap().apply {
    putBoolean("succeeded", step.succeeded)
    putBoolean("skipped", step.skipped)
    step.reason?.let { putString("reason", it) }
  }

  private fun mapMrzInfo(info: MRZInfo): WritableMap = Arguments.createMap().apply {
    putString("raw", info.toString().trim())
    putString(
      "format",
      when (info.documentType) {
        MRZInfo.DOC_TYPE_ID1 -> "TD1"
        MRZInfo.DOC_TYPE_ID2 -> "TD2"
        MRZInfo.DOC_TYPE_ID3 -> "TD3"
        else -> "UNKNOWN"
      }
    )
    putString("documentCode", info.documentCode.orEmpty())
    putString("issuingState", info.issuingState.orEmpty())
    putString("documentNumber", info.documentNumber.orEmpty().replace("<", ""))
    putString("primaryIdentifier", info.primaryIdentifier.orEmpty().replace("<", " ").trim())
    putString("secondaryIdentifier", info.secondaryIdentifier.orEmpty().replace("<", " ").trim())
    putString("nationality", info.nationality.orEmpty())
    putString("dateOfBirth", info.dateOfBirth.orEmpty())
    putString(
      "gender",
      when (info.gender) {
        Gender.MALE -> "M"
        Gender.FEMALE -> "F"
        else -> "<"
      }
    )
    putString("dateOfExpiry", info.dateOfExpiry.orEmpty())
    putString("optionalData1", runCatching { info.optionalData1.orEmpty() }.getOrDefault(""))
    putString("optionalData2", runCatching { info.optionalData2.orEmpty() }.getOrDefault(""))
  }

  private fun mapPersonalInfo(info: Dg13Parser.PersonalInfo): WritableMap = Arguments.createMap().apply {
    info.idNumber?.let { putString("idNumber", it) }
    info.oldIdNumber?.let { putString("oldIdNumber", it) }
    info.fullName?.let { putString("fullName", it) }
    info.dateOfBirth?.let { putString("dateOfBirth", it) }
    info.gender?.let { putString("gender", it) }
    info.nationality?.let { putString("nationality", it) }
    info.ethnicity?.let { putString("ethnicity", it) }
    info.religion?.let { putString("religion", it) }
    info.placeOfOrigin?.let { putString("placeOfOrigin", it) }
    info.placeOfResidence?.let { putString("placeOfResidence", it) }
    info.personalIdentification?.let { putString("personalIdentification", it) }
    info.dateOfIssue?.let { putString("dateOfIssue", it) }
    info.dateOfExpiry?.let { putString("dateOfExpiry", it) }
    info.fatherName?.let { putString("fatherName", it) }
    info.motherName?.let { putString("motherName", it) }
    info.spouseName?.let { putString("spouseName", it) }
    putArray("rawFields", Arguments.createArray().apply {
      info.rawFields.forEach { pushString(it) }
    })
  }

  private fun extractFaceImage(dg2Bytes: ByteArray): WritableMap? {
    val faceInfo = DG2File(ByteArrayInputStream(dg2Bytes)).faceInfos.firstOrNull() ?: return null
    val imageInfo = faceInfo.faceImageInfos.firstOrNull() ?: return null
    val bytes = imageInfo.imageInputStream.use { it.readBytes() }
    val decoded = ImageDecoder.decode(bytes, imageInfo.mimeType, imageInfo.width, imageInfo.height)
    return mapImage(decoded)
  }

  private fun extractSignatureImage(dg7Bytes: ByteArray): WritableMap? {
    val imageInfo = DG7File(ByteArrayInputStream(dg7Bytes)).images.firstOrNull() ?: return null
    val bytes = imageInfo.imageInputStream.use { it.readBytes() }
    val decoded = ImageDecoder.decode(bytes, imageInfo.mimeType, 0, 0)
    return mapImage(decoded)
  }

  private fun mapImage(decoded: ImageDecoder.DecodedImage): WritableMap = Arguments.createMap().apply {
    putString("base64", decoded.base64)
    putString("mimeType", decoded.mimeType)
    putInt("width", decoded.width)
    putInt("height", decoded.height)
    putBoolean("transcoded", decoded.transcoded)
  }

  private fun mapSod(sod: SODFile): WritableMap = Arguments.createMap().apply {
    putString("digestAlgorithm", sod.digestAlgorithm.orEmpty())
    putString(
      "signatureAlgorithm",
      runCatching { sod.digestEncryptionAlgorithm.orEmpty() }.getOrDefault("")
    )
    putMap("dataGroupHashes", Arguments.createMap().apply {
      sod.dataGroupHashes.forEach { (number, hash) -> putString("DG$number", Hex.encode(hash)) }
    })
    runCatching { sod.docSigningCertificate }.getOrNull()?.let { cert ->
      putMap("documentSigner", Arguments.createMap().apply {
        putString("subject", cert.subjectX500Principal.name)
        putString("issuer", cert.issuerX500Principal.name)
        putString("serialNumber", cert.serialNumber.toString(16))
        putString("notBefore", iso8601(cert.notBefore.time))
        putString("notAfter", iso8601(cert.notAfter.time))
      })
    }
  }

  // --------------------------------------------------------------- helpers

  private fun installBouncyCastle() {
    // Android đóng gói sẵn một bản BC rút gọn dưới tên "BC"; phải thay bằng bản
    // đầy đủ thì JMRTD mới dùng được Brainpool và AES-CMAC.
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) !is BouncyCastleProvider) {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
      Security.insertProviderAt(BouncyCastleProvider(), 1)
    }
  }

  private fun iso8601Now(): String = iso8601(System.currentTimeMillis())

  private fun iso8601(millis: Long): String {
    val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
    format.timeZone = TimeZone.getTimeZone("UTC")
    return format.format(java.util.Date(millis))
  }
}
