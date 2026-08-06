package com.nfcpassport.reader

import android.util.Base64
import com.nfcpassport.util.Tlv
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jmrtd.lds.SODFile
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Passive Authentication (ICAO 9303 Part 11 §5.1).
 *
 * Ba lớp kiểm tra độc lập:
 *  1. Hash của từng DataGroup đọc được khớp với hash công bố trong EF.SOD.
 *  2. Chữ ký CMS trên EF.SOD hợp lệ với public key của Document Signer (DSC).
 *  3. DSC được ký bởi một CSCA nằm trong danh sách tin cậy do ứng dụng cung cấp.
 *
 * Chỉ (1) + (2) thì chứng minh dữ liệu không bị sửa **so với SOD**, nhưng chưa
 * chứng minh SOD do cơ quan phát hành hợp pháp tạo ra — cần (3) cho việc đó.
 */
object PassiveAuthenticator {

  data class Result(
    val succeeded: Boolean,
    val dataGroupHashesValid: Boolean,
    val sodSignatureValid: Boolean,
    val documentSignerTrusted: Boolean,
    val mismatchedDataGroups: List<String>,
    val reason: String?,
  )

  fun verify(
    sodFile: SODFile,
    sodBytes: ByteArray,
    dataGroupBytes: Map<Int, ByteArray>,
    cscaCertificates: List<String>,
  ): Result {
    val reasons = mutableListOf<String>()

    // --- 1. Đối chiếu hash DataGroup ---
    val mismatched = mutableListOf<String>()
    var checkedCount = 0
    val expectedHashes: Map<Int, ByteArray> = sodFile.dataGroupHashes
    val digest = try {
      MessageDigest.getInstance(sodFile.digestAlgorithm)
    } catch (e: Exception) {
      reasons.add("Không hỗ trợ thuật toán băm ${sodFile.digestAlgorithm}")
      null
    }

    if (digest != null) {
      for ((dgNumber, expected) in expectedHashes) {
        val raw = dataGroupBytes[dgNumber] ?: continue // DG không được yêu cầu đọc
        checkedCount++
        digest.reset()
        val actual = digest.digest(raw)
        if (!MessageDigest.isEqual(expected, actual)) {
          mismatched.add("DG$dgNumber")
        }
      }
    }
    val hashesValid = digest != null && mismatched.isEmpty() && checkedCount > 0
    if (checkedCount == 0) reasons.add("Không có DataGroup nào để đối chiếu hash")
    if (mismatched.isNotEmpty()) reasons.add("Hash không khớp: ${mismatched.joinToString()}")

    // --- 2. Chữ ký CMS trên SOD ---
    val dsc: X509Certificate? = try {
      sodFile.docSigningCertificate
    } catch (e: Exception) {
      null
    }
    var signatureValid = false
    if (dsc == null) {
      reasons.add("EF.SOD không chứa chứng thư Document Signer")
    } else {
      signatureValid = try {
        val signedData = CMSSignedData(Tlv.unwrapSod(sodBytes))
        val verifier = JcaSimpleSignerInfoVerifierBuilder()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .build(dsc)
        signedData.signerInfos.signers.all { it.verify(verifier) }
      } catch (e: Exception) {
        reasons.add("Chữ ký SOD không hợp lệ: ${e.message}")
        false
      }
    }

    // --- 3. Chuỗi tin cậy tới CSCA ---
    var trusted = false
    if (dsc != null && cscaCertificates.isNotEmpty()) {
      val cscaCerts = parseCertificates(cscaCertificates)
      trusted = cscaCerts.any { csca ->
        try {
          dsc.verify(csca.publicKey, BouncyCastleProvider.PROVIDER_NAME)
          csca.checkValidity()
          true
        } catch (e: Exception) {
          false
        }
      }
      if (!trusted) reasons.add("DSC không khớp với CSCA nào được cung cấp")
    }

    val succeeded = hashesValid && signatureValid &&
      (cscaCertificates.isEmpty() || trusted)

    return Result(
      succeeded = succeeded,
      dataGroupHashesValid = hashesValid,
      sodSignatureValid = signatureValid,
      documentSignerTrusted = trusted,
      mismatchedDataGroups = mismatched,
      reason = reasons.takeIf { it.isNotEmpty() }?.joinToString("; "),
    )
  }

  private fun parseCertificates(sources: List<String>): List<X509Certificate> {
    val factory = CertificateFactory.getInstance("X.509")
    return sources.mapNotNull { source ->
      try {
        val der = if (source.contains("-----BEGIN")) {
          val body = source
            .substringAfter("-----BEGIN CERTIFICATE-----")
            .substringBefore("-----END CERTIFICATE-----")
            .replace(Regex("\\s"), "")
          Base64.decode(body, Base64.DEFAULT)
        } else {
          Base64.decode(source.replace(Regex("\\s"), ""), Base64.DEFAULT)
        }
        factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
      } catch (e: Exception) {
        null
      }
    }
  }
}
