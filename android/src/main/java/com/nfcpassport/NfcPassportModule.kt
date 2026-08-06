package com.nfcpassport

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule
import com.nfcpassport.reader.CccdReader
import com.nfcpassport.reader.ProgressReporter
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class NfcPassportModule(private val reactContext: ReactApplicationContext) :
  NfcPassportSpec(reactContext), NfcAdapter.ReaderCallback, LifecycleEventListener {

  companion object {
    const val NAME = "NfcPassport"
    private const val PROGRESS_EVENT = "NfcPassport:progress"

    /**
     * Chip eMRTD trả lời chậm khi Secure Messaging bật; 20s cho mỗi transceive
     * là đủ rộng nhưng vẫn phát hiện được thẻ đã rời.
     */
    private const val ISO_DEP_TIMEOUT_MS = 20_000

    /**
     * Khoảng giữa hai lần kiểm tra thẻ còn trong vùng đọc. Đặt lớn để tránh
     * ngắt giữa một chuỗi APDU dài (đọc DG2 có thể mất vài giây).
     */
    private const val PRESENCE_CHECK_DELAY_MS = 5_000
  }

  /** Một phiên quét đang chạy. */
  private class Session(
    val request: ScanRequest,
    val promise: Promise,
    val settled: AtomicBoolean = AtomicBoolean(false),
  )

  private val session = AtomicReference<Session?>(null)
  private val executor = Executors.newSingleThreadExecutor()
  private val mainHandler = Handler(Looper.getMainLooper())
  private var timeoutRunnable: Runnable? = null
  private var listenerCount = 0

  init {
    reactContext.addLifecycleEventListener(this)
  }

  override fun getName(): String = NAME

  override fun invalidate() {
    reactContext.removeLifecycleEventListener(this)
    rejectSession(ErrorCode.CANCELLED, "Module bị huỷ")
    executor.shutdownNow()
    super.invalidate()
  }

  // ---------------------------------------------------------------- JS API

  @ReactMethod
  override fun isSupported(promise: Promise) {
    promise.resolve(adapter() != null)
  }

  @ReactMethod
  override fun isEnabled(promise: Promise) {
    promise.resolve(adapter()?.isEnabled == true)
  }

  @ReactMethod
  override fun openNfcSettings(promise: Promise) {
    val activity = reactContext.currentActivity
    val intent = Intent(Settings.ACTION_NFC_SETTINGS).apply {
      if (activity == null) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
      (activity ?: reactContext).startActivity(intent)
      promise.resolve(true)
    } catch (e: Exception) {
      promise.resolve(false)
    }
  }

  @ReactMethod
  override fun startScan(options: ReadableMap, promise: Promise) {
    val request = try {
      ScanRequest.from(options)
    } catch (e: NfcPassportException) {
      promise.reject(e.code.name, e.message, e)
      return
    }

    val adapter = adapter()
    if (adapter == null) {
      promise.reject(ErrorCode.NOT_SUPPORTED.name, "Thiết bị không hỗ trợ NFC")
      return
    }
    if (!adapter.isEnabled) {
      promise.reject(ErrorCode.NFC_DISABLED.name, "NFC đang tắt")
      return
    }

    val activity = reactContext.currentActivity
    if (activity == null) {
      promise.reject(
        ErrorCode.UNKNOWN.name,
        "Không lấy được Activity hiện tại — hãy gọi scan() khi app đang ở foreground"
      )
      return
    }

    val newSession = Session(request, promise)
    if (!session.compareAndSet(null, newSession)) {
      promise.reject(ErrorCode.SESSION_BUSY.name, "Đang có một phiên quét khác")
      return
    }

    emitProgress("waiting_for_tag", 0.0, "Đưa thẻ CCCD lại gần điện thoại")
    enableReaderMode(activity, adapter)
    scheduleTimeout(request.timeoutMs)
  }

  @ReactMethod
  override fun cancel(promise: Promise) {
    promise.resolve(rejectSession(ErrorCode.CANCELLED, "Phiên quét đã bị huỷ"))
  }

  @ReactMethod
  override fun setSessionMessage(message: String) {
    // Chỉ có ý nghĩa trên iOS (NFC system sheet). Android không có UI hệ thống.
  }

  @ReactMethod
  override fun addListener(eventName: String) {
    listenerCount += 1
  }

  @ReactMethod
  override fun removeListeners(count: Double) {
    listenerCount = (listenerCount - count.toInt()).coerceAtLeast(0)
  }

  // ------------------------------------------------------------ NFC reader

  override fun onTagDiscovered(tag: Tag?) {
    val current = session.get() ?: return
    val isoDep = IsoDep.get(tag)
    if (isoDep == null) {
      // Thẻ không hỗ trợ ISO-DEP (ISO 14443-4) → chắc chắn không phải eMRTD.
      rejectSession(ErrorCode.NOT_AN_EMRTD, "Thẻ không hỗ trợ ISO 14443-4")
      return
    }

    emitProgress("tag_connected", 0.05, "Đã nhận thẻ, đang kết nối chip…")

    executor.execute {
      try {
        isoDep.timeout = ISO_DEP_TIMEOUT_MS
        val reporter = ProgressReporter { step, progress, dataGroup, message ->
          emitProgress(step, progress, message, dataGroup)
        }
        val result = CccdReader(current.request, reporter).read(isoDep)
        resolveSession(result)
      } catch (t: Throwable) {
        val mapped = ErrorMapper.map(t, ErrorMapper.Stage.READ)
        rejectSession(
          mapped.code,
          mapped.message ?: "Lỗi không xác định khi đọc thẻ",
          mapped.statusWord
        )
      } finally {
        runCatching { isoDep.close() }
      }
    }
  }

  private fun enableReaderMode(activity: Activity, adapter: NfcAdapter) {
    val flags = NfcAdapter.FLAG_READER_NFC_A or
      NfcAdapter.FLAG_READER_NFC_B or
      NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
      NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
    val extras = Bundle().apply {
      putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY_MS)
    }
    mainHandler.post {
      runCatching { adapter.enableReaderMode(activity, this, flags, extras) }
    }
  }

  private fun disableReaderMode() {
    val adapter = adapter() ?: return
    val activity = reactContext.currentActivity ?: return
    mainHandler.post { runCatching { adapter.disableReaderMode(activity) } }
  }

  // ------------------------------------------------------------- lifecycle

  override fun onHostResume() {
    val current = session.get() ?: return
    val adapter = adapter() ?: return
    val activity = reactContext.currentActivity ?: return
    if (current.settled.get()) return
    enableReaderMode(activity, adapter)
  }

  override fun onHostPause() {
    // Reader mode chỉ hợp lệ khi Activity ở foreground.
    disableReaderMode()
  }

  override fun onHostDestroy() {
    rejectSession(ErrorCode.CANCELLED, "Activity bị huỷ")
  }

  // ----------------------------------------------------------------- utils

  private fun adapter(): NfcAdapter? =
    runCatching { NfcAdapter.getDefaultAdapter(reactContext.applicationContext as Context) }
      .getOrNull()

  private fun scheduleTimeout(timeoutMs: Long) {
    cancelTimeout()
    val runnable = Runnable { rejectSession(ErrorCode.TIMEOUT, "Hết thời gian chờ thẻ") }
    timeoutRunnable = runnable
    mainHandler.postDelayed(runnable, timeoutMs)
  }

  private fun cancelTimeout() {
    timeoutRunnable?.let { mainHandler.removeCallbacks(it) }
    timeoutRunnable = null
  }

  /**
   * Giành quyền đóng phiên. Chỉ một lời gọi thắng, các lời gọi sau nhận `null`.
   * Reader mode và timer được dọn ngay tại đây.
   */
  private fun claimSession(): Session? {
    val current = session.get() ?: return null
    if (!current.settled.compareAndSet(false, true)) return null
    session.compareAndSet(current, null)
    cancelTimeout()
    disableReaderMode()
    return current
  }

  private fun resolveSession(result: WritableMap): Boolean {
    val current = claimSession() ?: return false
    emitProgress("done", 1.0, "Hoàn tất")
    current.promise.resolve(result)
    return true
  }

  private fun rejectSession(code: ErrorCode, message: String, statusWord: String? = null): Boolean {
    val current = claimSession() ?: return false
    val userInfo = Arguments.createMap().apply {
      putString("nativeCode", code.name)
      statusWord?.let { putString("statusWord", it) }
    }
    current.promise.reject(code.name, message, userInfo)
    return true
  }

  private fun emitProgress(
    step: String,
    progress: Double,
    message: String? = null,
    dataGroup: String? = null,
  ) {
    if (!reactContext.hasActiveReactInstance()) return
    val params = Arguments.createMap().apply {
      putString("step", step)
      putDouble("progress", progress)
      message?.let { putString("message", it) }
      dataGroup?.let { putString("dataGroup", it) }
    }
    runCatching {
      reactContext
        .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
        .emit(PROGRESS_EVENT, params)
    }
  }
}
