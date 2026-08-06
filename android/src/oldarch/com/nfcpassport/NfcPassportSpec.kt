package com.nfcpassport

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReadableMap

/**
 * Old Architecture: khai báo tay đúng chữ ký mà codegen sinh ra ở New Arch,
 * để `NfcPassportModule` dùng chung một implementation cho cả hai kiến trúc.
 */
abstract class NfcPassportSpec(context: ReactApplicationContext) :
  ReactContextBaseJavaModule(context) {

  abstract fun isSupported(promise: Promise)

  abstract fun isEnabled(promise: Promise)

  abstract fun openNfcSettings(promise: Promise)

  abstract fun startScan(options: ReadableMap, promise: Promise)

  abstract fun cancel(promise: Promise)

  abstract fun setSessionMessage(message: String)

  abstract fun addListener(eventName: String)

  abstract fun removeListeners(count: Double)
}
