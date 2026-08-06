package com.nfcpassport.reader

/** Callback tiến trình, được `NfcPassportModule` chuyển thành sự kiện JS. */
fun interface ProgressReporter {
  fun report(step: String, progress: Double, dataGroup: String?, message: String?)
}
