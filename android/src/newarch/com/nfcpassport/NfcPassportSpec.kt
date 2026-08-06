package com.nfcpassport

import com.facebook.react.bridge.ReactApplicationContext

/**
 * New Architecture: kế thừa lớp abstract do codegen sinh ra từ
 * `src/NativeNfcPassport.ts`.
 */
abstract class NfcPassportSpec(context: ReactApplicationContext) :
  NativeNfcPassportSpec(context)
