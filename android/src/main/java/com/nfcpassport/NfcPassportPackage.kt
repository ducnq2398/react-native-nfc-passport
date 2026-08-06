package com.nfcpassport

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

class NfcPassportPackage : BaseReactPackage() {

  override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? =
    if (name == NfcPassportModule.NAME) NfcPassportModule(reactContext) else null

  override fun getReactModuleInfoProvider(): ReactModuleInfoProvider = ReactModuleInfoProvider {
    mapOf(
      NfcPassportModule.NAME to ReactModuleInfo(
        NfcPassportModule.NAME,
        NfcPassportModule.NAME,
        /* canOverrideExistingModule = */ false,
        /* needsEagerInit = */ false,
        /* isCxxModule = */ false,
        /* isTurboModule = */ BuildConfig.IS_NEW_ARCHITECTURE_ENABLED
      )
    )
  }
}
