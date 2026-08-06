#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

#ifdef RCT_NEW_ARCH_ENABLED
#import <RNNfcPassportSpec/RNNfcPassportSpec.h>

@interface NfcPassport : RCTEventEmitter <NativeNfcPassportSpec>
#else

@interface NfcPassport : RCTEventEmitter <RCTBridgeModule>
#endif

@end
