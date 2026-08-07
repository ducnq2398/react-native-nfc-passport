#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

#ifdef RCT_NEW_ARCH_ENABLED
// Từ RN 0.74, codegen của thư viện bên thứ ba được gộp vào pod `ReactCodegen`.
// Với `use_frameworks!` thì không tồn tại framework tên RNNfcPassportSpec, nên
// phải dò cả hai dạng đường dẫn.
#if __has_include(<RNNfcPassportSpec/RNNfcPassportSpec.h>)
#import <RNNfcPassportSpec/RNNfcPassportSpec.h>
#else
#import <ReactCodegen/RNNfcPassportSpec.h>
#endif

@interface NfcPassport : RCTEventEmitter <NativeNfcPassportSpec>
#else

@interface NfcPassport : RCTEventEmitter <RCTBridgeModule>
#endif

@end
