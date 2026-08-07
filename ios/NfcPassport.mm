#import "NfcPassport.h"

// Header cầu nối do Swift sinh ra. Vị trí phụ thuộc cách CocoaPods dựng pod:
//  - `use_frameworks!` (framework tĩnh hoặc động): header nằm trong
//    react_native_nfc_passport.framework/Headers → phải dùng dạng <module/header>.
//  - Mặc định của React Native (static library): chỉ dạng "header" giải được.
// Không có dạng nào đúng cho cả hai, nên phải dò bằng __has_include.
#if __has_include(<react_native_nfc_passport/react_native_nfc_passport-Swift.h>)
#import <react_native_nfc_passport/react_native_nfc_passport-Swift.h>
#else
#import "react_native_nfc_passport-Swift.h"
#endif

static NSString *const kProgressEvent = @"NfcPassport:progress";

@implementation NfcPassport {
  BOOL _hasListeners;
}

RCT_EXPORT_MODULE(NfcPassport)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (instancetype)init
{
  if (self = [super init]) {
    __weak __typeof(self) weakSelf = self;
    NfcPassportImpl.shared.onProgress = ^(NSDictionary *payload) {
      __strong __typeof(weakSelf) strongSelf = weakSelf;
      if (strongSelf != nil && strongSelf->_hasListeners) {
        [strongSelf sendEventWithName:kProgressEvent body:payload];
      }
    };
  }
  return self;
}

- (void)invalidate
{
  NfcPassportImpl.shared.onProgress = nil;
  [NfcPassportImpl.shared cancel];
  [super invalidate];
}

#pragma mark - RCTEventEmitter

- (NSArray<NSString *> *)supportedEvents
{
  return @[ kProgressEvent ];
}

- (void)startObserving
{
  _hasListeners = YES;
}

- (void)stopObserving
{
  _hasListeners = NO;
}

#pragma mark - JS API

RCT_EXPORT_METHOD(isSupported : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)
{
  resolve(@([NfcPassportImpl.shared isSupported]));
}

RCT_EXPORT_METHOD(isEnabled : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)
{
  // iOS không có công tắc NFC riêng: hỗ trợ đồng nghĩa với sẵn sàng.
  resolve(@([NfcPassportImpl.shared isSupported]));
}

RCT_EXPORT_METHOD(openNfcSettings : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)
{
  resolve(@(NO));
}

RCT_EXPORT_METHOD(startScan
                  : (NSDictionary *)options resolve
                  : (RCTPromiseResolveBlock)resolve reject
                  : (RCTPromiseRejectBlock)reject)
{
  [NfcPassportImpl.shared startScan:options
      resolve:^(id _Nullable result) {
        resolve(result);
      }
      reject:^(NSString *code, NSString *message, NSDictionary *_Nullable userInfo) {
        NSError *error = [NSError errorWithDomain:@"NfcPassport"
                                             code:0
                                         userInfo:userInfo ?: @{}];
        reject(code, message, error);
      }];
}

RCT_EXPORT_METHOD(cancel : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)
{
  resolve(@([NfcPassportImpl.shared cancel]));
}

RCT_EXPORT_METHOD(setSessionMessage : (NSString *)message)
{
  [NfcPassportImpl.shared setSessionMessage:message];
}

#ifdef RCT_NEW_ARCH_ENABLED
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
  return std::make_shared<facebook::react::NativeNfcPassportSpecJSI>(params);
}
#endif

@end
