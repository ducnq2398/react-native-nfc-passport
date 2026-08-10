# react-native-nfc-passport

SDK React Native đọc chip NFC của **Căn cước công dân gắn chip Việt Nam (CCCD)** và hộ chiếu điện tử theo chuẩn **ICAO Doc 9303**.

SDK nhận MRZ đã có sẵn (từ OCR ở bước trước) rồi thực hiện toàn bộ quy trình: thiết lập kênh bảo mật, xác thực chip, đọc DataGroup, parse dữ liệu và trả về một object JavaScript.

> SDK **không** làm OCR. Bạn tự lấy `documentNumber`, `dateOfBirth`, `dateOfExpiry` (hoặc chuỗi MRZ thô) rồi truyền vào.

## Tính năng

| | Android | iOS |
|---|---|---|
| PACE (ECDH Generic Mapping) | ✅ qua JMRTD | ✅ cài đặt riêng trên OpenSSL |
| BAC (fallback) | ✅ | ✅ |
| Secure Messaging 3DES + AES | ✅ | ✅ |
| Chip Authentication | ✅ | ✅ (khoá ECDH) |
| Active Authentication | ✅ RSA + ECDSA | ✅ RSA |
| Passive Authentication (hash DG + chữ ký SOD + CSCA) | ✅ | ✅ |
| DG1 (MRZ), DG2 (ảnh), DG13 (thông tin tiếng Việt), DG14, DG15 | ✅ | ✅ |
| Giải mã JPEG 2000 của DG2 | ⚠️ cần decoder rời | ⚠️ ImageIO — xem [Ảnh DG2](#ảnh-dg2-jpeg-2000) |
| TurboModule / New Architecture | ✅ | ✅ |

**Yêu cầu:** React Native ≥ 0.75 · Android 8.0 (API 26)+ · iOS 15+ (iPhone 7 trở lên).

---

## Cài đặt

```sh
npm install react-native-nfc-passport
# hoặc
yarn add react-native-nfc-passport
```

```sh
cd ios && pod install
```

Autolinking lo phần còn lại. **Phải rebuild app** — Fast Refresh không nạp được native module mới.

Thư viện không chạy trên **Expo Go**; cần [development build](https://docs.expo.dev/develop/development-builds/introduction/).

### Android

`AndroidManifest.xml` của thư viện đã khai báo sẵn quyền `android.permission.NFC` và `uses-feature`, bạn không cần thêm gì.

Nếu app bật minify, ProGuard rules đã được đóng gói kèm (`consumer-rules.pro`).

### iOS

**1. Bật capability "Near Field Communication Tag Reading"** trong Xcode → target → *Signing & Capabilities*. Thao tác này thêm entitlement và cập nhật App ID trên Apple Developer.

Thao tác này chỉ thêm `com.apple.developer.nfc.readersession.formats` vào file `.entitlements`. Hai key còn lại nằm ở **`Info.plist`**, không phải entitlements.

**2. Thêm AID của eMRTD** vào `ios/<App>/Info.plist`:

```xml
<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
  <string>A0000002471001</string>
</array>
```

> Key này có tiền tố `com.apple.developer.` nên rất dễ nhầm là entitlement. Nó **không** phải. Đặt nhầm vào `.entitlements` sẽ làm việc ký thất bại với thông báo *"Entitlement … not found and could not be included in profile"*.

**3. Thêm mô tả quyền** vào `Info.plist`:

```xml
<key>NFCReaderUsageDescription</key>
<string>Ứng dụng cần quyền NFC để đọc chip trên thẻ Căn cước công dân của bạn.</string>
```

Thiếu bước 1 hoặc 3 thì `NFCTagReaderSession` bị từ chối ngay khi `begin()`. Thiếu bước 2 thì phiên **vẫn mở và sheet vẫn hiện**, nhưng CoreNFC không bao giờ trả thẻ về dưới dạng `.iso7816` — chạm thẻ sẽ không có phản ứng gì cho tới khi hệ thống tự timeout.

---

## Dùng nhanh

```ts
import NfcPassport, { NfcPassportError, userMessageFor } from 'react-native-nfc-passport';

const subscription = NfcPassport.addProgressListener((event) => {
  console.log(event.step, event.progress, event.message);
});

try {
  const data = await NfcPassport.scan({
    accessKey: {
      type: 'mrz',
      mrz: {
        documentNumber: '001199012345', // 12 chữ số trên thẻ
        dateOfBirth: '900115',          // YYMMDD
        dateOfExpiry: '400114',         // YYMMDD
      },
    },
  });

  console.log(data.personal?.fullName);
  console.log(data.personal?.placeOfResidence);
  console.log(data.security.passiveAuthentication.succeeded);
} catch (error) {
  if (error instanceof NfcPassportError) {
    console.warn(error.code, userMessageFor(error.code));
  }
} finally {
  subscription.remove();
}
```

Nếu OCR trả về nguyên ba dòng MRZ, truyền thẳng — SDK tự parse TD1/TD2/TD3 và xử lý cả trường hợp số giấy tờ 12 chữ số tràn sang optional data:

```ts
accessKey: { type: 'mrz', mrz: { rawMrz: line1 + '\n' + line2 + '\n' + line3 } }
```

---

## API

### `scan(options: ScanOptions): Promise<PassportData>`

| Tuỳ chọn | Mặc định | Ý nghĩa |
|---|---|---|
| `accessKey` | *(bắt buộc)* | `{ type: 'mrz', mrz }` hoặc `{ type: 'can', can }` |
| `dataGroups` | `['DG1','DG2','DG13','DG14','DG15']` | DataGroup cần đọc |
| `usePace` | `true` | Ưu tiên PACE |
| `allowBacFallback` | `true` | Cho phép lùi về BAC khi PACE không khả dụng |
| `chipAuthentication` | `true` | Chống clone chip |
| `activeAuthentication` | `true` | Chống clone chip (DG15) |
| `passiveAuthentication` | `true` | Kiểm tra hash DG + chữ ký SOD |
| `cscaCertificates` | `[]` | PEM/DER-base64 của CSCA để xác thực đầy đủ chuỗi tin cậy |
| `includeImages` | `true` | Trả ảnh DG2/DG7 dạng base64 |
| `includeRawData` | `false` | Trả bytes thô từng file trong `raw` |
| `rawEncoding` | `'base64'` | Mã hoá của `raw`: `'base64'` hoặc `'hex'` |
| `timeout` | `60000` | Timeout toàn phiên (ms) |
| `ios` | — | Văn bản hiển thị trên NFC sheet |

### Các hàm khác

```ts
NfcPassport.isSupported(): Promise<boolean>
NfcPassport.isEnabled(): Promise<boolean>          // Android: công tắc NFC
NfcPassport.getStatus(): Promise<NfcStatus>
NfcPassport.openNfcSettings(): Promise<boolean>    // Android
NfcPassport.addProgressListener(cb): EventSubscription
NfcPassport.setSessionMessage(text: string): void  // iOS NFC sheet
NfcPassport.cancel(): Promise<boolean>
```

Tiện ích MRZ được export sẵn: `parseMrz`, `buildMrzKey`, `buildMrzInformation`, `computeCheckDigit`, `verifyCheckDigit`.

### Kết quả

```ts
{
  mrz: { documentNumber, dateOfBirth, dateOfExpiry, primaryIdentifier, ... },
  personal: {                    // từ DG13
    idNumber, fullName, dateOfBirth, gender, nationality, ethnicity, religion,
    placeOfOrigin, placeOfResidence, personalIdentification,
    dateOfIssue, fatherName, motherName, spouseName,
    rawFields: string[],         // xem ghi chú DG13 bên dưới
  },
  faceImage: { base64, mimeType, width, height, transcoded },
  security: {
    accessProtocol: 'PACE' | 'BAC',
    secureMessagingCipher: 'AES' | 'DESede',
    chipAuthentication:   { succeeded, skipped, reason? },
    activeAuthentication: { succeeded, skipped, reason? },
    passiveAuthentication: {
      succeeded, dataGroupHashesValid, sodSignatureValid,
      documentSignerTrusted, mismatchedDataGroups,
    },
  },
  sod: { digestAlgorithm, dataGroupHashes, documentSigner },
  readAt, durationMs,
}
```

### Mã lỗi

`NfcPassportError.code` là một trong `NfcPassportErrorCode`, giống nhau trên cả hai nền tảng:

`NOT_SUPPORTED` · `NFC_DISABLED` · `CANCELLED` · `TIMEOUT` · `TAG_LOST` · `NOT_AN_EMRTD` · `INVALID_MRZ_KEY` · `PACE_FAILED` · `BAC_FAILED` · `COMMUNICATION_ERROR` · `PARSE_ERROR` · `AUTHENTICATION_FAILED` · `INVALID_ARGUMENT` · `SESSION_BUSY` · `UNKNOWN`

`userMessageFor(code)` trả về câu tiếng Việt sẵn dùng cho người dùng cuối.

---

## Bảo mật: đọc được ≠ tin được

Đọc thành công **không** có nghĩa dữ liệu đáng tin. Trước khi dùng dữ liệu cho eKYC, hãy kiểm tra:

```ts
const { passiveAuthentication: pa, chipAuthentication: ca } = data.security;

// 1. Dữ liệu khớp với chữ ký của cơ quan phát hành
if (!pa.dataGroupHashesValid || !pa.sodSignatureValid) reject();

// 2. Chữ ký đó thuộc về một CSCA tin cậy — chỉ có khi bạn truyền cscaCertificates
if (!pa.documentSignerTrusted) reject();

// 3. Chip là chip gốc, không phải bản sao
if (!ca.succeeded && !data.security.activeAuthentication.succeeded) reject();

// 4. Thẻ trên tay đúng là thẻ đã dùng để mở khoá
if (data.mrz?.documentNumber !== documentNumber) reject();
```

Nếu **không** truyền `cscaCertificates`, `documentSignerTrusted` luôn là `false` và Passive Authentication chỉ chứng minh dữ liệu nhất quán với SOD — kẻ tấn công tự tạo cặp SOD/DSC vẫn vượt qua được. Chứng thư CSCA của Việt Nam lấy từ [ICAO PKD](https://www.icao.int/Security/FAL/PKD) hoặc từ cơ quan phát hành.

---

## Ghi chú về DG13

ICAO 9303 để DG13 ("Optional details") cho quốc gia phát hành tự định nghĩa và **không có đặc tả công khai cho Việt Nam**. Parser hoạt động hai bước:

1. Duyệt cây TLV, gom mọi leaf decode được thành UTF-8 in được, giữ nguyên thứ tự → `personal.rawFields`. Bước này luôn đáng tin.
2. Gán tên trường bằng con trỏ tuần tự với các mốc neo nhận diện chắc chắn (chuỗi 12 chữ số, ngày tháng, `Nam`/`Nữ`, `Việt Nam`).

Nếu một đợt phát hành thay đổi bố cục, bước 2 có thể lệch nhưng bước 1 thì không. **Hãy đối chiếu với thẻ thật của bạn và dùng `rawFields` khi cần chắc chắn tuyệt đối.** Cả Android và iOS dùng chung thuật toán nên kết quả giống nhau.

---

## Giới hạn đã biết

- **DG3 (vân tay) và DG4 (mống mắt)** yêu cầu Extended Access Control với chứng thư CVCA do cơ quan phát hành cấp — không hỗ trợ và sẽ không hỗ trợ.
- **PACE trên bộ tham số MODP-DH** (`parameterId` 0/1/2) chưa cài đặt trên iOS; SDK tự lùi về BAC. Thẻ CCCD dùng đường cong elliptic nên nhánh này không xảy ra trong thực tế.
- **Active Authentication với khoá EC trên iOS** báo `skipped`; Android hỗ trợ đầy đủ.
- **JPEG 2000**: xem mục [Ảnh DG2](#ảnh-dg2-jpeg-2000) bên dưới.
- **Chip Authentication trên khoá DH** (không phải EC) chưa cài đặt trên iOS.

---

## Ảnh DG2 (JPEG 2000)

DG2 theo ISO/IEC 19794-5 thường lưu ảnh chân dung ở **JPEG 2000** — định dạng mà cả Android lẫn iOS đều không decode được một cách đảm bảo. SDK luôn *thử* transcode sang JPEG và cho bạn biết kết quả qua `faceImage.transcoded`:

```ts
if (data.faceImage?.transcoded) {
  // mimeType = 'image/jpeg', hiển thị trực tiếp được
  <Image source={{ uri: `data:image/jpeg;base64,${data.faceImage.base64}` }} />
} else {
  // base64 là bytes gốc (thường image/jp2) — cần decoder phía JS
}
```

**Android** không kèm decoder JPEG 2000 nào. Lựa chọn duy nhất trước đây, `com.gemalto.jp2:jp2-android`, chỉ tồn tại trên JCenter — repository đã đóng và artifact không được mirror sang Maven Central, Google Maven hay JitPack. Khai báo nó sẽ làm hỏng build. Nếu bạn cần transcode phía native, tự cung cấp AAR rồi thả vào app:

```gradle
// android/app/build.gradle
dependencies {
    implementation files('libs/jp2-android-1.0.3.aar')
}
```

SDK nạp `com.gemalto.jp2.JP2Decoder` bằng reflection nên chỉ cần lớp đó có mặt trong classpath là tự động hoạt động, không cần cấu hình thêm. Fork nào phơi ra cùng tên lớp cũng dùng được.

**iOS** dùng ImageIO, decode được JPEG 2000 trên phần lớn phiên bản nhưng không phải tất cả.

**Cách đơn giản nhất cho cả hai nền tảng** là decode phía JS khi `transcoded === false` — nhiều thư viện JPEG 2000 thuần JS/WASM làm được việc này, và bạn chỉ phải xử lý một đường dẫn code duy nhất.

Một số đợt phát hành CCCD dùng thẳng JPEG cho DG2; những thẻ đó luôn cho `transcoded: true` trên cả hai nền tảng mà không cần gì thêm.

---

## Kiến trúc

```
src/                          TypeScript: API công khai, chuẩn hoá MRZ, TurboModule spec
android/src/main/java/com/nfcpassport/
  NfcPassportModule.kt        reader-mode, vòng đời phiên, sự kiện tiến trình
  reader/CccdReader.kt        điều phối PACE → SELECT → CA → đọc DG → AA → PA
  reader/PassiveAuthenticator.kt
  reader/ActiveAuthVerifier.kt   ISO 9796-2 DS1
  parser/Dg13Parser.kt        DG13 Việt Nam
ios/
  NfcPassport.{h,mm}          bridge Obj-C++ (RCTEventEmitter + TurboModule)
  Sources/NfcPassportImpl.swift  NFCTagReaderSession, vòng đời phiên
  Sources/PassportReader.swift   điều phối, cùng thứ tự với Android
  Sources/{BAC,PACE,ChipAuthentication,ActiveAuthentication}.swift
  Sources/{Crypto,SecureMessaging,TagSession,ASN1,ECMath}.swift
  Sources/{DataGroups,DG13VN,SOD}.swift
```

Android dựa trên [JMRTD](https://jmrtd.org/) 0.7.42 + SCUBA + BouncyCastle (ghim phiên bản trong `android/build.gradle`; JMRTD chưa cam kết API ổn định giữa các minor).

iOS không có thư viện tương đương nên toàn bộ stack giao thức được cài đặt trong repo này: CommonCrypto cho phần đối xứng, Security.framework cho RSA/chữ ký, OpenSSL **chỉ** cho số học đường cong elliptic (Security.framework không hỗ trợ họ Brainpool).

---

## Mẹo đọc thành công

- Vị trí ăng-ten NFC khác nhau theo máy: iPhone ở mép trên mặt sau, đa số Android ở giữa mặt sau. Hướng dẫn người dùng rà chậm.
- Bỏ ốp lưng dày hoặc ốp có ví đựng thẻ kim loại.
- Giữ thẻ **cố định** cho tới khi xong: DG2 mất vài giây và mọi rung lắc đều gây `TAG_LOST`.
- `INVALID_MRZ_KEY` gần như luôn là do OCR đọc sai một chữ số. Cho người dùng sửa tay ba trường trước khi thử lại.

## License

MIT
