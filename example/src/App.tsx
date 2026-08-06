/**
 * Ví dụ tích hợp react-native-nfc-passport.
 *
 * MRZ trong ví dụ được nhập tay; trong ứng dụng thật, ba trường này đến từ bước
 * OCR mặt sau thẻ (SDK không làm OCR).
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Image,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import NfcPassport, {
  NfcPassportError,
  userMessageFor,
  type PassportData,
  type ScanProgressEvent,
} from 'react-native-nfc-passport';

export default function App() {
  const [documentNumber, setDocumentNumber] = useState('');
  const [dateOfBirth, setDateOfBirth] = useState('');
  const [dateOfExpiry, setDateOfExpiry] = useState('');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgressEvent | null>(null);
  const [data, setData] = useState<PassportData | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);

  const scanningRef = useRef(false);

  useEffect(() => {
    NfcPassport.getStatus().then(({ supported: s, enabled }) => {
      setSupported(s && enabled);
    });
  }, []);

  useEffect(() => {
    const subscription = NfcPassport.addProgressListener(setProgress);
    return () => subscription.remove();
  }, []);

  const handleScan = useCallback(async () => {
    if (scanningRef.current) return;

    const enabled = await NfcPassport.isEnabled();
    if (!enabled) {
      Alert.alert('NFC đang tắt', 'Bật NFC trong Cài đặt để đọc thẻ.', [
        { text: 'Để sau', style: 'cancel' },
        { text: 'Mở Cài đặt', onPress: () => NfcPassport.openNfcSettings() },
      ]);
      return;
    }

    scanningRef.current = true;
    setScanning(true);
    setData(null);
    setProgress(null);

    try {
      const result = await NfcPassport.scan({
        accessKey: {
          type: 'mrz',
          mrz: { documentNumber, dateOfBirth, dateOfExpiry },
        },
        dataGroups: ['DG1', 'DG2', 'DG13', 'DG14', 'DG15'],
        chipAuthentication: true,
        activeAuthentication: true,
        passiveAuthentication: true,
      });
      setData(result);
    } catch (error) {
      const message =
        error instanceof NfcPassportError
          ? `${userMessageFor(error.code)}\n\n(${error.code}: ${error.message})`
          : String(error);
      Alert.alert('Không đọc được thẻ', message);
    } finally {
      scanningRef.current = false;
      setScanning(false);
    }
  }, [documentNumber, dateOfBirth, dateOfExpiry]);

  const security = data?.security;

  return (
    <ScrollView style={styles.screen} contentContainerStyle={styles.content}>
      <Text style={styles.title}>Đọc CCCD gắn chip</Text>
      {supported === false && (
        <Text style={styles.warning}>Thiết bị không hỗ trợ NFC hoặc NFC đang tắt.</Text>
      )}

      <Text style={styles.label}>Số CCCD (12 chữ số)</Text>
      <TextInput
        style={styles.input}
        value={documentNumber}
        onChangeText={setDocumentNumber}
        keyboardType="number-pad"
        placeholder="001199012345"
        maxLength={12}
      />

      <Text style={styles.label}>Ngày sinh (YYMMDD)</Text>
      <TextInput
        style={styles.input}
        value={dateOfBirth}
        onChangeText={setDateOfBirth}
        keyboardType="number-pad"
        placeholder="900115"
        maxLength={6}
      />

      <Text style={styles.label}>Ngày hết hạn (YYMMDD)</Text>
      <TextInput
        style={styles.input}
        value={dateOfExpiry}
        onChangeText={setDateOfExpiry}
        keyboardType="number-pad"
        placeholder="400114"
        maxLength={6}
      />

      <TouchableOpacity
        style={[styles.button, scanning && styles.buttonDisabled]}
        onPress={handleScan}
        disabled={scanning}
      >
        <Text style={styles.buttonText}>{scanning ? 'Đang đọc…' : 'Quét NFC'}</Text>
      </TouchableOpacity>

      {scanning && (
        <View style={styles.progressBox}>
          <ActivityIndicator />
          <Text style={styles.progressText}>
            {progress?.message ?? 'Đưa thẻ lại gần điện thoại'}
          </Text>
          <Text style={styles.progressPercent}>
            {Math.round((progress?.progress ?? 0) * 100)}%
          </Text>
          {Platform.OS === 'android' && (
            <TouchableOpacity onPress={() => NfcPassport.cancel()}>
              <Text style={styles.cancel}>Huỷ</Text>
            </TouchableOpacity>
          )}
        </View>
      )}

      {data && (
        <View style={styles.result}>
          {data.faceImage && (
            <Image
              style={styles.avatar}
              source={{ uri: `data:${data.faceImage.mimeType};base64,${data.faceImage.base64}` }}
            />
          )}

          <Field label="Họ và tên" value={data.personal?.fullName} />
          <Field label="Số CCCD" value={data.personal?.idNumber ?? data.mrz?.documentNumber} />
          <Field label="Ngày sinh" value={data.personal?.dateOfBirth} />
          <Field label="Giới tính" value={data.personal?.gender} />
          <Field label="Quốc tịch" value={data.personal?.nationality} />
          <Field label="Dân tộc" value={data.personal?.ethnicity} />
          <Field label="Tôn giáo" value={data.personal?.religion} />
          <Field label="Quê quán" value={data.personal?.placeOfOrigin} />
          <Field label="Nơi thường trú" value={data.personal?.placeOfResidence} />
          <Field label="Đặc điểm nhận dạng" value={data.personal?.personalIdentification} />
          <Field label="Ngày cấp" value={data.personal?.dateOfIssue} />
          <Field label="Họ tên cha" value={data.personal?.fatherName} />
          <Field label="Họ tên mẹ" value={data.personal?.motherName} />

          <Text style={styles.sectionTitle}>Bảo mật</Text>
          <Field label="Kênh bảo mật" value={security?.accessProtocol} />
          <Field
            label="Chip Authentication"
            value={stepLabel(security?.chipAuthentication)}
          />
          <Field
            label="Active Authentication"
            value={stepLabel(security?.activeAuthentication)}
          />
          <Field
            label="Passive Authentication"
            value={stepLabel(security?.passiveAuthentication)}
          />
          <Field label="Thời gian đọc" value={`${Math.round(data.durationMs)} ms`} />
        </View>
      )}
    </ScrollView>
  );
}

function stepLabel(step?: { succeeded: boolean; skipped: boolean; reason?: string }) {
  if (!step) return undefined;
  if (step.skipped) return `Bỏ qua (${step.reason ?? 'không hỗ trợ'})`;
  return step.succeeded ? 'Hợp lệ' : `Thất bại (${step.reason ?? ''})`;
}

function Field({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <View style={styles.field}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <Text style={styles.fieldValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#fff' },
  content: { padding: 20, paddingBottom: 60 },
  title: { fontSize: 24, fontWeight: '700', marginBottom: 20 },
  warning: { color: '#b00020', marginBottom: 12 },
  label: { fontSize: 13, color: '#555', marginTop: 12, marginBottom: 4 },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
  },
  button: {
    marginTop: 24,
    backgroundColor: '#0b6bcb',
    borderRadius: 8,
    paddingVertical: 14,
    alignItems: 'center',
  },
  buttonDisabled: { opacity: 0.6 },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  progressBox: { marginTop: 20, alignItems: 'center', gap: 8 },
  progressText: { color: '#333' },
  progressPercent: { color: '#888', fontVariant: ['tabular-nums'] },
  cancel: { color: '#b00020', marginTop: 8 },
  result: { marginTop: 28 },
  avatar: { width: 120, height: 160, borderRadius: 8, marginBottom: 16, alignSelf: 'center' },
  sectionTitle: { fontSize: 16, fontWeight: '700', marginTop: 20, marginBottom: 8 },
  field: { flexDirection: 'row', paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: '#f0f0f0' },
  fieldLabel: { flex: 1, color: '#666', fontSize: 13 },
  fieldValue: { flex: 1.6, color: '#111', fontSize: 14 },
});
