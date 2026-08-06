/**
 * MRZ utilities — ICAO Doc 9303 Part 3 §4.9 (check digits) và Part 5/6/7 (layout).
 *
 * SDK không làm OCR. Module này chỉ chuẩn hoá kết quả OCR thành ba trường
 * (documentNumber, dateOfBirth, dateOfExpiry) dùng để dẫn xuất khoá BAC/PACE.
 */

import type { MrzKeyInput } from './types';
import { NfcPassportError } from './errors';
import { NfcPassportErrorCode } from './types';

const CHECK_DIGIT_WEIGHTS = [7, 3, 1];

/** Giá trị số của một ký tự MRZ theo ICAO 9303: '<' = 0, '0'-'9' = 0-9, 'A'-'Z' = 10-35. */
function charValue(c: string): number {
  if (c === '<') return 0;
  const code = c.charCodeAt(0);
  if (code >= 48 && code <= 57) return code - 48; // '0'..'9'
  if (code >= 65 && code <= 90) return code - 55; // 'A'..'Z' -> 10..35
  if (code >= 97 && code <= 122) return code - 87; // 'a'..'z' -> 10..35
  throw new NfcPassportError(
    NfcPassportErrorCode.INVALID_ARGUMENT,
    `Ký tự "${c}" không hợp lệ trong MRZ`
  );
}

/** Tính check digit ICAO 9303 (trọng số lặp 7-3-1, modulo 10). */
export function computeCheckDigit(input: string): string {
  let sum = 0;
  for (let i = 0; i < input.length; i++) {
    sum += charValue(input[i]!) * CHECK_DIGIT_WEIGHTS[i % 3]!;
  }
  return String(sum % 10);
}

/** Kiểm tra một trường MRZ khớp với check digit đi kèm. */
export function verifyCheckDigit(field: string, checkDigit: string): boolean {
  if (checkDigit === '<' || checkDigit === '') return true; // filler = không có check digit
  return computeCheckDigit(field) === checkDigit;
}

export interface ParsedMrz {
  format: 'TD1' | 'TD2' | 'TD3';
  documentCode: string;
  issuingState: string;
  documentNumber: string;
  dateOfBirth: string;
  dateOfExpiry: string;
  nationality: string;
  gender: string;
  primaryIdentifier: string;
  secondaryIdentifier: string;
  optionalData1: string;
  optionalData2: string;
  /** Các check digit không khớp; rỗng nghĩa là MRZ nhất quán. */
  checkDigitErrors: string[];
}

function normalizeLines(rawMrz: string): string[] {
  return rawMrz
    .toUpperCase()
    .replace(/[^A-Z0-9<\n\r]/g, '') // bỏ khoảng trắng và ký tự lạ do OCR
    .split(/[\n\r]+/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

function splitNames(field: string): {
  primary: string;
  secondary: string;
} {
  const [primaryRaw = '', secondaryRaw = ''] = field.split('<<');
  const clean = (s: string) => s.replace(/</g, ' ').trim().replace(/\s+/g, ' ');
  return { primary: clean(primaryRaw), secondary: clean(secondaryRaw) };
}

/**
 * Ghép số giấy tờ dài hơn 9 ký tự trong MRZ TD1.
 *
 * ICAO 9303 Part 5 §4.2.4: khi số giấy tờ dài hơn 9 ký tự, 9 ký tự đầu nằm ở
 * vị trí 6–14, vị trí 15 (check digit) là filler `<`, phần còn lại cộng check
 * digit thật được đặt ở đầu optional data và kết thúc bằng `<`.
 *
 * CCCD Việt Nam có 12 chữ số nên luôn rơi vào trường hợp này.
 */
function resolveExtendedDocumentNumber(
  first9: string,
  checkDigitField: string,
  optionalData: string
): { documentNumber: string; checkDigit: string; remainingOptional: string } {
  if (checkDigitField !== '<') {
    return {
      documentNumber: first9.replace(/<+$/, ''),
      checkDigit: checkDigitField,
      remainingOptional: optionalData,
    };
  }
  const terminator = optionalData.indexOf('<');
  const extension =
    terminator === -1 ? optionalData : optionalData.slice(0, terminator);
  if (extension.length === 0) {
    return {
      documentNumber: first9.replace(/<+$/, ''),
      checkDigit: '<',
      remainingOptional: optionalData,
    };
  }
  return {
    documentNumber: first9 + extension.slice(0, -1),
    checkDigit: extension.slice(-1),
    remainingOptional:
      terminator === -1 ? '' : optionalData.slice(terminator + 1),
  };
}

/** Parse MRZ thô (TD1 3×30, TD2 2×36, TD3 2×44) thành các trường rời rạc. */
export function parseMrz(rawMrz: string): ParsedMrz {
  const lines = normalizeLines(rawMrz);
  const errors: string[] = [];

  if (lines.length === 3) {
    const [l1 = '', l2 = '', l3 = ''] = lines;
    if (l1.length < 30 || l2.length < 30) {
      throw new NfcPassportError(
        NfcPassportErrorCode.INVALID_ARGUMENT,
        `MRZ TD1 phải có 3 dòng × 30 ký tự (nhận được ${l1.length}/${l2.length}/${l3.length})`
      );
    }
    const { documentNumber, checkDigit, remainingOptional } =
      resolveExtendedDocumentNumber(l1.slice(5, 14), l1.charAt(14), l1.slice(15, 30));

    const dateOfBirth = l2.slice(0, 6);
    const dateOfExpiry = l2.slice(8, 14);
    if (!verifyCheckDigit(documentNumber, checkDigit)) errors.push('documentNumber');
    if (!verifyCheckDigit(dateOfBirth, l2.charAt(6))) errors.push('dateOfBirth');
    if (!verifyCheckDigit(dateOfExpiry, l2.charAt(14))) errors.push('dateOfExpiry');

    const names = splitNames(l3.slice(0, 30));
    return {
      format: 'TD1',
      documentCode: l1.slice(0, 2).replace(/</g, ''),
      issuingState: l1.slice(2, 5).replace(/</g, ''),
      documentNumber,
      dateOfBirth,
      dateOfExpiry,
      nationality: l2.slice(15, 18).replace(/</g, ''),
      gender: l2.charAt(7),
      primaryIdentifier: names.primary,
      secondaryIdentifier: names.secondary,
      optionalData1: remainingOptional.replace(/</g, ''),
      optionalData2: l2.slice(18, 29).replace(/</g, ''),
      checkDigitErrors: errors,
    };
  }

  if (lines.length === 2) {
    const [l1 = '', l2 = ''] = lines;
    const isTd3 = l1.length >= 44 || l2.length >= 44;
    const expected = isTd3 ? 44 : 36;
    if (l1.length < expected || l2.length < expected) {
      throw new NfcPassportError(
        NfcPassportErrorCode.INVALID_ARGUMENT,
        `MRZ ${isTd3 ? 'TD3' : 'TD2'} phải có 2 dòng × ${expected} ký tự (nhận được ${l1.length}/${l2.length})`
      );
    }
    const documentNumber = l2.slice(0, 9).replace(/<+$/, '');
    const dateOfBirth = l2.slice(13, 19);
    const dateOfExpiry = l2.slice(21, 27);
    if (!verifyCheckDigit(l2.slice(0, 9), l2.charAt(9))) errors.push('documentNumber');
    if (!verifyCheckDigit(dateOfBirth, l2.charAt(19))) errors.push('dateOfBirth');
    if (!verifyCheckDigit(dateOfExpiry, l2.charAt(27))) errors.push('dateOfExpiry');

    const names = splitNames(l1.slice(5, expected));
    return {
      format: isTd3 ? 'TD3' : 'TD2',
      documentCode: l1.slice(0, 2).replace(/</g, ''),
      issuingState: l1.slice(2, 5).replace(/</g, ''),
      documentNumber,
      dateOfBirth,
      dateOfExpiry,
      nationality: l2.slice(10, 13).replace(/</g, ''),
      gender: l2.charAt(20),
      primaryIdentifier: names.primary,
      secondaryIdentifier: names.secondary,
      optionalData1: l2.slice(28, isTd3 ? 42 : 35).replace(/</g, ''),
      optionalData2: '',
      checkDigitErrors: errors,
    };
  }

  throw new NfcPassportError(
    NfcPassportErrorCode.INVALID_ARGUMENT,
    `Không nhận diện được định dạng MRZ: cần 2 hoặc 3 dòng, nhận được ${lines.length}`
  );
}

/** Ba trường được truyền xuống native để dẫn xuất khoá. */
export interface MrzKeyFields {
  documentNumber: string;
  dateOfBirth: string;
  dateOfExpiry: string;
}

const DATE_RE = /^\d{6}$/;

/**
 * Chuẩn hoá đầu vào MRZ (rời rạc hoặc thô) thành ba trường khoá.
 *
 * `MRZ_information = documentNumber || cd || dateOfBirth || cd || dateOfExpiry || cd`
 * được native tính lại (ICAO 9303 Part 11 §9.7.2 cho BAC, §4.4.1 cho PACE),
 * nên ở đây chỉ cần trả về giá trị các trường.
 */
export function buildMrzKey(input: MrzKeyInput): MrzKeyFields {
  let fields: MrzKeyFields;

  if (input.rawMrz != null) {
    const parsed = parseMrz(input.rawMrz);
    fields = {
      documentNumber: parsed.documentNumber,
      dateOfBirth: parsed.dateOfBirth,
      dateOfExpiry: parsed.dateOfExpiry,
    };
  } else {
    fields = {
      documentNumber: String(input.documentNumber ?? '')
        .toUpperCase()
        .replace(/[^A-Z0-9<]/g, ''),
      dateOfBirth: String(input.dateOfBirth ?? '').replace(/\D/g, ''),
      dateOfExpiry: String(input.dateOfExpiry ?? '').replace(/\D/g, ''),
    };
  }

  if (fields.documentNumber.length === 0) {
    throw new NfcPassportError(
      NfcPassportErrorCode.INVALID_ARGUMENT,
      'documentNumber rỗng — với CCCD đây là 12 chữ số in trên thẻ'
    );
  }
  if (!DATE_RE.test(fields.dateOfBirth)) {
    throw new NfcPassportError(
      NfcPassportErrorCode.INVALID_ARGUMENT,
      `dateOfBirth phải theo định dạng YYMMDD, nhận được "${fields.dateOfBirth}"`
    );
  }
  if (!DATE_RE.test(fields.dateOfExpiry)) {
    throw new NfcPassportError(
      NfcPassportErrorCode.INVALID_ARGUMENT,
      `dateOfExpiry phải theo định dạng YYMMDD, nhận được "${fields.dateOfExpiry}"`
    );
  }
  return fields;
}

/**
 * Chuỗi MRZ_information dùng để dẫn xuất khoá — hữu ích khi debug hoặc khi cần
 * đối chiếu với thẻ thật. Native tính lại chính chuỗi này.
 */
export function buildMrzInformation(fields: MrzKeyFields): string {
  const { documentNumber, dateOfBirth, dateOfExpiry } = fields;
  // JMRTD và ICAO đều pad số giấy tờ ngắn hơn 9 ký tự bằng '<' trước khi tính
  // check digit; số dài hơn 9 (CCCD 12 số) được dùng nguyên vẹn.
  const paddedDocNumber =
    documentNumber.length < 9 ? documentNumber.padEnd(9, '<') : documentNumber;
  return (
    paddedDocNumber +
    computeCheckDigit(paddedDocNumber) +
    dateOfBirth +
    computeCheckDigit(dateOfBirth) +
    dateOfExpiry +
    computeCheckDigit(dateOfExpiry)
  );
}
