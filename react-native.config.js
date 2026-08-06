/**
 * Autolinking configuration for react-native-nfc-passport.
 */
module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: 'android',
        packageImportPath: 'import com.nfcpassport.NfcPassportPackage;',
        packageInstance: 'new NfcPassportPackage()',
      },
      ios: {
        podspecPath: `${__dirname}/react-native-nfc-passport.podspec`,
      },
    },
  },
};
