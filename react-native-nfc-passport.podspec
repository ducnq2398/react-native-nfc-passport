require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-nfc-passport"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = "https://github.com/your-org/react-native-nfc-passport"
  s.license      = package["license"]
  s.authors      = { "Your Org" => "dev@example.com" }

  s.platforms    = { :ios => "15.0" }
  s.source       = { :git => "https://github.com/your-org/react-native-nfc-passport.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift}"
  s.private_header_files = "ios/**/*.h"

  s.frameworks   = "CoreNFC", "Security", "ImageIO", "CoreGraphics", "UIKit"
  s.swift_version = "5.7"

  # OpenSSL is required for:
  #   - PACE / Chip Authentication over Brainpool + MODP-DH domain parameters
  #     (CryptoKit / Security.framework only expose NIST curves)
  #   - CMS (SignedData) verification of EF.SOD during Passive Authentication
  s.dependency "OpenSSL-Universal", "~> 1.1.1900"

  s.pod_target_xcconfig = {
    "DEFINES_MODULE" => "YES",
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
    "SWIFT_OBJC_INTERFACE_HEADER_NAME" => "react_native_nfc_passport-Swift.h"
  }

  # Standard React Native dependency installer: wires up React-Core on the old
  # architecture and the full codegen/TurboModule stack when RCT_NEW_ARCH_ENABLED=1.
  if respond_to?(:install_modules_dependencies, true)
    install_modules_dependencies(s)
  else
    s.dependency "React-Core"
  end
end
