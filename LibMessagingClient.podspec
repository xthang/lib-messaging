#
# Copyright 2023 Ready
#

Pod::Spec.new do |s|
  s.name             = 'LibMessagingClient'
  s.version          = '0.1.0'
  s.summary          = 'A Swift wrapper library for communicating with the Ready messaging service.'

  s.homepage         = 'https://github.com/xthang/lib-messaging-client'
  s.license          = 'AGPL-3.0-only'
  s.author           = 'Ready.io'
  s.source           = { :git => 'https://github.com/xthang/lib-messaging-client', :tag => "v#{s.version}" }

  s.swift_version    = '5'
  s.platform         = :ios, '12.4'

#  s.dependency 'SignalCoreKit'

  s.source_files = ['swift/Sources/**/*.swift', 'swift/Sources/**/*.m']
  s.preserve_paths = [
    'swift/Sources/MessagingFfi',
    'bin/fetch_archive.py',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/MessagingFfi',
      # Duplicate this here to make sure the search path is passed on to Swift dependencies.
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      'LIB_MESSAGING_FFI_BUILD_PATH' => 'target/$(CARGO_BUILD_TARGET)/release',
      # Store libmessaging_ffi.a builds in a project-wide directory
      # because we keep simulator and device builds next to each other.
      'LIB_MESSAGING_FFI_TEMP_DIR' => '$(PROJECT_TEMP_DIR)/lib_messaging_ffi',
      'LIB_MESSAGING_FFI_LIB_TO_LINK' => '$(LIB_MESSAGING_FFI_TEMP_DIR)/$(LIB_MESSAGING_FFI_BUILD_PATH)/libmessaging_ffi.a',

      # Make sure we link the static library, not a dynamic one.
      'OTHER_LDFLAGS' => '$(LIB_MESSAGING_FFI_LIB_TO_LINK)',

      'LIB_MESSAGING_FFI_PREBUILD_ARCHIVE' => "lib-messaging-client-ios-build-v#{s.version}.tar.gz",
      'LIB_MESSAGING_FFI_PREBUILD_CHECKSUM' => ENV.fetch('LIB_MESSAGING_FFI_PREBUILD_CHECKSUM', ''),

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',
      # Presently, there's no special SDK or arch for maccatalyst,
      # so we need to hackily use the "IS_MACCATALYST" build flag
      # to set the appropriate cargo target
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_' => 'aarch64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_ARM_YES' => 'aarch64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=arm64]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_ARM_$(IS_MACCATALYST))',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_' => 'x86_64-apple-darwin',
      'CARGO_BUILD_TARGET_MAC_CATALYST_X86_YES' => 'x86_64-apple-ios-macabi',
      'CARGO_BUILD_TARGET[sdk=macosx*][arch=*]' => '$(CARGO_BUILD_TARGET_MAC_CATALYST_X86_$(IS_MACCATALYST))',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.script_phases = [
    { name: 'Download and cache lib-messaging-ffi',
      execution_position: :before_compile,
      script: %q(
        set -euo pipefail
        if [ -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh" ]; then
          # Local development
          exit 0
        fi
        "${PODS_TARGET_SRCROOT}"/bin/fetch_archive.py -u "https://build-artifacts.signal.org/libraries/${LIBSIGNAL_FFI_PREBUILD_ARCHIVE}" -c "${LIB_MESSAGING_FFI_PREBUILD_CHECKSUM}" -o "${USER_LIBRARY_DIR}/Caches/com.cystack.ready.libmessaging"
      ),
    },
    { name: 'Extract lib-messaging-ffi prebuild',
      execution_position: :before_compile,
      input_files: ['$(USER_LIBRARY_DIR)/Caches/com.cystack.ready.libmessaging/$(LIB_MESSAGING_FFI_PREBUILD_ARCHIVE)'],
      output_files: ['$(LIB_MESSAGING_FFI_LIB_TO_LINK)'],
      script: %q(
        set -euo pipefail
        rm -rf "${LIB_MESSAGING_FFI_TEMP_DIR}"
        if [ -e "${PODS_TARGET_SRCROOT}/swift/build_ffi.sh" ]; then
          # Local development
          ln -fhs "${PODS_TARGET_SRCROOT}" "${LIB_MESSAGING_FFI_TEMP_DIR}"
        elif [ -e "${SCRIPT_INPUT_FILE_0}" ]; then
          mkdir -p "${LIB_MESSAGING_FFI_TEMP_DIR}"
          cd "${LIB_MESSAGING_FFI_TEMP_DIR}"
          tar --modification-time -x -f "${SCRIPT_INPUT_FILE_0}"
        else
          echo 'error: could not download libmessaging_ffi.a; please provide LIB_MESSAGING_FFI_PREBUILD_CHECKSUM' >&2
          exit 1
        fi
      ),
    }
  ]

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'swift/Tests/*/*.swift'
    test_spec.preserve_paths = [
      'swift/Tests/*/Resources',
    ]
    test_spec.pod_target_xcconfig = {
      # Don't also link into the test target.
      'LIB_MESSAGING_FFI_LIB_TO_LINK' => '',
    }
  end
end
