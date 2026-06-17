# csc-client Makefile — UniFFI binding generation & cross-compilation

CRATE_NAME := csc_client
LIB_NAME   := lib$(CRATE_NAME)
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOST_LIB_EXT := dylib
else
  HOST_LIB_EXT :=.
endif
VERSION    := $(shell cargo metadata --no-deps --format-version 1 | python3 -c "import sys,.n; print(.n.load(sys.stdin)['packages'][0]['version'])")

BUILD_DIR      := target
BINDINGS_DIR   := bindings
SWIFT_DIR      := $(BINDINGS_DIR)/swift
KOTLIN_DIR     := $(BINDINGS_DIR)/kotlin
XCFRAMEWORK    := $(BUILD_DIR)/$(CRATE_NAME).xcframework

IOS_TARGETS     := aarch64-apple-ios
IOS_SIM_TARGETS := aarch64-apple-ios-sim x86_64-apple-ios
ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

.PHONY: all bindings ios android xcframework aar clean check-bindings

all: bindings

bindings: bindings-swift bindings-kotlin

bindings-swift: $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(SWIFT_DIR)
	cargo run --features bindgen --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language swift --out-dir $(SWIFT_DIR)

bindings-kotlin: $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(KOTLIN_DIR)
	cargo run --features bindgen --bin uniffi-bindgen -- generate \
		--library $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language kotlin --out-dir $(KOTLIN_DIR)

$(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT):
	cargo build

ios: $(foreach t,$(IOS_TARGETS) $(IOS_SIM_TARGETS),ios-$(t))
ios-%:
	cargo build --release --target $*

xcframework: ios bindings-swift
	@rm -rf $(XCFRAMEWORK)
	@mkdir -p $(BUILD_DIR)/ios-sim-universal $(BUILD_DIR)/Headers
	lipo -create $(foreach t,$(IOS_SIM_TARGETS),$(BUILD_DIR)/$(t)/release/$(LIB_NAME).a) \
		-output $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a
	@cp $(SWIFT_DIR)/$(CRATE_NAME)FFI.h $(BUILD_DIR)/Headers/
	@echo "framework module $(CRATE_NAME)FFI { header \"$(CRATE_NAME)FFI.h\" export * }" \
		> $(BUILD_DIR)/Headers/module.modulemap
	xcodebuild -create-xcframework \
		-library $(BUILD_DIR)/aarch64-apple-ios/release/$(LIB_NAME).a -headers $(BUILD_DIR)/Headers \
		-library $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a -headers $(BUILD_DIR)/Headers \
		-output $(XCFRAMEWORK)

android: $(foreach t,$(ANDROID_TARGETS),android-$(t))
android-%:
	cargo ndk --target $* --platform 28 -- build --release

AAR_DIR := $(BUILD_DIR)/aar
aar: android bindings-kotlin
	@mkdir -p $(AAR_DIR)/jni/arm64-v8a $(AAR_DIR)/jni/armeabi-v7a $(AAR_DIR)/jni/x86_64
	cp $(BUILD_DIR)/aarch64-linux-android/release/$(LIB_NAME). $(AAR_DIR)/jni/arm64-v8a/
	cp $(BUILD_DIR)/armv7-linux-androideabi/release/$(LIB_NAME). $(AAR_DIR)/jni/armeabi-v7a/
	cp $(BUILD_DIR)/x86_64-linux-android/release/$(LIB_NAME). $(AAR_DIR)/jni/x86_64/
	@echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.sirosfoundation.csc"/>' \
		> $(AAR_DIR)/AndroidManifest.xml
	cd $(AAR_DIR) && zip -r ../$(CRATE_NAME)-$(VERSION).aar .

check-bindings: bindings
	@git diff --exit-code $(BINDINGS_DIR) || \
		(echo "ERROR: Generated bindings are out of date." && exit 1)

clean:
	cargo clean
	rm -rf $(BINDINGS_DIR) $(BUILD_DIR)/aar $(BUILD_DIR)/ios-sim-universal $(BUILD_DIR)/Headers
