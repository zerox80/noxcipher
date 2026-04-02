# Repository Guidelines

## Project Structure & Module Organization
This repository is an Android app with a Rust JNI backend. Kotlin/Android code lives in `app/src/main/java/com/noxcipher/`, UI resources in `app/src/main/res/`, and Android tests in `app/src/test/java/` and `app/src/androidTest/java/`. NoxCipher is the Android app, so when working on that code always read the reference implementation in `C:\Daten2\VeraCrypt` before making changes. The Rust core is in `rust/src/`, with integration and regression tests under `rust/tests/`. Generated native libraries are expected in `app/src/main/jniLibs/`.

## Build, Test, and Development Commands
- `cd rust; cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 -o ../app/src/main/jniLibs build --release` builds the Rust library for Android. Do not use `cargo build` or `cargo check` here.
- `./gradlew assembleDebug` builds the Android app for local installation.
- `./gradlew assembleRelease` builds the release APK/AAB using the signing config from `keystore.properties`.
- `./gradlew test` and `./gradlew connectedAndroidTest` exist, but do not run test suites unless the task explicitly asks for verification.

## Coding Style & Naming Conventions
Follow the existing style in each language: Kotlin uses 4-space indentation, `PascalCase` for classes, and `camelCase` for functions, properties, and resources. Rust should follow `rustfmt` defaults, with `snake_case` for functions and modules. Keep comments short, natural, and specific; avoid wording that reads like generic AI-generated filler.

## Testing Guidelines
Tests are already organized by module: Rust unit/integration tests in `rust/tests/` and Android tests in the module test directories. Name tests after the behavior they cover, not the implementation detail. If you need validation, prefer targeted checks on the touched module instead of broad runs.

## Commit & Pull Request Guidelines
Recent commits use short, imperative subjects such as `Fix ...`, `Add ...`, and `Refactor ...`. Keep commit messages concise and action-oriented. Pull requests should describe the functional change, list affected areas (`app/` or `rust/`), and include screenshots or device notes for UI changes.

## Security & Configuration Tips
Do not commit real signing secrets. Use `keystore.properties.example` as the local template and keep `keystore.properties` private. Treat `release.keystore` as sensitive release material.
