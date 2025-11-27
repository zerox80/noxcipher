# NoxCipher - Complete Build Guide

This guide explains how to compile the **NoxCipher** project from scratch. It covers setting up the environment, building the Rust core, and running the Android app.

## 1. Prerequisites

Before you start, ensure you have the following installed:

1.  **Rust & Cargo**: [Install Rust](https://rustup.rs/)
2.  **Android Studio**: [Download](https://developer.android.com/studio)
3.  **Android NDK**:
    - Open Android Studio.
    - Go to **Tools > SDK Manager > SDK Tools**.
    - Check **NDK (Side by side)** and **CMake**.
    - Click **Apply** to install.
4.  **cargo-ndk**: This tool handles the complex linker setup for Android.
    ```powershell
    cargo install cargo-ndk
    ```
5.  **Android Targets**:
    ```powershell
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
    ```

## 2. Building the Rust Library (`rust_noxcipher`)

The core logic is in Rust. We need to compile it into `.so` (shared object) files for Android.

**CRITICAL**: Do NOT run `cargo build` directly. You must use `cargo ndk` to link correctly against the Android NDK.

1.  Open your terminal (PowerShell or CMD).
2.  Navigate to the `rust` directory:
    ```powershell
    cd rust
    ```
3.  Run the build command for all Android architectures:
    ```powershell
    cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 -o ../app/src/main/jniLibs build --release
    ```
    *   `-t ...`: Specifies the target architectures (ARM, x86).
    *   `-o ...`: Output directory. This automatically places the `.so` files where Android Studio expects them (`app/src/main/jniLibs`).

**Troubleshooting**:
- If you see `linker` errors, ensure `cargo-ndk` is installed and you are running the command exactly as above.
- Ensure you have the NDK installed in Android Studio.

## 3. Building the Android App (`app`)

Once the Rust library is built and placed in `jniLibs`, you can build the Android app.

1.  Open **Android Studio**.
2.  Select **Open** and choose the `veracrypt-android` folder (the root of this project).
3.  Wait for Gradle to sync.
4.  Connect your Android device via USB (ensure **USB Debugging** is on).
5.  Click the green **Run** button (Play icon) in the toolbar.

## 4. Usage

1.  Connect a USB OTG drive with a VeraCrypt container.
2.  Open **NoxCipher** on your phone.
3.  Grant the requested USB permissions.
4.  Select the USB device from the list.
5.  Enter your password.
6.  Browse your files!

## Project Structure

- **`rust/`**: Contains the Rust source code (`src/lib.rs`, `src/volume.rs`).
    - `Cargo.toml`: Rust dependencies (jni, fatfs, exfat, etc.).
- **`app/`**: Android Kotlin project.
    - `src/main/java/com/noxcipher/RustNative.kt`: JNI wrapper.
    - `src/main/jniLibs/`: Where the compiled Rust libraries go.
