# NoxCipher

NoxCipher is an Android application designed to mount and explore VeraCrypt volumes via USB OTG. It utilizes a Rust backend for secure and efficient volume handling, communicating with the Android frontend through JNI.

Key features include secure password management, file browsing capabilities, and robust error handling. The project demonstrates a hybrid architecture combining Kotlin for the UI and Rust for low level operations.

To build, ensure you have the Android SDK and Rust toolchain installed. This version includes a mock volume implementation for testing purposes without physical devices.
