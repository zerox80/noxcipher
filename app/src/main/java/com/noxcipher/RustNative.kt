package com.noxcipher

import android.util.Log

object RustNative {
    var isInitialized = false
        private set

    init {
        try {
            Log.d("RustNative", "Attempting to load library: rust_noxcipher")
            System.loadLibrary("rust_noxcipher")
            Log.d("RustNative", "Library loaded successfully. Initializing logger...")
            initLogger()
            Log.d("RustNative", "Logger initialized.")
            isInitialized = true
        } catch (e: UnsatisfiedLinkError) {
            Log.e("RustNative", "CRITICAL: Failed to load rust_noxcipher library. Ensure the .so file is present for this architecture.", e)
        } catch (e: Exception) {
            Log.e("RustNative", "CRITICAL: Unexpected error during native init", e)
        } catch (e: Throwable) {
             Log.e("RustNative", "CRITICAL: Fatal error during native init", e)
        }
    }

    private external fun initLogger()
    // Password as ByteArray for security
    external fun unlockVolume(fd: Int, password: ByteArray): Boolean
    external fun listFiles(path: String): Array<String>
    // Read into buffer, return bytes read
    external fun readFile(path: String, offset: Long, buffer: ByteArray): Int
}
