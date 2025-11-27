package com.noxcipher

import android.util.Log

object RustNative {
    init {
        try {
            Log.d("RustNative", "Attempting to load library: rust_noxcipher")
            System.loadLibrary("rust_noxcipher")
            Log.d("RustNative", "Library loaded successfully. Initializing logger...")
            initLogger()
            Log.d("RustNative", "Logger initialized.")
        } catch (e: UnsatisfiedLinkError) {
            Log.e("RustNative", "CRITICAL: Failed to load rust_noxcipher library. Ensure the .so file is present for this architecture.", e)
        } catch (e: Throwable) {
            Log.e("RustNative", "CRITICAL: Unexpected error during native init", e)
        }
    }

    private external fun initLogger()
    external fun unlockVolume(fd: Int, password: String): Boolean
    external fun listFiles(path: String): Array<String>
    external fun readFile(path: String, offset: Long, length: Int): ByteArray
}
