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

    external fun initLogger()

    /**
     * Retrieves the last 100 log lines from the native logger.
     */
    external fun getLogs(): Array<String>

    /**
     * Initializes the Veracrypt volume.
     * @param password The password bytes.
     * @param header The first 128KB of the volume (containing the header).
     * @param pim The PIM value (0 for default).
     * @return A handle to the native context, or throws exception.
     */
    external fun init(password: ByteArray, header: ByteArray, pim: Int, partitionOffset: Long): Long

    /**
     * Decrypts a buffer in-place.
     * @param handle The native context handle.
     * @param offset The absolute byte offset of the data (used for XTS tweak).
     * @param data The data to decrypt (in-place).
     */
    external fun decrypt(handle: Long, offset: Long, data: ByteArray)

    /**
     * Encrypts a buffer in-place.
     * @param handle The native context handle.
     * @param offset The absolute byte offset of the data (used for XTS tweak).
     * @param data The data to encrypt (in-place).
     */
    external fun encrypt(handle: Long, offset: Long, data: ByteArray)

    /**
     * Closes the native context.
     * @param handle The native context handle.
     */
    external fun close(handle: Long)

    /**
     * Gets the encrypted area start offset (data offset).
     * @param handle The native context handle.
     * @return The offset in bytes.
     */
    external fun getDataOffset(handle: Long): Long
}
