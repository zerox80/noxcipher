package com.noxcipher

import android.util.Log

// Singleton object to interface with the native Rust library.
object RustNative {
    // Flag to track if the native library was successfully initialized.
    var isInitialized = false
        private set

    // Static initialization block to load the library.
    init {
        try {
            Log.d("RustNative", "Attempting to load library: rust_noxcipher")
            // Load the shared library 'librust_noxcipher.so'.
            System.loadLibrary("rust_noxcipher")
            Log.d("RustNative", "Library loaded successfully. Initializing logger...")
            // Initialize the native logger.
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

    // Native method to initialize the Rust logger.
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
     * @param partitionOffset The offset of the partition start.
     * @param protectionPassword The protection password bytes (optional).
     * @param protectionPim The protection PIM value (0 for default).
     * @return A handle to the native context, or throws exception.
     */
    external fun init(
        password: ByteArray, 
        header: ByteArray, 
        pim: Int, 
        partitionOffset: Long, 
        protectionPassword: ByteArray?, 
        protectionPim: Int
    ): Long

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

    /**
     * Mounts the file system (NTFS/exFAT) via Rust.
     * @param volumeHandle The handle to the initialized volume.
     * @param callback The callback to read raw data.
     * @param volumeSize The size of the volume in bytes.
     * @return A handle to the file system, or -1 if failed.
     */
    external fun mountFs(volumeHandle: Long, callback: NativeReadCallback, volumeSize: Long): Long

    /**
     * Lists files in a directory.
     * @param fsHandle The file system handle.
     * @param path The path to list (e.g. "/").
     * @return Array of RustFile objects.
     */
    external fun listFiles(fsHandle: Long, path: String): Array<RustFile>

    /**
     * Reads data from a file.
     * @param fsHandle The file system handle.
     * @param path The path of the file.
     * @param offset The offset to read from.
     * @param buffer The buffer to read into.
     * @return The number of bytes read, or -1 if failed.
     */
    external fun readFile(fsHandle: Long, path: String, offset: Long, buffer: ByteArray): Long

    /**
     * Closes the file system.
     * @param fsHandle The file system handle.
     */
    external fun closeFs(fsHandle: Long)
}
