package com.noxcipher

import com.github.mjdev.libaums.driver.BlockDeviceDriver
import java.io.IOException
import java.nio.ByteBuffer

class VeracryptBlockDevice(
    private val physicalDevice: BlockDeviceDriver,
    private val rustHandle: Long
) : BlockDeviceDriver {

    override fun init() {
        // Physical device should already be initialized
    }

    override fun getBlockSize(): Int {
        return physicalDevice.blockSize
    }

    @Throws(IOException::class)
    override fun read(offset: Long, dest: ByteBuffer) {
        // 1. Read encrypted data from physical device
        val position = dest.position()
        physicalDevice.read(offset, dest)
        
        // 2. Decrypt in-place
        // We need to access the backing array of the ByteBuffer
        if (dest.hasArray()) {
            val array = dest.array()
            val arrayOffset = dest.arrayOffset() + position
            val length = dest.position() - position // Bytes read
            
            // Create a slice or pass offset/length to Rust?
            // Rust expects a ByteArray. We can pass the whole array but we need to tell Rust where to start?
            // My Rust signature is `decrypt(handle, offset, data)`.
            // JNI `jbyteArray` refers to the whole array.
            // If I pass `dest.array()`, it passes the whole backing array.
            // I should probably copy the relevant bytes to a temporary buffer if I can't slice it easily for JNI,
            // OR I can use `ByteBuffer` in JNI (GetDirectBufferAddress) if it's direct.
            // But `libaums` usually uses heap buffers.
            
            // For simplicity and safety with JNI:
            // Copy the read bytes to a new ByteArray, decrypt, copy back.
            // OR: pass the array and an offset/length to Rust?
            // My Rust `decrypt` takes `jbyteArray`. It decrypts the WHOLE array.
            // So I MUST pass a slice.
            
            val bytesRead = dest.position() - position
            if (bytesRead > 0) {
                val buffer = ByteArray(bytesRead)
                System.arraycopy(array, arrayOffset, buffer, 0, bytesRead)
                
                RustNative.decrypt(rustHandle, offset, buffer)
                
                System.arraycopy(buffer, 0, array, arrayOffset, bytesRead)
            }
        } else {
            // TODO: Handle direct buffers if necessary
            throw IOException("Direct buffers not supported yet")
        }
    }

    @Throws(IOException::class)
    override fun write(offset: Long, src: ByteBuffer) {
        throw IOException("Writing is not supported in this version")
    }
}
