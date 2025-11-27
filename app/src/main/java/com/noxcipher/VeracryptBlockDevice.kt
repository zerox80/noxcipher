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
        val bytesRead = dest.position() - position
        if (bytesRead > 0) {
            if (dest.hasArray()) {
                // Heap buffer: use backing array directly if possible (but we need to pass to JNI)
                // JNI takes jbyteArray.
                val array = dest.array()
                val arrayOffset = dest.arrayOffset() + position
                
                // We must copy to a clean ByteArray for JNI because we can't easily pass a slice/offset to our current Rust impl
                // Our Rust impl takes the WHOLE array and decrypts it.
                // So we MUST copy the relevant chunk.
                val buffer = ByteArray(bytesRead)
                System.arraycopy(array, arrayOffset, buffer, 0, bytesRead)
                
                RustNative.decrypt(rustHandle, offset, buffer)
                
                System.arraycopy(buffer, 0, array, arrayOffset, bytesRead)
            } else {
                // Direct buffer: must copy out
                val buffer = ByteArray(bytesRead)
                // Read from buffer (this advances position, so we need to reset or use absolute get?)
                // Actually, physicalDevice.read ADVANCED the position.
                // So we need to read from the *previous* position.
                
                // Save current position
                val currentPos = dest.position()
                
                // Go back to where we started reading
                dest.position(position)
                dest.get(buffer) // Reads bytesRead bytes
                
                // Decrypt
                RustNative.decrypt(rustHandle, offset, buffer)
                
                // Write back
                dest.position(position)
                dest.put(buffer)
                
                // Restore position (though put() should have advanced it to currentPos)
                if (dest.position() != currentPos) {
                    dest.position(currentPos)
                }
            }
        }
    }

    @Throws(IOException::class)
    override fun write(offset: Long, src: ByteBuffer) {
        // 1. Encrypt data before writing
        val position = src.position()
        val length = src.remaining()
        
        if (length <= 0) return

        val buffer = ByteArray(length)
        
        if (src.hasArray()) {
            val array = src.array()
            val arrayOffset = src.arrayOffset() + position
            System.arraycopy(array, arrayOffset, buffer, 0, length)
            src.position(position + length)
        } else {
            // Direct buffer: get() advances position, which is what we want (consume the source)
            src.get(buffer)
        }
        
        // Encrypt in-place in our temp buffer
        RustNative.encrypt(rustHandle, offset, buffer)
        
        // Write encrypted data to physical device
        val encryptedBuf = ByteBuffer.wrap(buffer)
        physicalDevice.write(offset, encryptedBuf)
    }
}
