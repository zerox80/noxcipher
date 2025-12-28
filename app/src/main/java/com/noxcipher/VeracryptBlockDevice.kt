package com.noxcipher

import me.jahnen.libaums.core.driver.BlockDeviceDriver
import java.io.IOException
import java.nio.ByteBuffer

class VeracryptBlockDevice(
    private val physicalDevice: BlockDeviceDriver,
    private val rustHandle: Long,
    private val dataOffset: Long
) : BlockDeviceDriver, java.io.Closeable {

    override fun init() {
        // Physical device should already be initialized
    }

    override val blockSize: Int
        get() = physicalDevice.blockSize

    override val blocks: Long
        get() = (physicalDevice.blocks * physicalDevice.blockSize - dataOffset) / physicalDevice.blockSize

    override fun read(offset: Long, dest: ByteBuffer) {
        // 1. Read encrypted data from physical device
        val position = dest.position()
        // Apply data offset to physical read
        physicalDevice.read(offset + dataOffset, dest)
        
        // 2. Decrypt in-place
        val bytesRead = dest.position() - position
        if (bytesRead > 0) {
            if (dest.isDirect) {
                // Zero-copy path for direct buffers
                RustNative.decryptDirect(rustHandle, offset, dest, position, bytesRead)
            } else if (dest.hasArray()) {
                val array = dest.array()
                val arrayOffset = dest.arrayOffset() + position
                
                val buffer = ByteArray(bytesRead)
                System.arraycopy(array, arrayOffset, buffer, 0, bytesRead)
                
                // Pass logical offset to Rust (it handles tweak calculation)
                RustNative.decrypt(rustHandle, offset, buffer)
                
                System.arraycopy(buffer, 0, array, arrayOffset, bytesRead)
            } else {
                val buffer = ByteArray(bytesRead)
                val currentPos = dest.position()
                
                dest.position(position)
                dest.get(buffer)
                
                RustNative.decrypt(rustHandle, offset, buffer)
                
                dest.position(position)
                dest.put(buffer)
                
                if (dest.position() != currentPos) {
                    dest.position(currentPos)
                }
            }
        }
    }

    @Throws(IOException::class)
    override fun write(offset: Long, src: ByteBuffer) {
        val position = src.position()
        val length = src.remaining()
        
        if (length <= 0) return

        // We must copy data to a temporary buffer to avoid modifying the source buffer during encryption
        // (BlockDeviceDriver.write contract implies source is read-only usually, or at least shouldn't be garbled)
        val buffer = ByteArray(length)
        
        if (src.hasArray()) {
            val array = src.array()
            val arrayOffset = src.arrayOffset() + position
            System.arraycopy(array, arrayOffset, buffer, 0, length)
            src.position(position + length)
        } else {
            src.get(buffer)
        }
        
        RustNative.encrypt(rustHandle, offset, buffer)
        
        val encryptedBuf = ByteBuffer.wrap(buffer)
        physicalDevice.write(offset + dataOffset, encryptedBuf)
    }

    override fun close() {
        RustNative.close(rustHandle)
    }
}
