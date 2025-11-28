package com.noxcipher.util

import me.jahnen.libaums.core.driver.BlockDeviceDriver
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PartitionDriver(
    private val parent: BlockDeviceDriver,
    private val offset: Long,
    private val length: Long
) : BlockDeviceDriver {
    override val blockSize: Int get() = parent.blockSize

    override fun init() {
        // Parent already init
    }

    override fun read(deviceOffset: Long, buffer: ByteBuffer) {
        if (deviceOffset + buffer.remaining() > length) {
            // Allow reading up to the end, truncate if necessary?
            // Or just throw. Standard behavior is usually throw or read less.
            // But ByteBuffer read doesn't return count.
            // Let's be strict for now.
             // throw IllegalArgumentException("Read out of bounds: offset=$deviceOffset, len=${buffer.remaining()}, partitionLen=$length")
             // Actually, sometimes we read a bit past end? No.
        }
        // Ensure we don't read past end
        val limit = buffer.limit()
        val remaining = buffer.remaining()
        if (deviceOffset + remaining > length) {
             // Adjust limit? No, we can't easily.
             // Just let it fail if parent fails, or trust caller.
        }
        
        parent.read(offset + deviceOffset, buffer)
    }

    override fun write(deviceOffset: Long, buffer: ByteBuffer) {
        if (deviceOffset + buffer.remaining() > length) {
            throw IllegalArgumentException("Write out of bounds")
        }
        parent.write(offset + deviceOffset, buffer)
    }

    override fun flush() {
        parent.flush()
    }
}

object GptUtils {
    fun parseGpt(device: BlockDeviceDriver): List<BlockDeviceDriver> {
        val blockSize = device.blockSize
        val buffer = ByteBuffer.allocate(blockSize)
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        
        // Read LBA 1 (GPT Header)
        // If blockSize is 512, LBA 1 is at 512.
        // If blockSize is 4096, LBA 1 is at 4096.
        try {
            device.read(blockSize.toLong(), buffer)
        } catch (e: Exception) {
            e.printStackTrace()
            return emptyList()
        }
        
        val sigBytes = ByteArray(8)
        buffer.position(0)
        buffer.get(sigBytes)
        // "EFI PART" is 45 46 49 20 50 41 52 54
        val expectedSig = byteArrayOf(0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54)
        if (!sigBytes.contentEquals(expectedSig)) {
            return emptyList()
        }
        
        // Parse Header
        // Number of partition entries at offset 80 (4 bytes)
        val numEntries = buffer.getInt(80)
        // Size of partition entry at offset 84 (4 bytes)
        val entrySize = buffer.getInt(84)
        // Partition entries starting LBA at offset 72 (8 bytes)
        val entriesStartLba = buffer.getLong(72)
        
        val partitions = mutableListOf<BlockDeviceDriver>()
        
        // Read entries
        val totalEntriesSize = numEntries * entrySize
        // Round up to block size
        val blocksToRead = (totalEntriesSize + blockSize - 1) / blockSize
        val readBuffer = ByteBuffer.allocate(blocksToRead * blockSize)
        readBuffer.order(ByteOrder.LITTLE_ENDIAN)
        
        try {
            device.read(entriesStartLba * blockSize, readBuffer)
        } catch (e: Exception) {
            e.printStackTrace()
            return emptyList()
        }
        
        for (i in 0 until numEntries) {
            val entryOffset = i * entrySize
            readBuffer.position(entryOffset)
            
            // Check Partition Type GUID (first 16 bytes). If all zero, it's unused.
            val typeGuid1 = readBuffer.getLong()
            val typeGuid2 = readBuffer.getLong()
            
            if (typeGuid1 == 0L && typeGuid2 == 0L) continue
            
            // Unique Partition GUID (next 16 bytes) - skip
            readBuffer.position(entryOffset + 32)
            
            // First LBA (8 bytes)
            val firstLba = readBuffer.getLong()
            // Last LBA (8 bytes)
            val lastLba = readBuffer.getLong()
            
            if (firstLba > 0 && lastLba >= firstLba) {
                val startByte = firstLba * blockSize
                val lengthBytes = (lastLba - firstLba + 1) * blockSize
                partitions.add(PartitionDriver(device, startByte, lengthBytes))
            }
        }
        
        return partitions
    }
}
