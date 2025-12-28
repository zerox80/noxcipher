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
    override val blocks: Long get() = length / blockSize

    override fun init() {
        // Parent already init
    }

    override fun read(deviceOffset: Long, buffer: ByteBuffer) {
        if (deviceOffset + buffer.remaining() > length) {
            throw IllegalArgumentException("Read out of bounds: offset=$deviceOffset, len=${buffer.remaining()}, partitionLen=$length")
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

    // override fun flush() {
    //    parent.flush()
    // }
}

object PartitionUtils {
    fun parseGpt(device: BlockDeviceDriver): List<BlockDeviceDriver> {
        val blockSize = device.blockSize
        val buffer = ByteBuffer.allocate(blockSize)
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        
        // Read LBA 1 (GPT Header)
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
        val numEntries = buffer.getInt(80)
        val entrySize = buffer.getInt(84)
        val entriesStartLba = buffer.getLong(72)
        
        val partitions = mutableListOf<BlockDeviceDriver>()
        
        // Read entries
        val totalEntriesSize = numEntries * entrySize
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
            
            val typeGuid1 = readBuffer.getLong()
            val typeGuid2 = readBuffer.getLong()
            
            if (typeGuid1 == 0L && typeGuid2 == 0L) continue
            
            readBuffer.position(entryOffset + 32)
            val firstLba = readBuffer.getLong()
            val lastLba = readBuffer.getLong()
            
            if (firstLba > 0 && lastLba >= firstLba) {
                val startByte = firstLba * blockSize
                val lengthBytes = (lastLba - firstLba + 1) * blockSize
                partitions.add(PartitionDriver(device, startByte, lengthBytes))
            }
        }
        
        return partitions
    }

    fun parseMbr(device: BlockDeviceDriver): List<BlockDeviceDriver> {
        val blockSize = device.blockSize
        val buffer = ByteBuffer.allocate(blockSize)
        buffer.order(ByteOrder.LITTLE_ENDIAN)

        try {
            device.read(0, buffer)
        } catch (e: Exception) {
            e.printStackTrace()
            return emptyList()
        }

        // Check signature 0x55AA at offset 510
        if (buffer.get(510).toInt().and(0xFF) != 0x55 || buffer.get(511).toInt().and(0xFF) != 0xAA) {
            return emptyList()
        }

        val partitions = mutableListOf<BlockDeviceDriver>()
        
        // Read 4 partition entries starting at offset 446
        for (i in 0 until 4) {
            val entryOffset = 446 + i * 16
            val type = buffer.get(entryOffset + 4).toInt().and(0xFF)
            
            if (type == 0) continue
            
            // LBA Start (4 bytes) at offset 8
            val lbaStart = buffer.getInt(entryOffset + 8).toLong().and(0xFFFFFFFFL)
            // Number of Sectors (4 bytes) at offset 12
            val sectorCount = buffer.getInt(entryOffset + 12).toLong().and(0xFFFFFFFFL)
            
            if (lbaStart > 0 && sectorCount > 0) {
                 val startByte = lbaStart * blockSize
                 val lengthBytes = sectorCount * blockSize
                 partitions.add(PartitionDriver(device, startByte, lengthBytes))
            }
        }
        return partitions
    }
}
