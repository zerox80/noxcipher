package com.noxcipher

import org.junit.Test
import org.junit.Assert.*

class FileUtilsTest {
    @Test
    fun testIsText() {
        assertTrue(FileUtils.isText("Hello World".toByteArray()))
        assertTrue(FileUtils.isText(ByteArray(0)))
        
        // Binary (null byte)
        assertFalse(FileUtils.isText(byteArrayOf(0, 1, 2)))
        
        // PDF magic
        assertFalse(FileUtils.isText(byteArrayOf(0x25, 0x50, 0x44, 0x46)))
        
        // Control chars
        val controlBytes = ByteArray(100) { if (it < 10) 1 else 65 } // 10% control chars
        assertFalse(FileUtils.isText(controlBytes))
    }
}
