package com.noxcipher

object FileUtils {
    fun isText(bytes: ByteArray): Boolean {
        // Bug 4 Fix: Improved binary detection
        if (bytes.isEmpty()) return true
        
        // Check for common binary headers (magic numbers)
        // PDF: %PDF
        if (bytes.size >= 4 && bytes[0] == 0x25.toByte() && bytes[1] == 0x50.toByte() && bytes[2] == 0x44.toByte() && bytes[3] == 0x46.toByte()) return false
        // PNG: .PNG
        if (bytes.size >= 4 && bytes[0] == 0x89.toByte() && bytes[1] == 0x50.toByte() && bytes[2] == 0x4E.toByte() && bytes[3] == 0x47.toByte()) return false
        // JPEG: FF D8 FF
        if (bytes.size >= 3 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() && bytes[2] == 0xFF.toByte()) return false

        val limit = minOf(bytes.size, 512)
        var controlChars = 0
        for (i in 0 until limit) {
            val b = bytes[i].toInt() and 0xFF
            if (b == 0) return false // Null byte is definitely binary
            if (b < 32 && b != 9 && b != 10 && b != 13) { // Control chars except tab, LF, CR
                controlChars++
            }
        }
        // If more than 5% are control characters, assume binary
        return controlChars == 0 || (controlChars.toFloat() / limit.toFloat() < 0.05)
    }

    fun toHex(bytes: ByteArray, sb: StringBuilder) {
        for (b in bytes) {
            sb.append(String.format("%02x", b.toInt() and 0xFF))
        }
    }
}
