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

    @Test
    fun testPlanHeaderAttemptUsesBackupWhenPrimaryIsEmpty() {
        val primaryHeader = ByteArray(131072)
        val backupHeader = ByteArray(131072) { 1 }

        val plan = planHeaderAttempt(primaryHeader, backupHeader)

        assertTrue(plan is HeaderPlan.Attempt)
        val attempt = plan as HeaderPlan.Attempt
        assertArrayEquals(primaryHeader, attempt.primaryHeaderBytes)
        assertArrayEquals(backupHeader, attempt.backupHeaderBytes)
        assertTrue(attempt.recoveryReason!!.contains("backup header recovery"))
    }

    @Test
    fun testPlanHeaderAttemptRejectsEmptyPrimaryWithoutBackup() {
        val primaryHeader = ByteArray(131072)

        val plan = planHeaderAttempt(primaryHeader, null)

        assertTrue(plan is HeaderPlan.Skip)
        assertEquals(
            "Primary header is empty and no usable backup header was found",
            (plan as HeaderPlan.Skip).reason,
        )
    }

    @Test
    fun testPlanHeaderAttemptRejectsCommonFilesystemHeader() {
        val primaryHeader = ByteArray(512)
        val signature = "NTFS".toByteArray()
        for (index in signature.indices) {
            primaryHeader[3 + index] = signature[index]
        }

        val plan = planHeaderAttempt(primaryHeader, ByteArray(131072) { 2 })

        assertTrue(plan is HeaderPlan.Skip)
        assertEquals(
            "Detected an unencrypted filesystem instead of a VeraCrypt header",
            (plan as HeaderPlan.Skip).reason,
        )
    }

    @Test
    fun testPlanHeaderAttemptAllowsShortPrimaryWithUsableBackup() {
        val primaryHeader = ByteArray(256)
        val backupHeader = ByteArray(131072) { 7 }

        val plan = planHeaderAttempt(primaryHeader, backupHeader)

        assertTrue(plan is HeaderPlan.Attempt)
        assertTrue((plan as HeaderPlan.Attempt).recoveryReason!!.contains("too small"))
    }

    @Test
    fun testPlanHeaderAttemptKeepsValidPrimaryAndDropsZeroBackup() {
        val primaryHeader = ByteArray(512)
        primaryHeader[0] = 0x54

        val plan = planHeaderAttempt(primaryHeader, ByteArray(131072))

        assertTrue(plan is HeaderPlan.Attempt)
        val attempt = plan as HeaderPlan.Attempt
        assertNull(attempt.backupHeaderBytes)
        assertNull(attempt.recoveryReason)
    }
}
