package com.noxcipher

import android.app.Application
import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.noxcipher.util.PartitionDriver
import com.noxcipher.util.PartitionUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import me.jahnen.libaums.core.UsbMassStorageDevice
import me.jahnen.libaums.core.driver.BlockDeviceDriver
import me.jahnen.libaums.core.fs.FileSystem
import me.jahnen.libaums.core.fs.FileSystemFactory
import me.jahnen.libaums.core.fs.UsbFile
import me.jahnen.libaums.core.partition.PartitionTableEntry
import java.io.IOException
import java.nio.ByteBuffer

internal data class MountCandidate(
    val driver: BlockDeviceDriver,
    val description: String,
    val volumeSize: Long,
    val physicalStartOffset: Long = 0L,
)

internal sealed class HeaderPlan {
    data class Attempt(
        val primaryHeaderBytes: ByteArray,
        val backupHeaderBytes: ByteArray?,
        val recoveryReason: String? = null,
    ) : HeaderPlan()

    data class Skip(val reason: String) : HeaderPlan()
}

internal fun isCommonFileSystemHeader(bytes: ByteArray): Boolean {
    if (bytes.size < 512) return false

    fun hasString(offset: Int, value: String): Boolean {
        if (offset + value.length > bytes.size) return false
        for (i in value.indices) {
            if (bytes[offset + i] != value[i].code.toByte()) return false
        }
        return true
    }

    return hasString(3, "NTFS") ||
        hasString(3, "EXFAT") ||
        hasString(82, "FAT32") ||
        hasString(54, "FAT16")
}

internal fun isAllZeroHeader(bytes: ByteArray): Boolean {
    val checkLen = minOf(bytes.size, 512)
    for (i in 0 until checkLen) {
        if (bytes[i] != 0.toByte()) return false
    }
    return checkLen > 0
}

internal fun planHeaderAttempt(primaryHeaderBytes: ByteArray, backupHeaderBytes: ByteArray?): HeaderPlan {
    val usableBackup = backupHeaderBytes?.takeIf { it.size >= 512 && !isAllZeroHeader(it) }

    if (primaryHeaderBytes.size < 512) {
        return if (usableBackup != null) {
            HeaderPlan.Attempt(
                primaryHeaderBytes = primaryHeaderBytes,
                backupHeaderBytes = usableBackup,
                recoveryReason = "Primary header window is too small. Trying backup header recovery.",
            )
        } else {
            HeaderPlan.Skip("Header area is too small to contain a VeraCrypt header")
        }
    }

    if (isAllZeroHeader(primaryHeaderBytes)) {
        return if (usableBackup != null) {
            HeaderPlan.Attempt(
                primaryHeaderBytes = primaryHeaderBytes,
                backupHeaderBytes = usableBackup,
                recoveryReason = "Primary header is empty. Trying backup header recovery.",
            )
        } else {
            HeaderPlan.Skip("Primary header is empty and no usable backup header was found")
        }
    }

    if (isCommonFileSystemHeader(primaryHeaderBytes)) {
        return HeaderPlan.Skip("Detected an unencrypted filesystem instead of a VeraCrypt header")
    }

    return HeaderPlan.Attempt(
        primaryHeaderBytes = primaryHeaderBytes,
        backupHeaderBytes = usableBackup,
    )
}

sealed class ConnectionResult {
    object Success : ConnectionResult()
    data class Error(val message: String) : ConnectionResult()
}

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val context: Context = application.applicationContext

    var activeFileSystem: FileSystem? = null
        private set

    private var activeDevice: UsbMassStorageDevice? = null
    private var rustHandle: Long? = null

    private val _connectionResult = MutableSharedFlow<ConnectionResult>()
    val connectionResult = _connectionResult.asSharedFlow()

    private val _logs = MutableSharedFlow<String>()
    val logs = _logs.asSharedFlow()

    private var connectionJob: Job? = null
    private val connectionMutex = Mutex()

    private data class CandidateDiscovery(
        val candidates: List<MountCandidate>,
        val diagnostic: String? = null,
    )

    fun connectDevice(
        usbManager: UsbManager, // Kept for UI compatibility; libaums handles the transport
        password: ByteArray,
        pim: Int,
        specificDevice: UsbDevice? = null,
        protectionPassword: ByteArray? = null,
        protectionPim: Int = 0,
    ) {
        connectionJob?.cancel()

        connectionJob = viewModelScope.launch(Dispatchers.IO) {
            connectionMutex.withLock {
                try {
                    closeConnection()

                    val devices = UsbMassStorageDevice.getMassStorageDevices(context)
                    if (devices.isEmpty()) {
                        _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_no_mass_storage)))
                        return@withLock
                    }

                    val candidateDevices = if (specificDevice != null) {
                        devices.filter { it.usbDevice == specificDevice }
                    } else {
                        devices
                    }

                    if (candidateDevices.isEmpty()) {
                        _connectionResult.emit(ConnectionResult.Error(if (specificDevice != null) "Selected USB device not found" else context.getString(R.string.error_no_mass_storage)))
                        return@withLock
                    }

                    var success = false
                    var lastError: String? = null

                    for (selected in candidateDevices) {
                        try {
                            selected.init()
                        } catch (e: Exception) {
                            Log.w("MainViewModel", "Failed to init device ${selected.usbDevice.deviceName}", e)
                            lastError = "Failed to initialize USB device ${selected.usbDevice.deviceName}"
                            continue
                        }

                        val discovery = buildMountCandidates(selected)
                        discovery.diagnostic?.let { Log.d("MainViewModel", it) }

                        if (discovery.candidates.isEmpty()) {
                            lastError = discovery.diagnostic ?: context.getString(R.string.error_no_partitions)
                            try {
                                selected.close()
                            } catch (_: Exception) {
                                // Best-effort cleanup for failed candidates.
                            }
                            continue
                        }

                        for (candidate in discovery.candidates) {
                            var localHandle: Long? = null
                            val candidateLabel = formatCandidateLabel(candidate)

                            try {
                                _logs.emit("Trying $candidateLabel")

                                val headerPlan = readHeaderPlan(candidate)
                                if (headerPlan is HeaderPlan.Skip) {
                                    lastError = "$candidateLabel: ${headerPlan.reason}"
                                    Log.d("MainViewModel", lastError)
                                    continue
                                }

                                val attemptPlan = headerPlan as? HeaderPlan.Attempt ?: continue
                                attemptPlan.recoveryReason?.let {
                                    _logs.emit("$candidateLabel: $it")
                                }

                                localHandle = openVolume(
                                    candidate = candidate,
                                    headerPlan = attemptPlan,
                                    password = password,
                                    pim = pim,
                                    protectionPassword = protectionPassword,
                                    protectionPim = protectionPim,
                                )

                                if (localHandle == null || localHandle <= 0) {
                                    lastError = "$candidateLabel: Invalid password/PIM or unsupported volume"
                                    continue
                                }

                                rustHandle = localHandle

                                val fs = mountFileSystem(candidate, localHandle)
                                activeFileSystem = fs
                                SessionManager.activeFileSystem = fs
                                _connectionResult.emit(ConnectionResult.Success)
                                success = true
                                activeDevice = selected
                                break
                            } catch (e: Exception) {
                                lastError = "$candidateLabel: ${e.message ?: "Unknown error"}"
                                Log.e("MainViewModel", "Mount failed for $candidateLabel", e)
                                localHandle?.let { RustNative.close(it) }
                                rustHandle = null
                            }
                        }

                        if (success) {
                            break
                        }

                        try {
                            selected.close()
                        } catch (e: Exception) {
                            Log.w("MainViewModel", "Failed to close USB device after unsuccessful mount", e)
                        }
                    }

                    try {
                        val nativeLogs = RustNative.getLogs()
                        if (nativeLogs.isNotEmpty()) {
                            _logs.emit(nativeLogs.joinToString("\n"))
                        }
                    } catch (_: Exception) {
                        // Ignore logger failures
                    }

                    if (!success) {
                        _connectionResult.emit(
                            ConnectionResult.Error(
                                context.getString(
                                    R.string.error_wrong_credentials,
                                    lastError ?: "No valid volume found",
                                ),
                            ),
                        )
                        closeConnection()
                    }
                } catch (e: Exception) {
                    _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_generic, e.message)))
                    closeConnection()
                } finally {
                    RustNative.clearByteArray(password)
                }
            }
        }
    }

    private suspend fun openVolume(
        candidate: MountCandidate,
        headerPlan: HeaderPlan.Attempt,
        password: ByteArray,
        pim: Int,
        protectionPassword: ByteArray?,
        protectionPim: Int,
    ): Long? {
        val passwordCandidates = buildPasswordCandidates(password)

        try {
            for ((index, pwd) in passwordCandidates.withIndex()) {
                if (index > 0) {
                    _logs.emit("Trying trimmed password on ${formatCandidateLabel(candidate)}...")
                }

                val handle = RustNative.init(
                    pwd,
                    headerPlan.primaryHeaderBytes,
                    pim,
                    0L, // Android exposes candidate-relative drivers to the current Rust API.
                    0L, // Header buffers always begin at offset 0 within the chosen candidate.
                    protectionPassword,
                    protectionPim,
                    candidate.volumeSize,
                    headerPlan.backupHeaderBytes,
                )

                if (handle > 0) {
                    return handle
                }
            }
        } finally {
            for (pwd in passwordCandidates) {
                if (pwd !== password) {
                    RustNative.clearByteArray(pwd)
                }
            }
        }

        return null
    }

    private fun mountFileSystem(candidate: MountCandidate, volumeHandle: Long): FileSystem {
        val dataOffset = RustNative.getDataOffset(volumeHandle)
        val veracryptDriver = VeracryptBlockDevice(candidate.driver, volumeHandle, dataOffset)

        return try {
            val dummyEntry = PartitionTableEntry(0x0C, 0, 0)
            FileSystemFactory.createFileSystem(dummyEntry, veracryptDriver)
        } catch (e: Exception) {
            val callback = FileSystemReadCallback(veracryptDriver)
            val fsHandle = RustNative.mountFs(volumeHandle, callback, candidate.volumeSize)
            if (fsHandle > 0) {
                RustFileSystem(fsHandle, context.getString(R.string.root_title))
            } else {
                throw IOException(context.getString(R.string.error_fs_detection))
            }
        }
    }

    fun listFiles(dir: UsbFile): Array<UsbFile> {
        return try {
            dir.listFiles()
        } catch (_: IOException) {
            emptyArray()
        }
    }

    fun closeConnection() {
        try {
            SessionManager.activeFileSystem = null
            activeFileSystem?.close()
            activeFileSystem = null

            rustHandle?.let { RustNative.close(it) }
            rustHandle = null

            activeDevice?.close()
            activeDevice = null
        } catch (_: Exception) {
            // Best-effort cleanup
        }
    }

    private fun safeVolumeSize(driver: BlockDeviceDriver): Long {
        return try {
            driver.blocks * driver.blockSize.toLong()
        } catch (_: Exception) {
            0L
        }
    }

    private fun buildMountCandidates(selected: UsbMassStorageDevice): CandidateDiscovery {
        val autoCandidates = selected.partitions.mapIndexedNotNull { index, driver ->
            buildCandidate(driver, "partition ${index + 1}")
        }
        if (autoCandidates.isNotEmpty()) {
            return CandidateDiscovery(autoCandidates)
        }

        val debug = StringBuilder()
        val rawDriver = tryCreateRawDriver(selected, debug)
            ?: return CandidateDiscovery(emptyList(), debug.takeIf { it.isNotEmpty() }?.toString())

        val manualCandidates = PartitionUtils.parseGpt(rawDriver)
            .ifEmpty { PartitionUtils.parseMbr(rawDriver) }
            .mapIndexedNotNull { index, driver ->
                buildCandidate(driver, "manual partition ${index + 1}")
            }

        if (manualCandidates.isNotEmpty()) {
            return CandidateDiscovery(manualCandidates, debug.takeIf { it.isNotEmpty() }?.toString())
        }

        val rawCandidate = buildCandidate(rawDriver, "whole device")
        return if (rawCandidate != null) {
            CandidateDiscovery(listOf(rawCandidate), debug.takeIf { it.isNotEmpty() }?.toString())
        } else {
            CandidateDiscovery(emptyList(), debug.takeIf { it.isNotEmpty() }?.toString())
        }
    }

    private fun buildCandidate(driver: BlockDeviceDriver, description: String): MountCandidate? {
        val volumeSize = safeVolumeSize(driver)
        if (volumeSize <= 0) return null

        val physicalStartOffset = (driver as? PartitionDriver)?.partitionOffset ?: 0L
        return MountCandidate(
            driver = driver,
            description = description,
            volumeSize = volumeSize,
            physicalStartOffset = physicalStartOffset,
        )
    }

    private fun readBytes(driver: BlockDeviceDriver, offset: Long, size: Int): ByteArray {
        if (size <= 0) return ByteArray(0)

        val buffer = ByteBuffer.allocate(size)
        driver.read(offset, buffer)
        val bytesRead = buffer.position()

        return when {
            bytesRead <= 0 -> ByteArray(0)
            bytesRead == size -> buffer.array()
            else -> buffer.array().copyOf(bytesRead)
        }
    }

    private fun readHeaderPlan(candidate: MountCandidate): HeaderPlan {
        val primaryReadSize = minOf(candidate.volumeSize, HEADER_GROUP_SIZE.toLong()).toInt()
        val primaryHeaderBytes = readBytes(candidate.driver, 0, primaryReadSize)
        val backupHeaderBytes = if (candidate.volumeSize >= HEADER_GROUP_SIZE) {
            readBytes(candidate.driver, candidate.volumeSize - HEADER_GROUP_SIZE, HEADER_GROUP_SIZE)
        } else {
            null
        }

        return planHeaderAttempt(primaryHeaderBytes, backupHeaderBytes)
    }

    private fun buildPasswordCandidates(password: ByteArray): List<ByteArray> {
        val candidates = mutableListOf(password)
        if (password.isEmpty()) return candidates

        if (password.last() == 0x20.toByte()) {
            var end = password.size - 1
            while (end >= 0 && password[end] == 0x20.toByte()) end--
            if (end >= 0) {
                candidates.add(password.copyOfRange(0, end + 1))
            }
        }

        return candidates
    }

    private fun isCommonFileSystem(bytes: ByteArray): Boolean {
        return isCommonFileSystemHeader(bytes)
    }

    private fun isAllZeros(bytes: ByteArray): Boolean {
        return isAllZeroHeader(bytes)
    }

    private fun formatCandidateLabel(candidate: MountCandidate): String {
        return if (candidate.physicalStartOffset > 0) {
            "${candidate.description} @ byte ${candidate.physicalStartOffset}"
        } else {
            candidate.description
        }
    }

    private fun tryCreateRawDriver(device: UsbMassStorageDevice, debug: StringBuilder): BlockDeviceDriver? {
        return try {
            val commField = UsbMassStorageDevice::class.java.getDeclaredField("usbCommunication")
            commField.isAccessible = true
            val comm = commField.get(device) ?: run {
                debug.append("\nUsbCommunication is null")
                return null
            }

            val scsiClass = Class.forName("me.jahnen.libaums.core.driver.scsi.ScsiBlockDevice")
            val constructor = scsiClass.constructors.firstOrNull { ctor ->
                ctor.parameterTypes.isNotEmpty() && ctor.parameterTypes[0].isAssignableFrom(comm.javaClass)
            } ?: run {
                debug.append("\nNo suitable ScsiBlockDevice constructor found")
                return null
            }

            val args = arrayOfNulls<Any>(constructor.parameterCount)
            args[0] = comm

            val params = constructor.parameterTypes
            for (i in 1 until params.size) {
                args[i] = when (params[i]) {
                    java.lang.Byte.TYPE, java.lang.Byte::class.java -> 0.toByte()
                    java.lang.Integer.TYPE, java.lang.Integer::class.java -> 0
                    java.lang.Long.TYPE, java.lang.Long::class.java -> 0L
                    java.lang.Boolean.TYPE, java.lang.Boolean::class.java -> false
                    else -> null
                }
            }

            val raw = constructor.newInstance(*args) as BlockDeviceDriver
            raw.init()
            raw
        } catch (e: Exception) {
            debug.append("\nManual driver creation failed: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    override fun onCleared() {
        super.onCleared()
        closeConnection()
    }

    private companion object {
        private const val HEADER_GROUP_SIZE = 131072
    }
}

class FileSystemReadCallback(private val driver: BlockDeviceDriver) : NativeReadCallback {
    override fun read(offset: Long, buffer: java.nio.ByteBuffer): Int {
        return try {
            val start = buffer.position()
            driver.read(offset, buffer)
            buffer.position() - start
        } catch (e: Exception) {
            android.util.Log.e("MainViewModel", "Error reading from physical driver", e)
            -1
        }
    }
}

