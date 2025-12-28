```
package com.noxcipher

import android.app.Application
import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
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

                    // Iterate over all candidate devices (e.g. if one is a mouse or non-VC drive)
                    for (selected in candidateDevices) {
                        try {
                            selected.init()
                        } catch (e: Exception) {
                            Log.w("MainViewModel", "Failed to init device ${selected.usbDevice.deviceName}", e)
                            continue
                        }

                        // activeDevice = selected // Don't set yet, wait for success

                        var partitions: List<BlockDeviceDriver> = selected.partitions
                        var rawDriver: BlockDeviceDriver? = null

                        if (partitions.isEmpty()) {
                            val debug = StringBuilder()
                            rawDriver = tryCreateRawDriver(selected, debug)

                            if (rawDriver != null) {
                                var manual = PartitionUtils.parseGpt(rawDriver)
                                if (manual.isEmpty()) manual = PartitionUtils.parseMbr(rawDriver)
                                partitions = manual
                            } else if (debug.isNotEmpty()) {
                                // Only emit logs if we fail completely later? Or just log?
                                Log.d("MainViewModel", debug.toString())
                            }
                        }

                        val targets = if (partitions.isNotEmpty()) partitions else listOfNotNull(rawDriver)
                        if (targets.isEmpty()) {
                            continue
                        }

                    for (physicalDriver in targets) {
                        var localHandle: Long? = null
                        try {
                            val volSize = safeVolumeSize(physicalDriver)
                            if (volSize <= 0) {
                                lastError = "Unable to determine volume size"
                                continue
                            }

                            val headerBytes = readBytes(physicalDriver, 0, HEADER_GROUP_SIZE)
                            val backupHeaderBytes = if (volSize >= HEADER_GROUP_SIZE) {
                                readBytes(physicalDriver, volSize - HEADER_GROUP_SIZE, HEADER_GROUP_SIZE)
                            } else {
                                null
                            }

                            if (isAllZeros(headerBytes)) {
                                lastError = "Skipped: Header is all zeros"
                                continue
                            }

                            if (isCommonFileSystem(headerBytes)) {
                                lastError = "Skipped: Detected unencrypted filesystem"
                                continue
                            }

                            val passwordCandidates = buildPasswordCandidates(password)

                            for ((index, pwd) in passwordCandidates.withIndex()) {
                                try {
                                    if (index > 0) _logs.emit("Trying trimmed password…")

                                    val handle = RustNative.init(
                                        pwd,
                                        headerBytes,
                                        pim,
                                        0L, // partitionOffset (tweak offset) – normal volumes use 0
                                        0L, // headerOffsetBias – headerBytes start at 0
                                        protectionPassword,
                                        protectionPim,
                                        volSize,
                                        backupHeaderBytes,
                                    )

                                    if (handle > 0) {
                                        localHandle = handle
                                        break
                                    }
                                } finally {
                                    if (pwd !== password) {
                                        RustNative.clearByteArray(pwd)
                                    }
                                }
                            }
                            // Clear original password bytes
                            RustNative.clearByteArray(password)
                            }

                            if (localHandle == null || localHandle <= 0) {
                                lastError = "Invalid password/PIM or not a VeraCrypt volume"
                                continue
                            }

                            rustHandle = localHandle

                            val dataOffset = RustNative.getDataOffset(localHandle)
                            val veracryptDriver = VeracryptBlockDevice(physicalDriver, localHandle, dataOffset)

                            val fs: FileSystem = try {
                                val dummyEntry = PartitionTableEntry(0x0C, 0, 0)
                                FileSystemFactory.createFileSystem(dummyEntry, veracryptDriver)
                            } catch (e: Exception) {
                                val callback = object : NativeReadCallback {
                                    override fun read(offset: Long, buffer: ByteBuffer): Int {
                                    return try {
                                        val start = buffer.position()
                                        physicalDriver.read(offset, buffer)
                                        buffer.position() - start
                                    } catch (e: Exception) {
                                        Log.e("MainViewModel", "Error reading from physical driver", e)
                                        -1
                                    }
                                }
                                }

                                val fsHandle = RustNative.mountFs(localHandle, callback, volSize)
                                if (fsHandle > 0) {
                                    RustFileSystem(fsHandle, context.getString(R.string.root_title))
                                } else {
                                    throw IOException(context.getString(R.string.error_fs_detection))
                                }
                            }

                            activeFileSystem = fs
                            SessionManager.activeFileSystem = fs
                            _connectionResult.emit(ConnectionResult.Success)
                            success = true
                            activeDevice = selected
                            break
                        } catch (e: Exception) {
                            lastError = e.message ?: "Unknown error"
                            localHandle?.let { RustNative.close(it) }
                            rustHandle = null
                        }
                    }
                    if (success) break
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

    fun listFiles(dir: UsbFile): Array<UsbFile> {
        return try {
            dir.listFiles()
        } catch (_: IOException) {
            emptyArray()
        }
    }

    private fun closeConnection() {
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

    private fun readBytes(driver: BlockDeviceDriver, offset: Long, size: Int): ByteArray {
        val buffer = ByteBuffer.allocate(size)
        driver.read(offset, buffer)
        return buffer.array()
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

    private fun isAllZeros(bytes: ByteArray): Boolean {
        val checkLen = minOf(bytes.size, 512)
        for (i in 0 until checkLen) {
            if (bytes[i] != 0.toByte()) return false
        }
        return true
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

