package com.noxcipher
// Import necessary Android and library classes.
import android.app.Application
import android.content.Context
import android.hardware.usb.UsbManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import me.jahnen.libaums.core.UsbMassStorageDevice
import me.jahnen.libaums.core.fs.FileSystem
import me.jahnen.libaums.core.fs.FileSystemFactory
import me.jahnen.libaums.core.fs.UsbFile
import me.jahnen.libaums.core.partition.PartitionTableEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.IOException
import java.nio.ByteBuffer

// Sealed class representing the result of a connection attempt.
sealed class ConnectionResult {
    // Represents a successful connection.
    object Success : ConnectionResult()
    // Represents a failed connection with an error message.
    data class Error(val message: String) : ConnectionResult()
}

// ViewModel for managing the main activity's data and business logic.
class MainViewModel(application: Application) : AndroidViewModel(application) {

    // Application context.
    private val context: Context = application.applicationContext
    
    // The currently active file system (if mounted).
    var activeFileSystem: FileSystem? = null
        private set
    
    // The currently connected USB device.
    private var activeDevice: UsbMassStorageDevice? = null
    // Handle to the native Rust volume object.
    private var rustHandle: Long? = null

    // SharedFlow to emit connection results to the UI.
    private val _connectionResult = MutableSharedFlow<ConnectionResult>()
    val connectionResult = _connectionResult.asSharedFlow()

    // Job for the current connection attempt.
    private var connectionJob: Job? = null
    // Mutex to ensure only one connection attempt runs at a time.
    private val connectionMutex = Mutex()

    // SharedFlow to emit logs to the UI.
    private val _logs = MutableSharedFlow<String>()
    val logs = _logs.asSharedFlow()

    // Function to connect to a USB device and mount the encrypted volume.
    fun connectDevice(
        usbManager: UsbManager, // Kept for compatibility if needed, but libaums handles it
        password: ByteArray,
        pim: Int,
        protectionPassword: ByteArray? = null,
        protectionPim: Int = 0
    ) {
        // Cancel any existing connection job.
        connectionJob?.cancel()
        
        // Launch a new coroutine on the IO dispatcher.
        connectionJob = viewModelScope.launch(Dispatchers.IO) {
            // Acquire the mutex to ensure exclusive access.
            connectionMutex.withLock {
                try {
                    // Close any existing connection first.
                    closeConnection()
                    
                    // Get list of connected mass storage devices.
                    val devices = UsbMassStorageDevice.getMassStorageDevices(context)
                    if (devices.isEmpty()) {
                        // Emit error if no devices found.
                        _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_no_mass_storage)))
                        return@withLock
                    }
                    
                    // Select first device.
                    val device = devices[0]
                    // Initialize the device.
                    device.init()
                    activeDevice = device
                    
                    // Try to get partitions from libaums.
                    // We cast to BlockDeviceDriver list because Partition implements it (usually)
                    // or we map it if needed. In 0.10.0 Partition implements BlockDeviceDriver.
                    var partitions: List<me.jahnen.libaums.core.driver.BlockDeviceDriver> = device.partitions
                    
                    var rawDriver: me.jahnen.libaums.core.driver.BlockDeviceDriver? = null
                    
                    // Fallback: Manual GPT/MBR parsing if no partitions found.
                    if (partitions.isEmpty()) {
                        val debugSb = StringBuilder()
                        
                        try {
                            // blockDevice field is missing, try to create ScsiBlockDevice manually.
                            // 1. Get UsbCommunication via reflection.
                            val commField = UsbMassStorageDevice::class.java.getDeclaredField("usbCommunication")
                            commField.isAccessible = true
                            val comm = commField.get(device)
                            
                            if (comm != null) {
                                // 2. Instantiate ScsiBlockDevice via reflection.
                                try {
                                    val scsiClass = Class.forName("me.jahnen.libaums.core.driver.scsi.ScsiBlockDevice")
                                    // Try to find constructor that takes UsbCommunication.
                                    val constructors = scsiClass.constructors
                                    var constructor = constructors.find { 
                                        it.parameterTypes.size == 1 && 
                                        it.parameterTypes[0].isAssignableFrom(comm.javaClass) 
                                    }
                                    
                                    if (constructor == null) {
                                        // Try constructor with more args if single-arg one not found.
                                         constructor = constructors.find { 
                                            it.parameterTypes.isNotEmpty() && 
                                            it.parameterTypes[0].isAssignableFrom(comm.javaClass) 
                                        }
                                    }
                                    
                                    if (constructor != null) {
                                        val args = arrayOfNulls<Any>(constructor.parameterCount)
                                        args[0] = comm
                                        
                                        // Fill other args with defaults.
                                        val params = constructor.parameterTypes
                                        for (i in 1 until params.size) {
                                            if (params[i] == Byte::class.javaPrimitiveType || params[i] == Byte::class.java) {
                                                args[i] = 0.toByte()
                                            } else if (params[i] == Int::class.javaPrimitiveType || params[i] == Int::class.java) {
                                                args[i] = 0
                                            } else if (params[i] == Long::class.javaPrimitiveType || params[i] == Long::class.java) {
                                                args[i] = 0L
                                            } else if (params[i] == Boolean::class.javaPrimitiveType || params[i] == Boolean::class.java) {
                                                args[i] = false
                                            }
                                        }
                                        
                                        // Create new instance and initialize it.
                                        rawDriver = constructor.newInstance(*args) as me.jahnen.libaums.core.driver.BlockDeviceDriver
                                        rawDriver.init()
                                    } else {
                                        debugSb.append("\nNo suitable ScsiBlockDevice constructor found.")
                                        debugSb.append("\nConstructors: ")
                                        constructors.forEach { c ->
                                            debugSb.append(c.parameterTypes.joinToString { it.simpleName }).append("; ")
                                        }
                                    }
                                } catch (e: ClassNotFoundException) {
                                    debugSb.append("\nScsiBlockDevice class not found.")
                                }
                            } else {
                                debugSb.append("\nUsbCommunication is null.")
                            }
                            
                            if (rawDriver != null) {
                                // Try parsing GPT first.
                                var manualPartitions = com.noxcipher.util.PartitionUtils.parseGpt(rawDriver)
                                if (manualPartitions.isEmpty()) {
                                    // Try parsing MBR if GPT fails.
                                    manualPartitions = com.noxcipher.util.PartitionUtils.parseMbr(rawDriver)
                                }
                                
                                // If manual parsing succeeded, use those partitions.
                                if (manualPartitions.isNotEmpty()) {
                                    partitions = manualPartitions
                                }
                            }
                        } catch (e: Exception) {
                            debugSb.append("\nManual driver creation fail: ${e.javaClass.simpleName} ${e.message}")
                            e.printStackTrace()
                        }
                        
                        // If still no partitions, log debug info and fail.
                        if (partitions.isEmpty()) {
                             val sb = StringBuilder()
                             sb.append("No partitions.")
                             sb.append(debugSb.toString())
                             
                             if (rawDriver != null) {
                                 try {
                                     // Read first sector for debugging.
                                     val debugBuf = ByteBuffer.allocate(512)
                                     rawDriver.read(0, debugBuf)
                                     val bytes = debugBuf.array()
                                     val sig1 = bytes[510]
                                     val sig2 = bytes[511]
                                     val first16 = bytes.take(16).joinToString(" ") { "%02X".format(it) }
                                     sb.append("\nMBR Sig: %02X %02X".format(sig1, sig2))
                                     sb.append("\nStart: ").append(first16)
                                 } catch (e: Exception) {
                                     sb.append("\nRead fail: ${e.message}")
                                 }
                             }
                            _connectionResult.emit(ConnectionResult.Error(sb.toString()))
                            return@withLock
                        }
                    }
                    
                    // Iterate over partitions and try to unlock.
                    var success = false
                    var lastError: String? = null

                    // If no partitions found, try the raw device itself.
                    // UsbMassStorageDevice is not a BlockDeviceDriver, but it has one.
                    // We need to access it. It might be private or accessible via property.
                    // Assuming blockDevice is accessible or we use the rawDriver we created manually if any.
                    
                    val rawTarget = if (partitions.isEmpty()) {
                         // If we created a manual rawDriver, use it.
                         // Otherwise try to get from device.
                         // Note: libaums UsbMassStorageDevice might not expose blockDevice publicly in all versions.
                         // But we can try.
                         // For now, let's assume we can use the manual 'rawDriver' if partitions is empty.
                         // If rawDriver is null, we can't do much.
                         if (rawDriver != null) listOf(rawDriver) else emptyList()
                    } else {
                        emptyList<me.jahnen.libaums.core.driver.BlockDeviceDriver>()
                    }
                    
                    // Determine targets to try: partitions or raw device.
                    val targets = if (partitions.isNotEmpty()) partitions else rawTarget

                    for (partition in targets) {
                        try {
                            val physicalDriver = partition
                            
                            // We need to try 3 candidates for the volume header:
                            // 1. Primary Header (Offset 0)
                            // 2. Backup Header (Offset VolumeSize - 128KB)
                            // 3. Hidden Volume Header (Offset VolumeSize - 64KB)
                            // VeraCrypt:
                            // Primary: 0
                            // Backup: VolumeSize - 131072 (128KB)
                            // Hidden: VolumeSize - 65536 (64KB)
                            
                            // Get volume size.
                            // libaums BlockDeviceDriver has `blocks` and `blockSize`.
                            // But `blocks` might be 0 for some raw devices.
                            val volSize = try {
                                physicalDriver.blocks.toLong() * physicalDriver.blockSize
                            } catch (e: Exception) {
                                0L
                            }
                            
                            // Prepare list of header candidates.
                            val candidates = mutableListOf<Pair<Long, String>>()
                            candidates.add(0L to "Primary")
                            candidates.add(65536L to "Hidden") // This seems to be a check for hidden volume at start? Standard hidden volume header is at 64KB.
                            
                            if (volSize > 131072) {
                                candidates.add((volSize - 131072) to "Backup")
                                candidates.add((volSize - 65536) to "Backup Hidden")
                            }
                            
                            // Get partition offset for XTS tweak.
                            // For standard VeraCrypt volumes (even on partitions), the XTS tweak is relative to the start of the volume (partition).
                            // So we should pass 0 as the partition offset.
                            // The physical offset is only used for System Encryption (boot drive), which we don't support yet.
                            val partitionOffset = 0L
                            
                            var handle: Long? = null
                            
                            // Try each candidate header.
                            var primaryError: String? = null
                            
                            for ((offset, type) in candidates) {
                                try {
                                    _logs.emit("Checking ${type} header at offset $offset...")
                                    
                                    // Read 128KB buffer to cover potential header locations.
                                    val headerBuffer = ByteBuffer.allocate(131072) 
                                    
                                    physicalDriver.read(offset, headerBuffer)
                                    val headerBytes = headerBuffer.array() // Pass full buffer.
                                    
                                    // Log partition info for debugging
                                    if (type == "Primary") {
                                        val sizeMb = volSize / (1024 * 1024)
                                        val hexStart = headerBytes.take(16).joinToString(" ") { "%02X".format(it) }
                                        val asciiStart = headerBytes.take(16).map { if (it in 32..126) it.toInt().toChar() else '.' }.joinToString("")
                                        _logs.emit("Partition Size: ${sizeMb} MB")
                                        _logs.emit("Header [0-16]: $hexStart | $asciiStart")
                                    }

                                    // Optimization 1: Check for all-zero header (Empty/Blank)
                                    if (type == "Primary" && isAllZeros(headerBytes)) {
                                        val msg = "Skipped: Header is all zeros (Empty)"
                                        lastError = msg
                                        _logs.emit(msg)
                                        break
                                    }

                                    // Optimization 2: Check for common filesystem signatures (NTFS, exFAT, FAT)
                                    if (type == "Primary" && isCommonFileSystem(headerBytes)) {
                                        val msg = "Skipped: Detected unencrypted filesystem"
                                        lastError = msg
                                        _logs.emit(msg)
                                        break 
                                    }
                                    
                                    // Attempt to initialize volume with Rust native code.
                                    _logs.emit("Verifying credentials...")
                                    
                                    // Prepare password candidates (Raw + Trimmed)
                                    // Android keyboards often add a trailing space.
                                    val passwordCandidates = mutableListOf<ByteArray>()
                                    passwordCandidates.add(password)
                                    
                                    // Check for trailing space (0x20)
                                    if (password.isNotEmpty() && password.last() == 0x20.toByte()) {
                                        var end = password.size - 1
                                        while (end >= 0 && password[end] == 0x20.toByte()) {
                                            end--
                                        }
                                        val trimmed = password.copyOfRange(0, end + 1)
                                        if (trimmed.isNotEmpty()) {
                                            passwordCandidates.add(trimmed)
                                        }
                                    }

                                    for ((index, pwd) in passwordCandidates.withIndex()) {
                                        if (index > 0) _logs.emit("Trying trimmed password...")
                                        
                                        // DEBUG: Log password hex to verify encoding
                                        val hexPwd = pwd.joinToString("") { "%02X".format(it) }
                                        _logs.emit("Pass Hex: $hexPwd")

                                        handle = RustNative.init(
                                            pwd,
                                            headerBytes,
                                            pim,
                                            partitionOffset,
                                            protectionPassword,
                                            protectionPim,
                                            volSize,
                                            null
                                        )
                                        if (handle != null && handle > 0) {
                                            lastError = "Success ($type)"
                                            _logs.emit("Volume mounted successfully!")
                                            break
                                        }
                                    }
                                    
                                    if (handle != null && handle > 0) {
                                        break
                                    }
                                } catch (e: Exception) {
                                    // Failed this candidate.
                                    val msg = "Failed $type: ${e.message}"
                                    lastError = msg
                                    _logs.emit(msg)
                                    
                                    // Capture primary error specifically.
                                    if (type == "Primary") {
                                        primaryError = msg
                                    }
                                }
                            }

                            // If no valid handle obtained, continue to next partition.
                            if (handle == null || handle <= 0) {
                                // If we had a primary error that indicates a crypto/password failure,
                                // and the last error was an IO error (like MAX RECOVERY ATTEMPTS exceeded from backup),
                                // revert to the primary error as it's more actionable for the user.
                                if (primaryError != null && lastError?.contains("Invalid password") == false && lastError?.contains("MAX RECOVERY") == true) {
                                    lastError = primaryError
                                }
                                continue
                            }
                            
                            rustHandle = handle
                            // Get data offset from Rust (where encrypted data starts).
                            val dataOffset = RustNative.getDataOffset(handle)
                            
                            // 3. Create Veracrypt Wrapper (BlockDeviceDriver).
                            val veracryptDriver = VeracryptBlockDevice(physicalDriver, handle, dataOffset)
                            
                            // 4. Mount Filesystem.
                            // Create a dummy partition entry for libaums.
                            val dummyEntry = PartitionTableEntry(0x0c, 0, 0)
                            var fs: FileSystem? = null
                            
                            try {
                                // Try to create standard file system (FAT32) via libaums.
                                fs = FileSystemFactory.createFileSystem(dummyEntry, veracryptDriver)
                            } catch (e: Exception) {
                                // libaums failed (likely not FAT32), try Rust FS (NTFS/exFAT).
                                val volSize = try {
                                    physicalDriver.blocks * physicalDriver.blockSize
                                } catch (e: Exception) { 0L }

                                // Create callback for Rust to read from the device.
                                val callback = object : NativeReadCallback {
                                    override fun read(offset: Long, length: Int): ByteArray {
                                        val buffer = ByteBuffer.allocate(length)
                                        try {
                                            physicalDriver.read(offset, buffer)
                                            return buffer.array()
                                        } catch (e: Exception) {
                                            e.printStackTrace()
                                            return ByteArray(0)
                                        }
                                    }
                                }

                                // Mount FS via Rust native code.
                                val fsHandle = RustNative.mountFs(handle, callback, volSize)
                                if (fsHandle > 0) {
                                    // Wrap Rust FS handle in a Kotlin FileSystem object.
                                    fs = RustFileSystem(fsHandle, "NoxCipher Volume")
                                } else {
                                    throw e // Re-throw if Rust FS also fails.
                                }
                            }
                            
                            // Set active file system and emit success.
                            activeFileSystem = fs
                            SessionManager.activeFileSystem = fs
                            _connectionResult.emit(ConnectionResult.Success)
                            success = true
                            break
                        } catch (e: Exception) {
                            e.printStackTrace()
                            val msg = e.message ?: "Unknown error"
                            lastError = "Decrypt failed (Handle: $rustHandle): $msg"
                            // Close handle if it was opened but FS failed.
                            rustHandle?.let { 
                                RustNative.close(it) 
                                rustHandle = null
                            }
                        }
                    }

                    // Fetch logs from Rust regardless of success/failure.
                    try {
                        val nativeLogs = RustNative.getLogs()
                        if (nativeLogs.isNotEmpty()) {
                            val logStr = nativeLogs.joinToString("\n")
                            _logs.emit(logStr)
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }

                    // If all attempts failed, emit error.
                    if (!success) {
                         _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_wrong_credentials, lastError ?: "No valid volume found")))
                         closeConnection()
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_generic, e.message)))
                    closeConnection()
                } finally {
                    // Clear password from memory.
                    password.fill(0)
                }
            }
        }
    }
    
    // Function to list files in a directory.
    fun listFiles(dir: UsbFile): Array<UsbFile> {
        return try {
            dir.listFiles()
        } catch (e: IOException) {
            emptyArray()
        }
    }

    // Function to close the connection and release resources.
    private fun closeConnection() {
        try {
            SessionManager.activeFileSystem = null
            activeFileSystem = null
            // Close Rust volume handle.
            rustHandle?.let { RustNative.close(it) }
            rustHandle = null
            // Close USB device.
            activeDevice?.close()
            activeDevice = null
        } catch (e: Exception) {
            // Ignore errors during close.
        }
    }

    // Helper to detect common unencrypted filesystems
    private fun isCommonFileSystem(bytes: ByteArray): Boolean {
        if (bytes.size < 512) return false
        
        // Helper to check ASCII string at offset
        fun hasString(offset: Int, value: String): Boolean {
            if (offset + value.length > bytes.size) return false
            for (i in value.indices) {
                if (bytes[offset + i] != value[i].code.toByte()) return false
            }
            return true
        }

        // NTFS: "NTFS    " at offset 3
        if (hasString(3, "NTFS")) return true
        
        // exFAT: "EXFAT   " at offset 3
        if (hasString(3, "EXFAT")) return true
        
        // FAT32: "FAT32   " at offset 82
        if (hasString(82, "FAT32")) return true
        
        // FAT16: "FAT16   " at offset 54
        if (hasString(54, "FAT16")) return true
        
        return false
    }

    // Helper to check if header is all zeros (first 512 bytes)
    private fun isAllZeros(bytes: ByteArray): Boolean {
        val checkLen = if (bytes.size < 512) bytes.size else 512
        for (i in 0 until checkLen) {
            if (bytes[i] != 0.toByte()) return false
        }
        return true
    }

    // Called when ViewModel is cleared.
    override fun onCleared() {
        super.onCleared()
        closeConnection()
    }
}
