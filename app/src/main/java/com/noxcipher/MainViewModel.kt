package com.noxcipher

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

    private var connectionJob: Job? = null
    private val connectionMutex = Mutex()

    private val _logs = MutableSharedFlow<String>()
    val logs = _logs.asSharedFlow()

    fun connectDevice(
        usbManager: UsbManager, // Kept for compatibility if needed, but libaums handles it
        password: ByteArray,
        pim: Int
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

                    // Select first device
                    val device = devices[0]
                    device.init()
                    activeDevice = device

                    // Try to get partitions from libaums
                    // We cast to BlockDeviceDriver list because Partition implements it (usually)
                    // or we map it if needed. In 0.10.0 Partition implements BlockDeviceDriver.
                    var partitions: List<me.jahnen.libaums.core.driver.BlockDeviceDriver> = device.partitions
                    
                    // Fallback: Manual GPT/MBR parsing if no partitions found
                    if (partitions.isEmpty()) {
                        var rawDriver: me.jahnen.libaums.core.driver.BlockDeviceDriver? = null
                        val debugSb = StringBuilder()
                        
                        try {
                            // blockDevice field is missing, try to create ScsiBlockDevice manually
                            // 1. Get UsbCommunication
                            val commField = UsbMassStorageDevice::class.java.getDeclaredField("usbCommunication")
                            commField.isAccessible = true
                            val comm = commField.get(device)
                            
                            if (comm != null) {
                                // 2. Instantiate ScsiBlockDevice
                                try {
                                    val scsiClass = Class.forName("me.jahnen.libaums.core.driver.scsi.ScsiBlockDevice")
                                    // Try to find constructor that takes UsbCommunication
                                    val constructors = scsiClass.constructors
                                    var constructor = constructors.find { 
                                        it.parameterTypes.size == 1 && 
                                        it.parameterTypes[0].isAssignableFrom(comm.javaClass) 
                                    }
                                    
                                    if (constructor == null) {
                                        // Try constructor with 2 args (UsbCommunication, listener/partitionTable?)
                                        // Or maybe it takes the interface?
                                        // Let's just try to find one that takes UsbCommunication as first arg
                                         constructor = constructors.find { 
                                            it.parameterTypes.isNotEmpty() && 
                                            it.parameterTypes[0].isAssignableFrom(comm.javaClass) 
                                        }
                                    }

                                    if (constructor != null) {
                                        val args = arrayOfNulls<Any>(constructor.parameterCount)
                                        args[0] = comm
                                        
                                        // Fill other args
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
                                // Try GPT first
                                var manualPartitions = com.noxcipher.util.PartitionUtils.parseGpt(rawDriver)
                                if (manualPartitions.isEmpty()) {
                                    // Try MBR
                                    manualPartitions = com.noxcipher.util.PartitionUtils.parseMbr(rawDriver)
                                }

                                if (manualPartitions.isNotEmpty()) {
                                    partitions = manualPartitions
                                }
                            }
                        } catch (e: Exception) {
                            debugSb.append("\nManual driver creation fail: ${e.javaClass.simpleName} ${e.message}")
                            e.printStackTrace()
                        }

                        if (partitions.isEmpty()) {
                             val sb = StringBuilder()
                             sb.append("No partitions.")
                             sb.append(debugSb.toString())
                             
                             if (rawDriver != null) {
                                 try {
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
                    
                    // Iterate over partitions and try to unlock
                    var success = false
                    var lastError: String? = null

                    for (partition in partitions) {
                        try {
                            val physicalDriver = partition
                            
                            // 1. Read Header (first 128KB)
                            val headerSize = 128 * 1024
                            val headerBuffer = ByteBuffer.allocate(headerSize)
                            physicalDriver.read(0, headerBuffer)
                            
                            // 2. Initialize Rust Crypto
                            val headerBytes = headerBuffer.array()
                            val handle = try {
                                 RustNative.init(password, headerBytes, pim)
                            } catch (e: Exception) {
                                // Wrong password or not a veracrypt partition
                                lastError = e.message
                                continue
                            }
                            rustHandle = handle
                            // Log handle
                            lastError = "Handle: $handle"
        
                            // 3. Create Veracrypt Wrapper
                            val veracryptDriver = VeracryptBlockDevice(physicalDriver, handle)
                            
                            // 4. Mount Filesystem
                            val dummyEntry = PartitionTableEntry(0x0c, 0, 0)
                            val fs = FileSystemFactory.createFileSystem(dummyEntry, veracryptDriver)
                            
                            activeFileSystem = fs
                            SessionManager.activeFileSystem = fs
                            _connectionResult.emit(ConnectionResult.Success)
                            success = true
                            break
                        } catch (e: Exception) {
                            e.printStackTrace()
                            val msg = e.message ?: "Unknown error"
                            lastError = "Decrypt failed (Handle: $rustHandle): $msg"
                            // Close handle if it was opened but FS failed
                            rustHandle?.let { 
                                RustNative.close(it) 
                                rustHandle = null
                            }
                        }
                    }

                    // Fetch logs from Rust regardless of success/failure
                    try {
                        val nativeLogs = RustNative.getLogs()
                        if (nativeLogs.isNotEmpty()) {
                            val logStr = nativeLogs.joinToString("\n")
                            _logs.emit(logStr)
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }

                    if (!success) {
                         _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_wrong_credentials, lastError ?: "No valid volume found")))
                         closeConnection()
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_generic, e.message)))
                    closeConnection()
                } finally {
                    password.fill(0)
                }
            }
        }
    }
    
    fun listFiles(dir: UsbFile): Array<UsbFile> {
        return try {
            dir.listFiles()
        } catch (e: IOException) {
            emptyArray()
        }
    }

    private fun closeConnection() {
        try {
            SessionManager.activeFileSystem = null
            activeFileSystem = null
            rustHandle?.let { RustNative.close(it) }
            rustHandle = null
            activeDevice?.close()
            activeDevice = null
        } catch (e: Exception) {
            // Ignore
        }
    }

    override fun onCleared() {
        super.onCleared()
        closeConnection()
    }
}
