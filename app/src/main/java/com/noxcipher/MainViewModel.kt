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
                    
                    // Fallback: Manual GPT parsing if no partitions found
                    if (partitions.isEmpty()) {
                        try {
                            // Use reflection to get the raw block device driver from UsbMassStorageDevice
                            // It's usually a private field 'blockDevice'
                            val blockDeviceField = UsbMassStorageDevice::class.java.getDeclaredField("blockDevice")
                            blockDeviceField.isAccessible = true
                            val rawDriver = blockDeviceField.get(device) as me.jahnen.libaums.core.driver.BlockDeviceDriver
                            
                            val manualPartitions = com.noxcipher.util.GptUtils.parseGpt(rawDriver)
                            if (manualPartitions.isNotEmpty()) {
                                partitions = manualPartitions
                            }
                        } catch (e: Exception) {
                            e.printStackTrace()
                        }
                    }

                    if (partitions.isEmpty()) {
                        _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_no_partitions)))
                        return@withLock
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
                            lastError = e.message
                            // Close handle if it was opened but FS failed
                            rustHandle?.let { 
                                RustNative.close(it) 
                                rustHandle = null
                            }
                        }
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
