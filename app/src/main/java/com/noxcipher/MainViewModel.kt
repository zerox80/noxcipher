package com.noxcipher

import android.app.Application
import android.content.Context
import android.hardware.usb.UsbManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.github.mjdev.libaums.UsbMassStorageDevice
import com.github.mjdev.libaums.fs.FileSystem
import com.github.mjdev.libaums.fs.FileSystemFactory
import com.github.mjdev.libaums.fs.UsbFile
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

                    // We assume the first partition is the Veracrypt volume
                    // In a real app, we might iterate partitions or let user choose.
                    // libaums partitions are BlockDeviceDrivers.
                    val partitions = device.partitions
                    if (partitions.isEmpty()) {
                        _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_no_partitions)))
                        return@withLock
                    }
                    
                    // Get the raw block device driver for the partition
                    // libaums 'Partition' object wraps the driver.
                    // We need to access the BlockDeviceDriver.
                    // Actually, device.partitions returns List<Partition>.
                    // Partition has a 'blockDevice' property which is BlockDeviceDriver.
                    val partition = partitions[0]
                    val physicalDriver = partition
                    
                    // 1. Read Header (first 128KB)
                    // Veracrypt header is in the first 512 bytes, but we read more just in case.
                    val headerSize = 128 * 1024
                    val headerBuffer = ByteBuffer.allocate(headerSize)
                    physicalDriver.read(0, headerBuffer)
                    
                    // 2. Initialize Rust Crypto
                    val headerBytes = headerBuffer.array()
                    val handle = try {
                         // Use provided PIM
                         RustNative.init(password, headerBytes, pim)
                    } catch (e: Exception) {
                        _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_wrong_credentials, e.message)))
                        return@withLock
                    }
                    rustHandle = handle

                    // 3. Create Veracrypt Wrapper
                    val veracryptDriver = VeracryptBlockDevice(physicalDriver, handle)
                    
                    // 4. Mount Filesystem
                    // libaums FileSystemFactory detects FS type from the driver
                    val fs = FileSystemFactory.createFileSystem(null, veracryptDriver)
                    if (fs == null) {
                         _connectionResult.emit(ConnectionResult.Error(context.getString(R.string.error_fs_detection)))
                         return@withLock
                    }
                    
                    activeFileSystem = fs
                    SessionManager.activeFileSystem = fs
                    _connectionResult.emit(ConnectionResult.Success)

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
