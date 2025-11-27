package com.noxcipher

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

sealed class ConnectionResult {
    object Success : ConnectionResult()
    data class Error(val message: String) : ConnectionResult()
}

class MainViewModel : ViewModel() {

    var activeConnection: UsbDeviceConnection? = null
        private set

    private val _connectionResult = MutableSharedFlow<ConnectionResult>()
    val connectionResult = _connectionResult.asSharedFlow()

    private var connectionJob: Job? = null
    private val connectionMutex = Mutex()

    fun connectDevice(
        usbManager: UsbManager,
        device: UsbDevice,
        password: ByteArray // Changed to ByteArray
    ) {
        // Cancel any existing connection attempt
        connectionJob?.cancel()
        
        connectionJob = viewModelScope.launch(Dispatchers.IO) {
            // Use Mutex to ensure only one connection attempt runs at a time
            // and to protect activeConnection state changes
            connectionMutex.withLock {
                try {
                    // Close previous connection if it's different or we are reconnecting
                    activeConnection?.close()
                    activeConnection = null

                    val connection = usbManager.openDevice(device)
                    if (connection == null) {
                        _connectionResult.emit(ConnectionResult.Error("Failed to open device connection"))
                        password.fill(0) // Clear password
                        return@withLock
                    }

                    activeConnection = connection
                    val fd = connection.fileDescriptor

                    // Call Rust
                    // Use NonCancellable to ensure we don't interrupt the native call in a bad state
                    // or at least ensure we handle the result.
                    val success = withContext(kotlinx.coroutines.NonCancellable) {
                        try {
                            RustNative.unlockVolume(fd, password)
                        } catch (e: Exception) {
                            // Log error but don't emit yet, handle below
                            false
                        } finally {
                            password.fill(0) // Always clear password
                        }
                    }

                    if (success) {
                        _connectionResult.emit(ConnectionResult.Success)
                    } else {
                        _connectionResult.emit(ConnectionResult.Error("Unlock failed"))
                        // Close connection on failure
                        activeConnection?.close()
                        activeConnection = null
                    }

                } catch (e: Exception) {
                    _connectionResult.emit(ConnectionResult.Error("Error: ${e.message}"))
                    activeConnection?.close()
                    activeConnection = null
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        try {
            activeConnection?.close()
        } catch (e: Exception) {
            // Ignore
        }
    }
}
