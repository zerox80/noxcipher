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
    private val isConnecting = AtomicBoolean(false)

    fun connectDevice(
        usbManager: UsbManager,
        device: UsbDevice,
        password: String
    ) {
        if (isConnecting.getAndSet(true)) {
            return // Already connecting
        }

        // Cancel any existing connection attempt
        connectionJob?.cancel()
        
        connectionJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                // Close previous connection if it's different or we are reconnecting
                activeConnection?.close()
                activeConnection = null

                val connection = usbManager.openDevice(device)
                if (connection == null) {
                    _connectionResult.emit(ConnectionResult.Error("Failed to open device connection"))
                    isConnecting.set(false)
                    return@launch
                }

                activeConnection = connection
                val fd = connection.fileDescriptor

                // Call Rust
                val success = try {
                    RustNative.unlockVolume(fd, password)
                } catch (e: Exception) {
                    _connectionResult.emit(ConnectionResult.Error("Unlock Error: ${e.message}"))
                    isConnecting.set(false)
                    return@launch
                }

                if (success) {
                    _connectionResult.emit(ConnectionResult.Success)
                } else {
                    _connectionResult.emit(ConnectionResult.Error("Unlock failed (unknown reason)"))
                }

            } catch (e: Exception) {
                _connectionResult.emit(ConnectionResult.Error("Error: ${e.message}"))
            } finally {
                isConnecting.set(false)
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
