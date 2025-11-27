package com.noxcipher

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var usbManager: UsbManager
    private lateinit var tvLog: TextView
    
    companion object {
        private const val ACTION_USB_PERMISSION = "com.noxcipher.USB_PERMISSION"
    }
    
    // Use ViewModel to retain connection across config changes
    private val viewModel: MainViewModel by androidx.activity.viewModels()

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                ACTION_USB_PERMISSION -> {
                    val device: UsbDevice? = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        // Bug 1 Fix: Do not auto-connect as we don't have the password here securely.
                        // The previous code `connectDevice(this)` was also missing the password argument, causing a crash/compilation error.
                        Toast.makeText(context, "Permission granted. Please click 'List Devices' again.", Toast.LENGTH_LONG).show()
                    } else {
                        log("Permission denied for device $device")
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device: UsbDevice? = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    }
                    log("Device detached: ${device?.deviceName}")
                    // Ideally we should close connection here, but ViewModel handles it on cleared or we can trigger it.
                    // For now just log.
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        log("MainActivity onCreate started")
        setContentView(R.layout.activity_main)

        try {
            usbManager = getSystemService(Context.USB_SERVICE) as UsbManager
            tvLog = findViewById(R.id.tvLog)
            log("Views initialized")

            findViewById<Button>(R.id.btnListDevices).setOnClickListener {
                listDevices()
            }

            val filter = IntentFilter(ACTION_USB_PERMISSION)
            filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(usbReceiver, filter)
            }
            log("Receiver registered")

            // Observe ViewModel results
            lifecycleScope.launch {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    viewModel.connectionResult.collect { result ->
                        when (result) {
                            is ConnectionResult.Success -> {
                                log("Unlock successful")
                                val intent = Intent(this@MainActivity, FileBrowserActivity::class.java)
                                startActivity(intent)
                            }
                            is ConnectionResult.Error -> {
                                log(result.message)
                                Toast.makeText(this@MainActivity, result.message, Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            }

        } catch (e: Exception) {
            Log.e("MainActivity", "Error in onCreate", e)
            Toast.makeText(this, "Error initializing app: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun listDevices() {
        val deviceList = usbManager.deviceList
        log("Found ${deviceList.size} devices")
        
        if (deviceList.isEmpty()) {
            Toast.makeText(this, "No USB devices found", Toast.LENGTH_SHORT).show()
            return
        }

        // Get password once
        val etPassword = findViewById<android.widget.EditText>(R.id.etPassword)
        val passwordText = etPassword.text
        if (passwordText.isNullOrEmpty()) {
            Toast.makeText(this, "Password cannot be empty", Toast.LENGTH_SHORT).show()
            return
        }

        // Bug 2 Fix: Break loop after first successful connection attempt to avoid race condition
        // Also Bug 3 Fix: Use manual byte conversion to avoid uncleared ByteBuffer
        for (device in deviceList.values) {
            log("Device: ${device.deviceName} (Vendor: ${device.vendorId}, Product: ${device.productId})")
            
            if (usbManager.hasPermission(device)) {
                // Bug 1 Fix: Check if native lib is initialized
                if (!RustNative.isInitialized) {
                    Toast.makeText(this, "Native library not initialized", Toast.LENGTH_LONG).show()
                    return
                }

                // Bug 3 Fix: Manual conversion to avoid uncleared ByteBuffer
                val passwordBytes = ByteArray(passwordText.length)
                for (i in passwordText.indices) {
                    passwordBytes[i] = passwordText[i].code.toByte()
                }

                connectDevice(device, passwordBytes)
                
                // Clear UI immediately
                passwordText.clear()
                
                // Break after first attempt to avoid cancelling our own job
                break 
            } else {
                requestPermission(device)
                // Don't break here, we might want to request permission for multiple devices? 
                // Or just the first one? Let's stick to first one for simplicity and consistency.
                break
            }
        }
    }

    private fun requestPermission(device: UsbDevice) {
        val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION), PendingIntent.FLAG_IMMUTABLE)
        usbManager.requestPermission(device, permissionIntent)
    }

    private fun connectDevice(device: UsbDevice, passwordBytes: ByteArray) {
        log("Connecting to ${device.deviceName}...")
        viewModel.connectDevice(usbManager, device, passwordBytes)
    }

    private fun log(message: String) {
        Log.d("MainActivity", message)
        runOnUiThread {
            if (this::tvLog.isInitialized) {
                tvLog.append("\n$message")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(usbReceiver)
        } catch (e: IllegalArgumentException) {
            // Receiver not registered, ignore
        }
    }
}
