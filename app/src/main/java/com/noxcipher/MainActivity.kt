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
import androidx.activity.viewModels
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    private lateinit var usbManager: UsbManager
    private lateinit var tvLog: TextView
    
    companion object {
        private const val ACTION_USB_PERMISSION = "com.noxcipher.USB_PERMISSION"
    }
    
    // Use ViewModel to retain connection across config changes
    private val viewModel: MainViewModel by viewModels()

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
                        Toast.makeText(context, context.getString(R.string.toast_permission_granted), Toast.LENGTH_SHORT).show()
                        
                        // Auto-connect if password is available
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

            val etPassword = findViewById<android.widget.EditText>(R.id.etPassword)
            val etPim = findViewById<android.widget.EditText>(R.id.etPim)
            
            val editorListener = android.widget.TextView.OnEditorActionListener { _, actionId, _ ->
                if (actionId == android.view.inputmethod.EditorInfo.IME_ACTION_GO) {
                    listDevices()
                    true
                } else {
                    false
                }
            }
            
            etPassword.setOnEditorActionListener(editorListener)
            etPim.setOnEditorActionListener(editorListener)

            val filter = IntentFilter(ACTION_USB_PERMISSION)
            filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            ContextCompat.registerReceiver(this, usbReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
            log("Receiver registered")

            // Observe ViewModel results
            lifecycleScope.launch {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    viewModel.connectionResult.collect { result ->
                        when (result) {
                            is ConnectionResult.Success -> {
                                findViewById<android.view.View>(R.id.progressBar).visibility = android.view.View.GONE
                                setInputsEnabled(true)
                                log("Unlock successful")
                                val intent = Intent(this@MainActivity, FileBrowserActivity::class.java)
                                startActivity(intent)
                            }
                            is ConnectionResult.Error -> {
                                findViewById<android.view.View>(R.id.progressBar).visibility = android.view.View.GONE
                                setInputsEnabled(true)
                                log(result.message)
                                Toast.makeText(this@MainActivity, result.message, Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            }
            
            // Observe Logs
            lifecycleScope.launch {
                repeatOnLifecycle(Lifecycle.State.STARTED) {
                    viewModel.logs.collect { logs ->
                        log(logs)
                    }
                }
            }

        } catch (e: Exception) {
            Log.e("MainActivity", "Error in onCreate", e)
            Toast.makeText(this, getString(R.string.toast_error_init, e.message), Toast.LENGTH_LONG).show()
        }
    }

    private fun listDevices() {
        val deviceList = usbManager.deviceList
        log("Found ${deviceList.size} devices")
        
        if (deviceList.isEmpty()) {
            Toast.makeText(this, getString(R.string.toast_no_devices), Toast.LENGTH_SHORT).show()
            return
        }

        // Get password once
        val etPassword = findViewById<android.widget.EditText>(R.id.etPassword)
        val passwordText = etPassword.text
        if (passwordText.isNullOrEmpty()) {
            Toast.makeText(this, getString(R.string.toast_password_empty), Toast.LENGTH_SHORT).show()
            return
        }

        // Get PIM
        val etPim = findViewById<android.widget.EditText>(R.id.etPim)
        val pimText = etPim.text.toString()
        val pim = if (pimText.isEmpty()) 0 else pimText.toIntOrNull() ?: 0

        // Break loop after first successful connection attempt to avoid race condition
        // Use manual byte conversion to avoid uncleared ByteBuffer
        // Flag to track if we found any potential device
        var permissionRequested = false
        
        for (device in deviceList.values) {
            log("Device: ${device.deviceName} (Vendor: ${device.vendorId}, Product: ${device.productId})")
            
            if (usbManager.hasPermission(device)) {
                 // Check if native lib is initialized
                if (!RustNative.isInitialized) {
                    Toast.makeText(this, getString(R.string.toast_native_not_init), Toast.LENGTH_LONG).show()
                    return
                }

                // Use UTF-8 encoding for password (standard for Veracrypt)
                val passwordBytes = passwordText.toString().toByteArray(java.nio.charset.StandardCharsets.UTF_8)

                // Try to connect. If successful, we are done.
                // Note: 'connectDevice' launches a coroutine via ViewModel. 
                // We can't easily know if it succeeded immediately here.
                // But typically we only want to try the first valid-looking device or all?
                // Identifying the correct device is hard without user selection.
                // But assuming user plugged in ONE drive, we should try it.
                // If multiple, this loop might trigger multiple connection attempts.
                // For safety, let's try the first one we have permission for.
                
                try {
                    connectDevice(device, passwordBytes, pim)
                    
                    // Clear password bytes (best effort)
                    // Password bytes cleared in ViewModel finally block
                    
                    // Clear UI immediately
                    passwordText.clear()
                    
                    return // Stop after initiating connection to first authorized device
                } catch (e: Exception) {
                    log("Failed to start connection: ${e.message}")
                }
            } else if (!permissionRequested) {
                // Request permission for the first unauthorized device we see, but continue checking others
                requestPermission(device)
                permissionRequested = true
            }
        }
        
        if (!permissionRequested) {
             // If we are here, we looped all devices. None had permission (or we requested it), or connection failed.
             log("No suitable device connected or permission requested.")
        }
    }

    private fun requestPermission(device: UsbDevice) {
        val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION), PendingIntent.FLAG_IMMUTABLE)
        usbManager.requestPermission(device, permissionIntent)
    }

    private fun connectDevice(device: UsbDevice, passwordBytes: ByteArray, pim: Int) {
        log("Connecting to ${device.deviceName}...")
        findViewById<android.view.View>(R.id.progressBar).visibility = android.view.View.VISIBLE
        setInputsEnabled(false)
        // ViewModel handles device selection internally using libaums
        viewModel.connectDevice(usbManager, passwordBytes, pim, device)
    }

    private fun setInputsEnabled(enabled: Boolean) {
        findViewById<android.view.View>(R.id.btnListDevices).isEnabled = enabled
        findViewById<android.view.View>(R.id.etPassword).isEnabled = enabled
        findViewById<android.view.View>(R.id.etPim).isEnabled = enabled
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
