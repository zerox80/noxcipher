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
                    // Bug #4 fix: close stale handles when USB device is removed
                    viewModel.closeConnection()
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

        // Flag to track if we found any potential device
        var permissionRequested = false

        for (device in deviceList.values) {
            log("Device: ${device.deviceName} (Vendor: ${device.vendorId}, Product: ${device.productId})")

            if (!usbManager.hasPermission(device)) {
                // Request permission for the first unauthorized device we see, but continue checking others
                if (!permissionRequested) {
                    requestPermission(device)
                    permissionRequested = true
                }
            }
        }

        val authorizedDevices = deviceList.values.filter { usbManager.hasPermission(it) }

        if (authorizedDevices.isNotEmpty()) {
            if (!RustNative.isInitialized) {
                Toast.makeText(this, getString(R.string.toast_native_not_init), Toast.LENGTH_LONG).show()
                return
            }

            val passwordBytes = ByteArray(passwordText.length)
            for (i in passwordText.indices) {
                passwordBytes[i] = passwordText[i].code.toByte()
                passwordText.replace(i, i + 1, "0")
            }
            passwordText.clear()

            // Pass null to let ViewModel scan all available devices
            // Note: passwordBytes will be cleared inside the ViewModel once used
            connectDevice(null, passwordBytes, pim)

            return
        }

        if (!permissionRequested && authorizedDevices.isEmpty()) {
            if (!permissionRequested) log("No suitable device connected or permission requested.")
        }
    }

    private fun requestPermission(device: UsbDevice) {
        val intent = Intent(ACTION_USB_PERMISSION).setPackage(packageName)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
        val permissionIntent = PendingIntent.getBroadcast(this, 0, intent, flags)
        usbManager.requestPermission(device, permissionIntent)
    }

    private fun connectDevice(device: UsbDevice?, passwordBytes: ByteArray, pim: Int) {
        val deviceName = device?.deviceName ?: "all devices"
        log("Connecting to $deviceName...")
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
