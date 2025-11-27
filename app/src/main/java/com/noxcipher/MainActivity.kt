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
                    val device: UsbDevice? = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        device?.apply {
                            connectDevice(this)
                        }
                    } else {
                        log("Permission denied for device $device")
                    }
                }
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val device: UsbDevice? = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
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
            registerReceiver(usbReceiver, filter)
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

        for (device in deviceList.values) {
            log("Device: ${device.deviceName} (Vendor: ${device.vendorId}, Product: ${device.productId})")
            if (usbManager.hasPermission(device)) {
                connectDevice(device)
            } else {
                requestPermission(device)
            }
        }
    }

    private fun requestPermission(device: UsbDevice) {
        val permissionIntent = PendingIntent.getBroadcast(this, 0, Intent(ACTION_USB_PERMISSION), PendingIntent.FLAG_IMMUTABLE)
        usbManager.requestPermission(device, permissionIntent)
    }

    private fun connectDevice(device: UsbDevice) {
        log("Connecting to ${device.deviceName}...")
        val passwordStr = findViewById<android.widget.EditText>(R.id.etPassword).text.toString()
        if (passwordStr.isEmpty()) {
            Toast.makeText(this, "Password cannot be empty", Toast.LENGTH_SHORT).show()
            return
        }
        val passwordBytes = passwordStr.toByteArray(Charsets.UTF_8)
        viewModel.connectDevice(usbManager, device, passwordBytes)
        // Clear local reference, though String remains until GC. 
        // Ideally we'd use CharSequence or Editable to avoid String creation if possible, 
        // but EditText.text.toString() creates it anyway.
        // We can at least clear the ByteArray we created.
        // Note: ViewModel clears it too, but this is a separate copy if we passed a copy. 
        // In Kotlin, toByteArray() creates a new array. ViewModel receives that array.
        // So we don't need to clear it here if we pass it directly.
        // Wait, we passed `passwordBytes`. ViewModel clears it.
        // But `passwordStr` is still in memory. 
        // To be truly secure, we should avoid `toString()` and use `Chars` but Android EditText makes it hard.
        // For now, the fix is ensuring the ByteArray passed to JNI is cleared, which ViewModel does.
        // We just added validation here.
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
        unregisterReceiver(usbReceiver)
    }
}
