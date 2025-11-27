package com.noxcipher

import android.content.Intent
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.StandardCharsets

class FileBrowserActivity : AppCompatActivity() {

    private lateinit var lvFiles: ListView
    private var currentDialog: androidx.appcompat.app.AlertDialog? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_browser)
        lvFiles = findViewById(R.id.lvFiles)

        loadFiles()
    }

    private fun loadFiles() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // List files from root
                val files = try {
                    RustNative.listFiles("/")
                } catch (e: Exception) {
                    // Handle process death/restoration where Rust state is lost
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@FileBrowserActivity, "Session expired or error: ${e.message}", Toast.LENGTH_LONG).show()
                        // Redirect to Login
                        val intent = Intent(this@FileBrowserActivity, MainActivity::class.java)
                        intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
                        startActivity(intent)
                        finish()
                    }
                    return@launch
                }
                
                withContext(Dispatchers.Main) {
                    val adapter = ArrayAdapter(this@FileBrowserActivity, android.R.layout.simple_list_item_1, files)
                    lvFiles.adapter = adapter

                    lvFiles.setOnItemClickListener { _, _, position, _ ->
                        val fileName = files[position]
                        readFile(fileName)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileBrowserActivity, "Unexpected error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun readFile(fileName: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Bug 4 Fix: Chunked reading to avoid OOM
                val chunkSize = 8 * 1024 // 8KB chunks
                val maxReadSize = 1024 * 1024 // 1MB limit for display
                val buffer = ByteArray(chunkSize)
                val contentBuilder = java.io.ByteArrayOutputStream()
                
                var totalRead = 0
                var offset = 0L
                var isTruncated = false

                while (totalRead < maxReadSize) {
                    val bytesRead = RustNative.readFile(fileName, offset, buffer)
                    if (bytesRead < 0) throw java.io.IOException("Read failed")
                    if (bytesRead == 0) break // EOF

                    contentBuilder.write(buffer, 0, bytesRead)
                    totalRead += bytesRead
                    offset += bytesRead
                    
                    if (totalRead >= maxReadSize) {
                        isTruncated = true
                        break
                    }
                }
                
                val content = contentBuilder.toByteArray()
                
                // Bug 5 Fix: Better binary detection
                val (text, truncated) = withContext(Dispatchers.Default) {
                    val isText = isText(content)
                    val displayText = if (isText) {
                        String(content, StandardCharsets.UTF_8)
                    } else {
                        val sb = StringBuilder()
                        sb.append("[Binary Data: ${content.size} bytes]\n\nHex Dump (First 512 bytes):\n")
                        toHex(content.take(512).toByteArray(), sb)
                        sb.toString()
                    }
                    Pair(displayText, isTruncated)
                }
                
                withContext(Dispatchers.Main) {
                    showFileContent(fileName, text, truncated)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileBrowserActivity, "Error reading file: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun showFileContent(fileName: String, content: String, isTruncated: Boolean) {
        if (currentDialog?.isShowing == true) {
            currentDialog?.dismiss()
        }

        val scrollView = android.widget.ScrollView(this)
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        
        if (isTruncated) {
            val warning = android.widget.TextView(this).apply {
                text = "WARNING: File content truncated (showing first 1MB)"
                setTextColor(android.graphics.Color.RED)
                setPadding(32, 32, 32, 0)
            }
            container.addView(warning)
        }

        val textView = android.widget.TextView(this).apply {
            text = content
            setPadding(32, 32, 32, 32)
            setTextIsSelectable(true)
        }
        container.addView(textView)
        scrollView.addView(container)

        currentDialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(fileName)
            .setView(scrollView)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun isText(bytes: ByteArray): Boolean {
        // Bug 5 Fix: Improved binary detection
        if (bytes.isEmpty()) return true
        
        // Check for common binary headers (magic numbers)
        // PDF: %PDF
        if (bytes.size >= 4 && bytes[0] == 0x25.toByte() && bytes[1] == 0x50.toByte() && bytes[2] == 0x44.toByte() && bytes[3] == 0x46.toByte()) return false
        // PNG: .PNG
        if (bytes.size >= 4 && bytes[0] == 0x89.toByte() && bytes[1] == 0x50.toByte() && bytes[2] == 0x4E.toByte() && bytes[3] == 0x47.toByte()) return false
        // JPEG: FF D8 FF
        if (bytes.size >= 3 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() && bytes[2] == 0xFF.toByte()) return false

        val limit = minOf(bytes.size, 512)
        var controlChars = 0
        for (i in 0 until limit) {
            val b = bytes[i].toInt() and 0xFF
            if (b == 0) return false // Null byte is definitely binary
            if (b < 32 && b != 9 && b != 10 && b != 13) { // Control chars except tab, LF, CR
                controlChars++
            }
        }
        // If more than 10% are control characters, assume binary
        return controlChars < (limit * 0.1)
    }

    private fun toHex(bytes: ByteArray, sb: StringBuilder) {
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
    }
}
