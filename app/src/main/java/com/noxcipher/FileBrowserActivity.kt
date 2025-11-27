package com.noxcipher

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Bug 8: Check if volume is unlocked (simple check via try/catch on listFiles or shared state)
        // Since we don't have a shared state singleton for "isUnlocked" easily accessible without ViewModel,
        // we can try a quick operation or just rely on loadFiles failing gracefully.
        // Better: Check if we can list files immediately.
        
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
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@FileBrowserActivity, "Not connected or error: ${e.message}", Toast.LENGTH_LONG).show()
                        finish() // Close activity if we can't list files
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
                // Bug 5: Read limit warning
                val readLimit = 4096
                val content = RustNative.readFile(fileName, 0, readLimit)
                
                // Bug 4: UI Freeze - Process text on IO/Default dispatcher
                val (text, isTruncated) = withContext(Dispatchers.Default) {
                    val isText = isText(content)
                    val displayText = if (isText) {
                        String(content, StandardCharsets.UTF_8)
                    } else {
                        "[Binary Data: ${content.size} bytes]\n\nHex Dump (First 512 bytes):\n${toHex(content.take(512).toByteArray())}"
                    }
                    // Check if we likely hit the limit (this is a heuristic, ideally we'd check file size)
                    val truncated = content.size == readLimit
                    Pair(displayText, truncated)
                }
                
                withContext(Dispatchers.Main) {
                    showFileContent(fileName, text, isTruncated)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileBrowserActivity, "Error reading file: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun showFileContent(fileName: String, content: String, isTruncated: Boolean) {
        val scrollView = android.widget.ScrollView(this)
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        
        if (isTruncated) {
            val warning = android.widget.TextView(this).apply {
                text = "WARNING: File content truncated (showing first 4KB)"
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

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(fileName)
            .setView(scrollView)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun isText(bytes: ByteArray): Boolean {
        // Bug 6: Better binary detection
        // Check first 512 bytes for nulls or excessive control characters
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

    private fun toHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
