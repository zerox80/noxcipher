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
    private var currentPath = "/"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_browser)
        lvFiles = findViewById(R.id.lvFiles)

        loadFiles()
    }

    override fun onBackPressed() {
        if (currentPath != "/") {
            // Go up
            val parent = java.io.File(currentPath).parent
            currentPath = if (parent == null || parent == "/") "/" else "$parent/"
            loadFiles()
        } else {
            super.onBackPressed()
        }
    }

    private fun loadFiles() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // List files from root
                val files = try {
                    if (!RustNative.isInitialized) throw Exception("Native library not initialized")
                    RustNative.listFiles(currentPath)
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
                        if (fileName.endsWith("/")) {
                            // Directory navigation
                            currentPath = if (currentPath == "/") "/$fileName" else "$currentPath/$fileName".replace("//", "/")
                            // Remove trailing slash for path construction if needed, but Rust might expect it or not.
                            // Let's keep it simple: if we append "dir/", we get "/dir/".
                            // Actually, we should probably clean it up.
                            // If fileName is "dir/", new path is "/dir/".
                            // If we are in "/dir/", and click "subdir/", new path is "/dir/subdir/".
                            // But wait, Rust listFiles takes a path.
                            // If I pass "/dir/", it should work.
                            loadFiles()
                        } else {
                            readFile(fileName)
                        }
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
                    // Construct full path
                    val fullPath = if (currentPath == "/") fileName else "$currentPath$fileName"
                    val bytesRead = RustNative.readFile(fullPath, offset, buffer)
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
                    val isText = FileUtils.isText(content)
                    val displayText = if (isText) {
                        String(content, StandardCharsets.UTF_8)
                    } else {
                        val sb = StringBuilder()
                        sb.append("[Binary Data: ${content.size} bytes]\n\nHex Dump (First 512 bytes):\n")
                        FileUtils.toHex(content.take(512).toByteArray(), sb)
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
                text = "WARNING: File content truncated (showing first 1MB). File is too large to display fully."
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

}
