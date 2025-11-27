package com.noxcipher

import android.content.Intent
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.github.mjdev.libaums.fs.UsbFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

class FileBrowserActivity : AppCompatActivity() {

    private lateinit var lvFiles: ListView
    private var currentDialog: androidx.appcompat.app.AlertDialog? = null
    private var currentDir: UsbFile? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_browser)
        lvFiles = findViewById(R.id.lvFiles)

        val fs = SessionManager.activeFileSystem
        if (fs == null) {
            Toast.makeText(this, "Session expired", Toast.LENGTH_LONG).show()
            finish()
            return
        }
        
        currentDir = fs.rootDirectory
        loadFiles()
    }

    override fun onBackPressed() {
        if (currentDir != null && !currentDir!!.isRoot) {
            // Go up
            currentDir = currentDir!!.parent
            loadFiles()
        } else {
            super.onBackPressed()
        }
    }

    private fun loadFiles() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dir = currentDir ?: return@launch
                val files = dir.listFiles()
                
                // Sort: Directories first, then files
                val sortedFiles = files.sortedWith(compareBy({ !it.isDirectory }, { it.name }))
                
                withContext(Dispatchers.Main) {
                    // Display names
                    val fileNames = sortedFiles.map { if (it.isDirectory) "${it.name}/" else it.name }
                    val adapter = ArrayAdapter(this@FileBrowserActivity, android.R.layout.simple_list_item_1, fileNames)
                    lvFiles.adapter = adapter

                    lvFiles.setOnItemClickListener { _, _, position, _ ->
                        val selectedFile = sortedFiles[position]
                        if (selectedFile.isDirectory) {
                            currentDir = selectedFile
                            loadFiles()
                        } else {
                            readFile(selectedFile)
                        }
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@FileBrowserActivity, "Error listing files: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun readFile(file: UsbFile) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Bug 4 Fix: Chunked reading to avoid OOM
                val maxReadSize = 1024 * 1024 // 1MB limit for display
                val buffer = ByteBuffer.allocate(maxReadSize)
                
                // UsbFile.read takes offset and ByteBuffer
                // We read up to maxReadSize
                val lengthToRead = Math.min(file.length, maxReadSize.toLong()).toInt()
                buffer.limit(lengthToRead)
                
                file.read(0, buffer)
                
                val content = ByteArray(lengthToRead)
                buffer.flip()
                buffer.get(content)
                
                val isTruncated = file.length > maxReadSize
                
                // Bug 5 Fix: Better binary detection
                val (text, truncated) = withContext(Dispatchers.Default) {
                    val isText = FileUtils.isText(content)
                    val displayText = if (isText) {
                        String(content, StandardCharsets.UTF_8)
                    } else {
                        val sb = StringBuilder()
                        sb.append("[Binary Data: ${file.length} bytes]\n\nHex Dump (First 512 bytes):\n")
                        FileUtils.toHex(content.take(512).toByteArray(), sb)
                        sb.toString()
                    }
                    Pair(displayText, isTruncated)
                }
                
                withContext(Dispatchers.Main) {
                    showFileContent(file.name, text, truncated)
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
