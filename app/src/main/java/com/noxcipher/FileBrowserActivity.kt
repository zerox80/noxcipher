package com.noxcipher // Defines the package name for this class

import android.content.Intent // Imports the Intent class for starting activities (though unused here)
import android.os.Bundle // Imports Bundle for passing data between activities/components
import android.widget.ArrayAdapter // Imports ArrayAdapter to adapt a list of objects to views
import android.widget.ListView // Imports ListView to display a scrollable list of items
import android.widget.Toast // Imports Toast for showing short messages to the user
import androidx.appcompat.app.AppCompatActivity // Imports the base class for activities using modern Android features
import androidx.lifecycle.lifecycleScope // Imports lifecycleScope to launch coroutines bound to the activity's lifecycle
import me.jahnen.libaums.core.fs.UsbFile // Imports UsbFile interface from libaums for USB file operations
import kotlinx.coroutines.Dispatchers // Imports Dispatchers to control which thread coroutines run on
import kotlinx.coroutines.launch // Imports launch builder to start a new coroutine
import kotlinx.coroutines.withContext // Imports withContext to switch the context (thread) of a coroutine
import java.nio.ByteBuffer // Imports ByteBuffer for efficient byte handling
import java.nio.charset.StandardCharsets // Imports StandardCharsets for character encoding constants

// Defines the FileBrowserActivity class which inherits from AppCompatActivity
class FileBrowserActivity : AppCompatActivity() {

    private lateinit var lvFiles: ListView // Declares a ListView variable to display files, initialized later
    private var currentDialog: androidx.appcompat.app.AlertDialog? = null // Declares a nullable variable to hold the currently shown dialog
    private var currentDir: UsbFile? = null // Declares a nullable variable to hold the current directory being viewed

    // Called when the activity is first created
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState) // Calls the superclass implementation of onCreate
        setContentView(R.layout.activity_file_browser) // Sets the UI layout for this activity from the XML resource
        lvFiles = findViewById(R.id.lvFiles) // Finds the ListView in the layout by its ID and assigns it to lvFiles

        val fs = SessionManager.activeFileSystem // Retrieves the active file system from the SessionManager
        // Checks if the file system is null (session expired or not set)
        if (fs == null) {
            // Shows a toast message indicating the session has expired
            Toast.makeText(this, getString(R.string.toast_session_expired), Toast.LENGTH_LONG).show()
            finish() // Closes the activity
            return // Returns from the method to stop further execution
        }
        
        currentDir = fs.rootDirectory // Sets the current directory to the root directory of the file system
        loadFiles() // Calls the function to load and display files in the current directory
    }

    // Called when the user presses the back button
    override fun onBackPressed() {
        // Checks if the current directory is not null and is not the root directory
        if (currentDir != null && !currentDir!!.isRoot) {
            // Go up one level in the directory hierarchy
            currentDir = currentDir!!.parent // Sets currentDir to its parent directory
            loadFiles() // Reloads the file list for the new current directory
        } else {
            super.onBackPressed() // If at root or null, performs the default back action (close activity)
        }
    }

    // Function to load files from the current directory and display them
    private fun loadFiles() {
        // Launches a coroutine in the IO dispatcher for background work
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Gets the current directory, or returns if it is null
                val dir = currentDir ?: return@launch
                val files = dir.listFiles() // Lists all files and directories in the current directory
                
                // Sort: Directories first, then files
                // Sorts the files: directories appear before files, then sorted by name
                val sortedFiles = files.sortedWith(compareBy({ !it.isDirectory }, { it.name }))
                
                // Switches to the Main (UI) thread to update the UI
                withContext(Dispatchers.Main) {
                    // Display names
                    // Maps the file objects to their names, appending "/" to directory names
                    val fileNames = sortedFiles.map { if (it.isDirectory) "${it.name}/" else it.name }
                    // Creates an ArrayAdapter to bind the file names to the ListView
                    val adapter = ArrayAdapter(this@FileBrowserActivity, android.R.layout.simple_list_item_1, fileNames)
                    lvFiles.adapter = adapter // Sets the adapter to the ListView

                    // Sets a click listener for items in the ListView
                    lvFiles.setOnItemClickListener { _, _, position, _ ->
                        val selectedFile = sortedFiles[position] // Gets the file object corresponding to the clicked position
                        // Checks if the selected item is a directory
                        if (selectedFile.isDirectory) {
                            currentDir = selectedFile // Updates the current directory to the selected one
                            loadFiles() // Loads the contents of the new directory
                        } else {
                            readFile(selectedFile) // If it's a file, calls readFile to read and display its content
                        }
                    }
                }
            } catch (e: Exception) { // Catches any exceptions that occur during file listing
                // Switches to the Main thread to show an error message
                withContext(Dispatchers.Main) {
                    // Shows a toast with the error message
                    Toast.makeText(this@FileBrowserActivity, getString(R.string.toast_error_listing, e.message), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    // Function to read the content of a selected file
    private fun readFile(file: UsbFile) {
        // Launches a coroutine in the IO dispatcher
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Chunked reading to avoid OOM (Out Of Memory)
                val maxReadSize = 1024 * 1024 // Sets a 1MB limit for the amount of data to read/display
                val buffer = ByteBuffer.allocate(maxReadSize) // Allocates a ByteBuffer of the specified size
                
                // UsbFile.read takes offset and ByteBuffer
                // We read up to maxReadSize
                // Calculates the number of bytes to read: minimum of file length and maxReadSize
                val lengthToRead = Math.min(file.length, maxReadSize.toLong()).toInt()
                buffer.limit(lengthToRead) // Sets the limit of the buffer to the calculated length
                
                file.read(0, buffer) // Reads data from the file into the buffer starting at offset 0
                
                val content = ByteArray(lengthToRead) // Creates a ByteArray to hold the read data
                buffer.flip() // Flips the buffer to prepare it for reading (from buffer to array)
                buffer.get(content) // Transfers bytes from the buffer into the content array
                
                val isTruncated = file.length > maxReadSize // Checks if the file is larger than the read limit
                
                // Better binary detection
                // Switches to the Default dispatcher for CPU-intensive work (text detection/formatting)
                val (text, truncated) = withContext(Dispatchers.Default) {
                    val isText = FileUtils.isText(content) // Checks if the content is text using a utility function
                    // Determines the text to display
                    val displayText = if (isText) {
                        String(content, StandardCharsets.UTF_8) // Converts bytes to a UTF-8 string if it is text
                    } else {
                        val sb = StringBuilder() // Creates a StringBuilder for hex output
                        // Appends a template string indicating binary content and file size
                        sb.append(getString(R.string.binary_display_template, file.length))
                        // Converts the first 512 bytes to a hex string representation
                        FileUtils.toHex(content.take(512).toByteArray(), sb)
                        sb.toString() // Returns the resulting string
                    }
                    Pair(displayText, isTruncated) // Returns a pair containing the display text and truncation status
                }
                
                // Switches to the Main thread to show the file content
                withContext(Dispatchers.Main) {
                    showFileContent(file.name, text, truncated) // Calls showFileContent to display the data in a dialog
                }
            } catch (e: Exception) { // Catches any exceptions during file reading
                // Switches to the Main thread to show an error message
                withContext(Dispatchers.Main) {
                    // Shows a toast with the error message
                    Toast.makeText(this@FileBrowserActivity, getString(R.string.toast_error_reading, e.message), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    // Function to display the file content in a dialog
    private fun showFileContent(fileName: String, content: String, isTruncated: Boolean) {
        // Checks if a dialog is currently showing and dismisses it
        if (currentDialog?.isShowing == true) {
            currentDialog?.dismiss()
        }

        val scrollView = android.widget.ScrollView(this) // Creates a ScrollView to allow scrolling of content
        // Creates a LinearLayout to hold the content views
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL // Sets orientation to vertical
        }
        
        // If the content was truncated, adds a warning message
        if (isTruncated) {
            val warning = android.widget.TextView(this).apply {
                text = getString(R.string.warning_truncated) // Sets the warning text
                setTextColor(android.graphics.Color.RED) // Sets the text color to red
                setPadding(32, 32, 32, 0) // Sets padding
            }
            container.addView(warning) // Adds the warning view to the container
        }

        // Creates a TextView to display the file content
        val textView = android.widget.TextView(this).apply {
            text = content // Sets the content text
            setPadding(32, 32, 32, 32) // Sets padding
            setTextIsSelectable(true) // Allows the user to select and copy text
        }
        container.addView(textView) // Adds the text view to the container
        scrollView.addView(container) // Adds the container to the scroll view

        // Builds and shows an AlertDialog with the content
        currentDialog = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(fileName) // Sets the dialog title to the file name
            .setView(scrollView) // Sets the custom view (scroll view)
            .setPositiveButton(R.string.dialog_close, null) // Adds a close button
            .show() // Shows the dialog
    }

}
