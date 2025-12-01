package com.noxcipher

import me.jahnen.libaums.core.fs.FileSystem
import me.jahnen.libaums.core.fs.UsbFile
import java.nio.ByteBuffer
import java.io.IOException

// Implementation of libaums FileSystem interface backed by Rust native code.
class RustFileSystem(
    private val fsHandle: Long,
    private val label: String
) : FileSystem {
    // Return root directory wrapper.
    override val rootDirectory: UsbFile
        get() = RustUsbFile(fsHandle, "/", true, 0, null)

    // Return volume label.
    override val volumeLabel: String
        get() = label

    // Capacity metrics (placeholders as we don't query them from Rust yet).
    override val capacity: Long = 0 
    override val occupiedSpace: Long = 0 
    override val freeSpace: Long = 0 
    override val chunkSize: Int = 512
    override val type: Int = 0 // Changed from String to Int to match interface
}

// Implementation of libaums UsbFile interface backed by Rust native code.
class RustUsbFile(
    private val fsHandle: Long,
    private val path: String,
    private val isDir: Boolean,
    private val size: Long,
    private val parentDir: UsbFile? // Renamed to avoid conflict
) : UsbFile {
    // Search not implemented.
    override fun search(name: String): UsbFile? { return null } 
    // Directory flag.
    override val isDirectory: Boolean = isDir
    // File name derived from path.
    override var name: String = if (path == "/") "/" else path.substringAfterLast("/")
    // Absolute path.
    override val absolutePath: String = path
    // Parent directory.
    override val parent: UsbFile? = parentDir
    // File size.
    override var length: Long = size
    // Root check.
    override val isRoot: Boolean = path == "/"
    
    // Missing property
    // Missing property
    override fun createdAt(): Long = 0
    override fun lastAccessed(): Long = 0
    override fun lastModified(): Long = 0


    // List files in this directory.
    override fun listFiles(): Array<UsbFile> {
        // Call native listFiles.
        val files = RustNative.listFiles(fsHandle, path)
        // Map RustFile objects to RustUsbFile wrappers.
        return files.map { 
            val childPath = if (path == "/") "/${it.name}" else "$path/${it.name}"
            RustUsbFile(fsHandle, childPath, it.isDir, it.size, this) 
        }.toTypedArray()
    }

    override fun list(): Array<String> {
        return listFiles().map { it.name }.toTypedArray()
    }


    // Read data from file.
    override fun read(offset: Long, destination: ByteBuffer) {
        val len = destination.remaining()
        if (len <= 0) return
        
        // Allocate temporary buffer.
        val buffer = ByteArray(len)
        // Call native readFile.
        val read = RustNative.readFile(fsHandle, path, offset, buffer)
        // Copy read data to destination buffer.
        if (read > 0) {
            destination.put(buffer, 0, read.toInt())
        }
    }
    
    // Write operations are not supported (Read-only).
    override fun write(offset: Long, source: ByteBuffer) {
        throw IOException("Read-only file system")
    }
    
    override fun flush() {}
    override fun close() {}
    override fun createDirectory(name: String): UsbFile { throw IOException("Read-only") }
    override fun createFile(name: String): UsbFile { throw IOException("Read-only") }
    override fun moveTo(destination: UsbFile) { throw IOException("Read-only") }
    override fun delete() { throw IOException("Read-only") }
    // setName removed as it's likely not in interface or covered by var name
}

