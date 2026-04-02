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

    // Bug #10 fix: report a non-zero capacity so the system doesn't refuse file operations.
    // Real values require a RustNative.getFsStats() JNI call (not yet implemented).
    override val capacity: Long = Long.MAX_VALUE / 2
    override val occupiedSpace: Long = 0
    override val freeSpace: Long = Long.MAX_VALUE / 2
    override val chunkSize: Int = 512
    override val type: Int = 0 // Changed from String to Int to match interface

    override fun close() {
        RustNative.closeFs(fsHandle)
    }
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
        val files = RustNative.listFiles(fsHandle, path) ?: emptyArray()
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
        
        if (destination.isDirect) {
            val position = destination.position()
            val read = RustNative.readFileDirect(fsHandle, path, offset, destination, position, len)
            if (read < 0) throw IOException("Native read failed")
            if (read > 0) destination.position(position + read.toInt())
            return
        }

        // Optimization: Use backing array if directly accessible and safe
        if (destination.hasArray() && !destination.isReadOnly) {
            val array = destination.array()
            val arrayOffset = destination.arrayOffset() + destination.position()
            val read = RustNative.readFileArray(fsHandle, path, offset, array, arrayOffset, len)
            if (read < 0) throw IOException("Native read failed")
            if (read > 0) destination.position(destination.position() + read.toInt())
            return
        }
        
        // Allocate temporary buffer (fallback)
        val buffer = ByteArray(len)
        // Call native readFile.
        val read = RustNative.readFile(fsHandle, path, offset, buffer)
        if (read < 0) {
            throw IOException("Native read failed")
        }
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
    override fun close() {
        // Bug #6 fix: individual file close must NOT close the entire filesystem handle.
        // RustFileSystem.close() (the FileSystem itself) is the correct owner of fsHandle.
    }
    // Write operations gracefully fail or do nothing since we disabled flags.
    override fun createDirectory(name: String): UsbFile { throw IOException("Read-only") }
    override fun createFile(name: String): UsbFile { throw IOException("Read-only") }
    override fun moveTo(destination: UsbFile) { throw IOException("Read-only") }
    override fun delete() { throw IOException("Read-only") }
    // setName removed as it's likely not in interface or covered by var name
}

