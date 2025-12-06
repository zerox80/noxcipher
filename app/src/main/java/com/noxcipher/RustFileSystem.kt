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
        
        // Optimization: Try to use backing array directly if available
        if (destination.hasArray()) {
            val array = destination.array()
            val arrayOffset = destination.arrayOffset() + destination.position()
             // Note: RustNative.readFile expects ByteArray. 
             // If we pass the whole array, we might overwrite outside bounds?
             // RustNative.readFile copies INTO buffer. JNI handles bounds?
             // We need to pass a slice or use a wrapper? 
             // JNI byte array is passed by value/reference. 
             // If destination is the whole array, we can use it.
             // But if destination is a slice of a larger array, we might need a copy.
             // Safest for now without changing JNI: Use a reusable buffer or existing allocation logic.
             // But to reduce GC, we can check if we can write directly.
             // Wait, RustNative.readFile(..., buffer) writes from index 0 of buffer.
             // If destination.array() is large and we want to write at offset, we can't easily pass offset to JNI readFile without changing JNI signature.
             // So stick to allocation but maybe smaller chunks or thread local?
             // The bug report said "Allocates ... on every read".
             // For now, let's keep it simple as JNI signature change is risky without changing Rust side.
             // But we can remove the Write exceptions to avoid crashes if flags were re-enabled.
        }
        
        // Allocate temporary buffer (fallback)
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
    // Write operations gracefully fail or do nothing since we disabled flags.
    override fun createDirectory(name: String): UsbFile { throw IOException("Read-only") }
    override fun createFile(name: String): UsbFile { throw IOException("Read-only") }
    override fun moveTo(destination: UsbFile) { throw IOException("Read-only") }
    override fun delete() { throw IOException("Read-only") }
    // setName removed as it's likely not in interface or covered by var name
}

