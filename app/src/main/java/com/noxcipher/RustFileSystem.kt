package com.noxcipher

import me.jahnen.libaums.core.fs.FileSystem
import me.jahnen.libaums.core.fs.UsbFile
import java.nio.ByteBuffer
import java.io.IOException

class RustFileSystem(
    private val fsHandle: Long,
    private val label: String
) : FileSystem {
    override val rootDirectory: UsbFile
        get() = RustUsbFile(fsHandle, "/", true, 0, null)

    override val volumeLabel: String
        get() = label

    override val capacity: Long = 0 
    override val occupiedSpace: Long = 0 
    override val freeSpace: Long = 0 
    override val chunkSize: Int = 512
    override val type: String = "RustFS"
}

class RustUsbFile(
    private val fsHandle: Long,
    private val path: String,
    private val isDir: Boolean,
    private val size: Long,
    private val parent: UsbFile?
) : UsbFile {
    override fun search(name: String): UsbFile? { return null } 
    override val isDirectory: Boolean = isDir
    override val name: String = if (path == "/") "/" else path.substringAfterLast("/")
    override val absolutePath: String = path
    override val parent: UsbFile? = parent
    override val length: Long = size
    override val isRoot: Boolean = path == "/"

    override fun listFiles(): Array<UsbFile> {
        val files = RustNative.listFiles(fsHandle, path)
        return files.map { 
            val childPath = if (path == "/") "/${it.name}" else "$path/${it.name}"
            RustUsbFile(fsHandle, childPath, it.isDir, it.size, this) 
        }.toTypedArray()
    }

    override fun read(offset: Long, destination: ByteBuffer) {
        val len = destination.remaining()
        if (len <= 0) return
        
        val buffer = ByteArray(len)
        val read = RustNative.readFile(fsHandle, path, offset, buffer)
        if (read > 0) {
            destination.put(buffer, 0, read.toInt())
        }
    }
    
    override fun write(offset: Long, source: ByteBuffer) {
        throw IOException("Read-only file system")
    }
    
    override fun flush() {}
    override fun close() {}
    override fun createDirectory(name: String): UsbFile { throw IOException("Read-only") }
    override fun createFile(name: String): UsbFile { throw IOException("Read-only") }
    override fun moveTo(destination: UsbFile) { throw IOException("Read-only") }
    override fun delete() { throw IOException("Read-only") }
    override fun setName(newName: String) { throw IOException("Read-only") }
}
