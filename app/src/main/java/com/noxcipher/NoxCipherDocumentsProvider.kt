package com.noxcipher

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.webkit.MimeTypeMap
import com.github.mjdev.libaums.fs.UsbFile
import java.io.FileNotFoundException
import java.io.IOException

class NoxCipherDocumentsProvider : DocumentsProvider() {

    companion object {
        private const val DEFAULT_ROOT_ID = "root"
        private val DEFAULT_DOCUMENT_PROJECTION = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            DocumentsContract.Document.COLUMN_FLAGS,
            DocumentsContract.Document.COLUMN_SIZE
        )
        
        private val DEFAULT_ROOT_PROJECTION = arrayOf(
            DocumentsContract.Root.COLUMN_ROOT_ID,
            DocumentsContract.Root.COLUMN_FLAGS,
            DocumentsContract.Root.COLUMN_ICON,
            DocumentsContract.Root.COLUMN_TITLE,
            DocumentsContract.Root.COLUMN_DOCUMENT_ID,
            DocumentsContract.Root.COLUMN_AVAILABLE_BYTES
        )
    }

    override fun onCreate(): Boolean {
        return true
    }

    override fun queryRoots(projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION)
        
        val fs = SessionManager.activeFileSystem
        if (fs != null) {
            val row = result.newRow()
            row.add(DocumentsContract.Root.COLUMN_ROOT_ID, DEFAULT_ROOT_ID)
            row.add(DocumentsContract.Root.COLUMN_FLAGS, DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD)
            row.add(DocumentsContract.Root.COLUMN_ICON, R.mipmap.ic_launcher)
            row.add(DocumentsContract.Root.COLUMN_TITLE, "NoxCipher Volume")
            row.add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, "/")
            // row.add(DocumentsContract.Root.COLUMN_AVAILABLE_BYTES, fs.capacity - fs.occupiedSpace) // Optional
        }
        
        return result
    }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException("Volume not mounted")
        
        try {
            val parentFile = getFileForDocId(fs, parentDocumentId)
            if (!parentFile.isDirectory) {
                throw FileNotFoundException("Document is not a directory: $parentDocumentId")
            }
            
            for (file in parentFile.listFiles()) {
                includeFile(result, file)
            }
        } catch (e: IOException) {
            throw FileNotFoundException("Failed to list files: ${e.message}")
        }
        
        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException("Volume not mounted")
        
        try {
            val file = getFileForDocId(fs, documentId)
            includeFile(result, file)
        } catch (e: IOException) {
            throw FileNotFoundException("File not found: $documentId")
        }
        
        return result
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException("Volume not mounted")
        val file = getFileForDocId(fs, documentId)
        
        // We need to return a ParcelFileDescriptor.
        // Since libaums doesn't give us a java.io.File or a real FD, we must use a Proxy.
        // Android provides StorageManager.openProxyFileDescriptor but it requires API 26+.
        // Our minSdk is 26, so we are good.
        
        val storageManager = context!!.getSystemService(android.content.Context.STORAGE_SERVICE) as android.os.storage.StorageManager
        
        // We need to implement a ProxyFileDescriptorCallback
        val callback = object : android.os.ProxyFileDescriptorCallback() {
            private var currentOffset = 0L

            override fun onGetSize(): Long {
                return file.length
            }

            override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
                // libaums read: read(offset, buffer)
                // We need to handle the offset.
                // If offset != currentOffset, we might need to seek?
                // UsbFile.read takes an offset.
                
                val buffer = java.nio.ByteBuffer.wrap(data)
                // UsbFile.read writes into buffer.
                // It returns bytes read? No, it throws IOException or returns nothing?
                // Checking libaums source/docs (mental model):
                // int read(long offset, ByteBuffer destination)
                
                // Ensure we don't read past EOF
                if (offset >= file.length) return 0
                
                val lengthToRead = Math.min(size.toLong(), file.length - offset).toInt()
                buffer.limit(lengthToRead)
                
                try {
                    file.read(offset, buffer)
                    return buffer.position()
                } catch (e: IOException) {
                    throw android.system.ErrnoException("read", android.system.OsConstants.EIO)
                }
            }

            override fun onRelease() {
                // Nothing to close on file itself, handled by FS
            }
        }
        
        return storageManager.openProxyFileDescriptor(
            ParcelFileDescriptor.parseMode(mode),
            callback,
            android.os.Handler(android.os.Looper.getMainLooper())
        )
    }

    private fun getFileForDocId(fs: com.github.mjdev.libaums.fs.FileSystem, docId: String): UsbFile {
        if (docId == "/") return fs.rootDirectory
        
        // Split path and traverse
        // docId is like "/folder/file.txt"
        val parts = docId.split("/").filter { it.isNotEmpty() }
        var current = fs.rootDirectory
        
        for (part in parts) {
            val children = current.listFiles()
            current = children.find { it.name == part } ?: throw FileNotFoundException("File not found: $part in $docId")
        }
        
        return current
    }

    private fun includeFile(result: MatrixCursor, file: UsbFile) {
        val row = result.newRow()
        
        // Construct ID
        // We need full path. UsbFile doesn't always store full path efficiently.
        // But we can construct it if we assume we are traversing.
        // Wait, 'file' object doesn't have 'absolutePath'?
        // We might need to store parent path in recursion or re-construct.
        // For simple implementation:
        // If we are listing children of a parent, we know the parent ID.
        // But here we just have 'file'.
        // Let's assume we can get path or we use a hack.
        // Actually, UsbFile usually has a reference to parent.
        
        val docId = getDocIdForFile(file)
        
        row.add(DocumentsContract.Document.COLUMN_DOCUMENT_ID, docId)
        row.add(DocumentsContract.Document.COLUMN_DISPLAY_NAME, file.name)
        
        val mimeType = if (file.isDirectory) {
            DocumentsContract.Document.MIME_TYPE_DIR
        } else {
            val ext = MimeTypeMap.getFileExtensionFromUrl(file.name)
            MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
        }
        row.add(DocumentsContract.Document.COLUMN_MIME_TYPE, mimeType)
        
        // Flags
        var flags = 0
        // if (file.isDirectory) flags = flags or DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
        // We are read-only for now
        
        row.add(DocumentsContract.Document.COLUMN_FLAGS, flags)
        row.add(DocumentsContract.Document.COLUMN_SIZE, file.length)
        row.add(DocumentsContract.Document.COLUMN_LAST_MODIFIED, 0) // Not available easily
    }
    
    private fun getDocIdForFile(file: UsbFile): String {
        if (file.isRoot) return "/"
        val parent = file.parent
        val parentId = if (parent.isRoot) "" else getDocIdForFile(parent)
        return "$parentId/${file.name}"
    }
}
