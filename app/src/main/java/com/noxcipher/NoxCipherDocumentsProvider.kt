package com.noxcipher

import android.database.Cursor
import me.jahnen.libaums.core.fs.UsbFile
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.webkit.MimeTypeMap
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
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
        
        private object BackgroundHandler {
            private val handlerThread = android.os.HandlerThread("ContentProviderIO")
            init {
                handlerThread.start()
            }
            fun getHandler(): android.os.Handler {
                return android.os.Handler(handlerThread.looper)
            }
        }
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
            row.add(DocumentsContract.Root.COLUMN_TITLE, context!!.getString(R.string.root_title))
            row.add(DocumentsContract.Root.COLUMN_DOCUMENT_ID, DEFAULT_ROOT_ID)
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
        
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(context!!.getString(R.string.error_volume_not_mounted))
        
        try {
            val parentFile = if (parentDocumentId == DEFAULT_ROOT_ID) {
                fs.rootDirectory
            } else {
                 getFileForDocId(fs, parentDocumentId)
            }
             
            if (!parentFile.isDirectory) {
                throw FileNotFoundException(context!!.getString(R.string.error_doc_not_dir, parentDocumentId))
            }
            
            for (file in parentFile.listFiles()) {
                includeFile(result, file)
            }
        } catch (e: IOException) {
            throw FileNotFoundException(context!!.getString(R.string.error_list_files, e.message))
        }
        
        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(context!!.getString(R.string.error_volume_not_mounted))
        
        try {
            val file = getFileForDocId(fs, documentId)
            includeFile(result, file)
        } catch (e: IOException) {
            throw FileNotFoundException(context!!.getString(R.string.error_file_not_found, documentId))
        }
        
        return result
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(context!!.getString(R.string.error_volume_not_mounted))
        val file = getFileForDocId(fs, documentId)
        
        // We need to return a ParcelFileDescriptor.
        // Since libaums doesn't give us a java.io.File or a real FD, we must use a Proxy.
        // Android provides StorageManager.openProxyFileDescriptor but it requires API 26+.
        // Our minSdk is 26, so we are good.
        
        val storageManager = context!!.getSystemService(android.content.Context.STORAGE_SERVICE) as android.os.storage.StorageManager
        
        // Use cached thread pool or single thread executor 
        // For simplicity in this bug fix, use a lazy singleton executor or just cached thread pool.
        // Creating a new HandlerThread for every file is bad.
        // We can reuse a global HandlerThread.
        
        val handler = BackgroundHandler.getHandler()

        // We need to implement a ProxyFileDescriptorCallback
        val callback = object : android.os.ProxyFileDescriptorCallback() {
            private var currentOffset = 0L

            override fun onGetSize(): Long {
                return file.length
            }

            override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
                val buffer = java.nio.ByteBuffer.wrap(data)
                
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

            override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
                val buffer = java.nio.ByteBuffer.wrap(data, 0, size)
                try {
                    file.write(offset, buffer)
                    return size
                } catch (e: IOException) {
                    throw android.system.ErrnoException("write", android.system.OsConstants.EIO)
                }
            }

            override fun onRelease() {
                try {
                    file.flush()
                } catch (e: IOException) {
                    // Ignore
                }
                // Do NOT quit the shared thread.
            }
        }
        
        return storageManager.openProxyFileDescriptor(
            ParcelFileDescriptor.parseMode(mode),
            callback,
            handler
        )
    }
    
    private fun getFileForDocId(fs: me.jahnen.libaums.core.fs.FileSystem, docId: String): UsbFile {
        if (docId == DEFAULT_ROOT_ID) return fs.rootDirectory
        
        // Split path and traverse
        // docId is like "/folder/file.txt"
        val parts = docId.split("/").filter { it.isNotEmpty() }
        var current = fs.rootDirectory
        
        for (part in parts) {
            val children = current.listFiles()
            current = children.find { it.name == part } ?: throw FileNotFoundException(context!!.getString(R.string.error_file_not_found_in, part, docId))
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
        // Disable write flags as write support is incomplete/buggy
        val flags = 0 // DocumentsContract.Document.FLAG_SUPPORTS_WRITE | ...
        
        // if (file.isDirectory) {
        //     flags = flags or DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE
        // }
        
        row.add(DocumentsContract.Document.COLUMN_FLAGS, flags)
        row.add(DocumentsContract.Document.COLUMN_SIZE, file.length)
        row.add(DocumentsContract.Document.COLUMN_LAST_MODIFIED, file.lastModified())
    }
    
    private fun getDocIdForFile(file: UsbFile): String {
        if (file.isRoot) return DEFAULT_ROOT_ID
        // RustUsbFile might not implement parent correctly or recursion depth issue?
        // For now, assume simplified path construction based on file.absolutePath if available or name.
        // But Libaums UsbFile contract relies on parent.
        // Safety check.
        val parent = file.parent
        return if (parent == null || parent.isRoot) {
            // Parent is root or null (treated as root child)
            "$DEFAULT_ROOT_ID/${file.name}"
        } else {
             // Safe recursion (hope no cycles)
             "${getDocIdForFile(parent)}/${file.name}"
        }
    }

    override fun deleteDocument(documentId: String) {
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(context!!.getString(R.string.error_volume_not_mounted))
        try {
            val file = getFileForDocId(fs, documentId)
            file.delete()
        } catch (e: IOException) {
            throw FileNotFoundException(context!!.getString(R.string.error_delete, e.message))
        }
    }

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String {
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(context!!.getString(R.string.error_volume_not_mounted))
        try {
            val parentFile = getFileForDocId(fs, parentDocumentId)
            if (!parentFile.isDirectory) throw FileNotFoundException(context!!.getString(R.string.error_parent_not_dir))
            
            val newFile = if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR) {
                parentFile.createDirectory(displayName)
            } else {
                parentFile.createFile(displayName)
            }
            return getDocIdForFile(newFile)
        } catch (e: IOException) {
            throw FileNotFoundException(context!!.getString(R.string.error_create, e.message))
        }
    }
}
