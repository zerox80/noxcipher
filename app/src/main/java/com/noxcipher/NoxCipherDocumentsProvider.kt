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
            row.add(DocumentsContract.Root.COLUMN_TITLE, requireNotNull(context).getString(R.string.root_title))
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
        
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(requireNotNull(context).getString(R.string.error_volume_not_mounted))
        
        try {
            val parentFile = if (parentDocumentId == DEFAULT_ROOT_ID) {
                fs.rootDirectory
            } else {
                 getFileForDocId(fs, parentDocumentId)
            }
             
            if (!parentFile.isDirectory) {
                throw FileNotFoundException(requireNotNull(context).getString(R.string.error_doc_not_dir, parentDocumentId))
            }
            
            for (file in parentFile.listFiles()) {
                includeFile(result, file)
            }
        } catch (e: IOException) {
            throw FileNotFoundException(requireNotNull(context).getString(R.string.error_list_files, e.message))
        }
        
        return result
    }

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor {
        val result = MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(requireNotNull(context).getString(R.string.error_volume_not_mounted))
        
        try {
            val file = getFileForDocId(fs, documentId)
            includeFile(result, file)
        } catch (e: IOException) {
            throw FileNotFoundException(requireNotNull(context).getString(R.string.error_file_not_found, documentId))
        }
        
        return result
    }

    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?
    ): ParcelFileDescriptor {
        val fs = SessionManager.activeFileSystem ?: throw FileNotFoundException(requireNotNull(context).getString(R.string.error_volume_not_mounted))
        val file = getFileForDocId(fs, documentId)

        if (file.isDirectory) {
            throw FileNotFoundException(requireNotNull(context).getString(R.string.error_doc_not_dir, documentId))
        }

        if (!isReadOnlyMode(mode)) {
            throw FileNotFoundException("Read-only file system")
        }
        
        // We need to return a ParcelFileDescriptor.
        // Since libaums doesn't give us a java.io.File or a real FD, we must use a Proxy.
        // Android provides StorageManager.openProxyFileDescriptor but it requires API 26+.
        // Our minSdk is 26, so we are good.
        
        val (readFd, writeFd) = ParcelFileDescriptor.createReliablePipe()

        try {
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                try {
                    ParcelFileDescriptor.AutoCloseOutputStream(writeFd).use { os ->
                        val buffer = java.nio.ByteBuffer.allocate(8192)
                        var offset = 0L
                        while (offset < file.length) {
                            buffer.clear()
                            val toRead = Math.min(8192L, file.length - offset).toInt()
                            buffer.limit(toRead)
                            file.read(offset, buffer)
                            val bytesRead = buffer.position()
                            if (bytesRead <= 0) {
                                break
                            }
                            os.write(buffer.array(), 0, bytesRead)
                            offset += bytesRead
                        }
                    }
                } catch (e: Exception) {
                    try { writeFd.closeWithError("Read failed: " + e.message) } catch (e2: Exception) {}
                }
            }
        } catch (e: Exception) {
            try { readFd.close() } catch (ignored: Exception) {}
            try { writeFd.close() } catch (ignored: Exception) {}
            throw FileNotFoundException("Open failed: ${e.message}")
        }
        
        return readFd
    }
    
    private fun getFileForDocId(fs: me.jahnen.libaums.core.fs.FileSystem, docId: String): UsbFile {
        if (docId == DEFAULT_ROOT_ID) return fs.rootDirectory
        
        // Split path and traverse
        // docId is like "root/folder/file.txt"
        // We need to ignore the first component if it is DEFAULT_ROOT_ID
        val parts = docId.split("/").filter { it.isNotEmpty() }
        var current = fs.rootDirectory
        
        for (part in parts) {
            if (part == DEFAULT_ROOT_ID) continue
            val children = current.listFiles()
            current = children.find { it.name == part } ?: throw FileNotFoundException(requireNotNull(context).getString(R.string.error_file_not_found_in, part, docId))
        }
        
        return current
    }

    private fun includeFile(result: MatrixCursor, file: UsbFile) {
        val row = result.newRow()

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
        // Read-only provider
        val flags = 0
        
        row.add(DocumentsContract.Document.COLUMN_FLAGS, flags)
        row.add(DocumentsContract.Document.COLUMN_SIZE, file.length)
        row.add(DocumentsContract.Document.COLUMN_LAST_MODIFIED, file.lastModified())
    }
    
    private fun getDocIdForFile(file: UsbFile): String {
        if (file.isRoot) return DEFAULT_ROOT_ID

        val normalizedPath = file.absolutePath.replace('\\', '/').trim()
        val relativePath = normalizedPath.removePrefix("/").trim('/')
        return if (relativePath.isEmpty()) DEFAULT_ROOT_ID else "$DEFAULT_ROOT_ID/$relativePath"
    }

    private fun isReadOnlyMode(mode: String): Boolean {
        return mode.contains('r') && mode.none { it == 'w' || it == 'a' || it == 't' }
    }

    override fun deleteDocument(documentId: String) {
        throw FileNotFoundException("Read-only file system")
    }

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String {
        throw FileNotFoundException("Read-only file system")
    }
}
