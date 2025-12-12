// Import standard I/O traits and types.
use std::io::{self, Read, Seek, SeekFrom};
// Import Arc for shared ownership.
use std::sync::Arc;
// Import Volume struct from volume module.
use crate::volume::Volume;
// Import CallbackReader from io_callback module.
use crate::io_callback::CallbackReader;
// Import NTFS implementation.
use ntfs::{Ntfs, NtfsReadSeek};
// Import ExFAT implementation.
// use exfat::ExFat;

use zeroize::Zeroize;

// Struct representing a reader that decrypts data on the fly.
// structure definition without Clone derive
pub struct DecryptedReader {
    // The underlying reader (CallbackReader) that provides raw encrypted data.
    inner: CallbackReader,
    // The volume context containing encryption keys and settings.
    volume: Arc<Volume>,
    // The sector size of the volume.
    sector_size: u64,
    // The index of the currently buffered sector.
    current_sector_index: u64,
    // Buffer to hold the decrypted data of the current sector.
    // Wrapped in Option for lazy allocation to save memory when listing many files.
    sector_buffer: Option<Vec<u8>>,
}

impl Drop for DecryptedReader {
    fn drop(&mut self) {
        if let Some(mut buf) = self.sector_buffer.take() {
            buf.zeroize();
        }
    }
}

impl Clone for DecryptedReader {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            volume: self.volume.clone(),
            sector_size: self.sector_size,
            // Reset state in clone to avoid stale buffer/index and unnecessary allocation
            current_sector_index: u64::MAX,
            sector_buffer: None,
        }
    }
}

// Implementation of DecryptedReader methods.
impl DecryptedReader {
    // Constructor to create a new DecryptedReader.
    pub fn new(inner: CallbackReader, volume: Arc<Volume>) -> Self {
        // Get the sector size from the volume.
        let sector_size = volume.sector_size() as u64;
        // Return a new instance.
        Self {
            inner,
            volume,
            sector_size,
            // Initialize with an invalid sector index.
            current_sector_index: u64::MAX, // Invalid
            // Lazy allocation.
            sector_buffer: None,
        }
    }

    // Helper method to read and decrypt a specific sector.
    fn read_sector(&mut self, sector_index: u64) -> io::Result<()> {
        // If the requested sector is already in the buffer, do nothing.
        if self.current_sector_index == sector_index {
            return Ok(());
        }

        // Calculate the byte offset of the sector.
        let offset = sector_index * self.sector_size;
        
        // Seek to the sector offset in the underlying reader ONLY if needed.
        // We track position manually to check, but since 'inner' is CallbackReader which tracks safely...
        // Actually, we can just seek. CallbackReader seek is cheap (arithmetic).
        // Optimization: avoid JNI overhead if position is already correct?
        // But CallbackReader `seek` implementation is pure Rust arithmetic update of a u64 field.
        // It DOES NOT call JNI. So `self.inner.seek` is very cheap.
        // The issue reported was "inner reader... for every call".
        // If `inner.seek` is cheap, then the optimization is less critical, but good practice.
        self.inner.seek(SeekFrom::Start(offset))?;

        // Read encrypted data into the buffer.
        // Use read loop to handle potential partial reads or EOF if file is truncated.
        // We pad with zeros if we cannot read a full sector (best effort for recovery/inspection).
        // Ensure buffer is allocated.
        if self.sector_buffer.is_none() {
            self.sector_buffer = Some(vec![0u8; self.sector_size as usize]);
        }
        let buffer = self.sector_buffer.as_mut().unwrap();

        let mut read_len = 0;
        while read_len < buffer.len() {
            match self.inner.read(&mut buffer[read_len..]) {
                Ok(0) => break, // EOF
                Ok(n) => read_len += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        
        // If we read partial sector, pad the rest with zeros (already zero initialized? No, we reuse buffer).
        // Wait, current implementation allocates buffer once in struct?
        // Ah, `self.sector_buffer` is reused. We MUST zero out the rest if partial read.
        if read_len < buffer.len() {
             // For security/determinism, zero out the rest.
             for i in read_len..buffer.len() {
                 buffer[i] = 0;
             }
        }
        // If read_len is 0 and we are truly at EOF, decrypting a zero block might be valid or not, 
        // but read_sector is usually called when we expect data. 
        // If we are at EOF of volume, the caller (Read impl) handles offsets. 
        // This helper reads PHYSICAL sector.
        // If file is truncated, we treat as zero-padded.

        // Decrypt the data in-place using the volume's decrypt_sector method.
        self.volume
            .decrypt_sector(sector_index, buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decrypt error: {}", e)))?;

        // Update the current sector index.
        self.current_sector_index = sector_index;
        Ok(())
    }
}

// Implement Read trait for DecryptedReader.
impl Read for DecryptedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Get the current position in the stream.
        // Optimization: Avoid `stream_position` which calls `seek(Current(0))`.
        // We know we are `CallbackReader`, whose seek is cheap.
        // But let's rely on `self.inner.stream_position()` being efficient enough or use correct seek logic.
        let current_pos = self.inner.stream_position()?;
        
        // Calculate sector index.
        let sector_index = current_pos / self.sector_size;
        let offset_in_sector = (current_pos % self.sector_size) as usize;

        // Ensure the correct sector is loaded and decrypted.
        // Note: This seeks `inner` to sector start.
        self.read_sector(sector_index)?;

        // Calculate available bytes in this sector.
        let available = self.sector_size as usize - offset_in_sector;
        let to_read = std::cmp::min(buf.len(), available);

        // Copy decrypted data.
        let buffer = self.sector_buffer.as_ref().unwrap();
        buf[..to_read].copy_from_slice(&buffer[offset_in_sector..offset_in_sector + to_read]);

        // Advance inner position properly.
        // read_sector left inner at (sector_start + sector_size).
        // We want it to be at (current_pos + to_read).
        // So we MUST seek back.
        // current_pos + to_read might be < sector_end.
        self.inner.seek(SeekFrom::Start(current_pos + to_read as u64))?;

        Ok(to_read)
    }
}

// Implement Seek trait for DecryptedReader.
impl Seek for DecryptedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

// Enum representing supported file systems.
pub enum SupportedFileSystem {
    // NTFS file system wrapper.
    Ntfs(Box<Ntfs<DecryptedReader>>), // Cached NTFS instance (boxed to avoid large size on stack/enum)
    // ExFAT file system wrapper.
    ExFat(Vec<exfat::directory::Item<DecryptedReader>>),
}

// Struct to hold information about a file or directory.
pub struct FileInfo {
    // Name of the file or directory.
    pub name: String,
    // True if it is a directory, false otherwise.
    pub is_dir: bool,
    // Size of the file in bytes.
    pub size: u64,
}

// Implementation of methods for SupportedFileSystem.
impl SupportedFileSystem {
    // Method to list files in a given directory path.
    pub fn list_files(&mut self, path: &str) -> io::Result<Vec<FileInfo>> {
        // Remove leading/trailing slashes from the path.
        let path = path.trim_matches('/');
        
        // Security: Prevent path traversal.
        if path.contains("..") {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Path traversal detected"));
        }
        
        // Split the path into components.
        let components: Vec<&str> = if path.is_empty() {
            // If path is empty, it's the root directory.
            Vec::new()
        } else {
            // Split by forward slash and filter empty components.
            path.split('/').filter(|s| !s.is_empty()).collect()
        };

        match self {
            // Handle NTFS file system.
            SupportedFileSystem::Ntfs(ntfs) => {
                // Get the underlying reader (mutable borrow from Ntfs struct? No, Ntfs owns it.)
                // Ntfs struct allows access to its inner reader via `get_mut()`.
                // Accessing root directory requires mutable access to reader.
                let reader = ntfs.get_mut();
                reader.seek(SeekFrom::Start(0))?;

                // Start at the root directory.
                let mut current_dir = ntfs
                    .root_directory(reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                // Traverse the directory structure based on path components.
                for component in components {
                    // Get the index of the current directory.
                    let index = current_dir
                        .directory_index(reader)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    let mut found = false;
                    // Iterate through entries in the directory.
                    let mut entries = index.entries();
                    while let Some(entry) = entries.next(&mut *reader) {
                        let entry: ntfs::NtfsIndexEntry<ntfs::indexes::NtfsFileNameIndex> = entry?;
                        // Check if the entry name matches the current component.
                        let key = entry.key().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key error: {}", e)))?;
                        if let Some(key) = key {
                            if key.name().to_string_lossy() == component && key.is_directory() {
                                let id = entry.file_reference().file_record_number();
                                current_dir = ntfs.file(reader, id).map_err(|e| {
                                    io::Error::new(io::ErrorKind::Other, e.to_string())
                                })?;
                                found = true;
                                break;
                            }
                        }
                    }
                    // If component not found, return NotFound error.
                    if !found {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"));
                    }
                }

                // We are now at the target directory. Get its index.
                let index = current_dir
                    .directory_index(reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let mut results = Vec::new();
                // Iterate through entries to collect file info.
                let mut entries = index.entries();
                while let Some(entry_res) = entries.next(reader) {
                    // Handle individual entry errors without failing the whole listing
                    let entry: ntfs::NtfsIndexEntry<ntfs::indexes::NtfsFileNameIndex> = match entry_res {
                        Ok(e) => e,
                        Err(e) => {
                            log::warn!("Failed to read NTFS entry: {}", e);
                            continue;
                        }
                    };
                    
                    let key = match entry.key() {
                        Ok(k) => k,
                        Err(e) => {
                             log::warn!("Failed to read NTFS entry key: {}", e);
                             continue;
                        }
                    };
                    
                    if let Some(key) = key {
                        // Get the name of the entry.
                        let name = key.name().to_string_lossy();
                        // Skip current and parent directory entries.
                        if name == "." || name == ".." {
                            continue;
                        }
    
                        // Determine if it's a directory.
                        let is_dir = key.is_directory();
                        // Get the size of the entry.
                        let size = key.data_size();
                        // Add to results.
                        results.push(FileInfo {
                            name: name.to_string(),
                            is_dir,
                            size,
                        });
                    }
                }
                // Return the list of files.
                Ok(results)
            }
            // Handle ExFAT file system.
            SupportedFileSystem::ExFat(root_items) => {
                let mut loaded_dir: Vec<exfat::directory::Item<DecryptedReader>> = Vec::new();
                let mut is_root = true;

                for component in components {
                    let mut found_dir_items = None;

                    if is_root {
                        for item in root_items.iter() {
                            if let exfat::directory::Item::Directory(dir) = item {
                                if dir.name() == component {
                                    found_dir_items = Some(dir.open().map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?);
                                    break;
                                }
                            }
                        }
                    } else {
                        for item in loaded_dir.iter() {
                            if let exfat::directory::Item::Directory(dir) = item {
                                if dir.name() == component {
                                    found_dir_items = Some(dir.open().map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?);
                                    break;
                                }
                            }
                        }
                    }

                    if let Some(items) = found_dir_items {
                        loaded_dir = items;
                        is_root = false;
                    } else {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"));
                    }
                }

                let mut results = Vec::new();
                let items_to_list = if is_root {
                    root_items.iter()
                } else {
                    loaded_dir.iter()
                };

                for item in items_to_list {
                    match item {
                        exfat::directory::Item::Directory(dir) => {
                            results.push(FileInfo {
                                name: dir.name().to_string(),
                                is_dir: true,
                                size: 0,
                            });
                        }
                        exfat::directory::Item::File(file) => {
                            results.push(FileInfo {
                                name: file.name().to_string(),
                                is_dir: false,
                                size: file.len(),
                            });
                        }
                    }
                }
                Ok(results)
            }
        }
    }

    // Method to read data from a specific file.
    pub fn read_file(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        // Remove leading/trailing slashes.
        let path = path.trim_matches('/');
        
        // Security: Prevent path traversal.
        if path.contains("..") {
             return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Path traversal detected"));
        }
        
        // Split path into components.
        let components: Vec<&str> = if path.is_empty() {
            // Cannot read root as a file.
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty path"));
        } else {
            path.split('/').filter(|s| !s.is_empty()).collect()
        };

        // Separate the file name from the directory path components.
        let (file_name, dir_components) = components.split_last().ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path components"))?;

        match self {
            // Handle NTFS file system.
            SupportedFileSystem::Ntfs(ntfs) => {
                let reader = ntfs.get_mut();
                reader.seek(SeekFrom::Start(0))?;
                
                // Start at root.
                let mut current_dir = ntfs
                    .root_directory(reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                // Traverse directories.
                for component in dir_components {
                    let index = current_dir
                        .directory_index(reader)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    let mut found = false;
                    let mut entries = index.entries();
                    while let Some(entry) = entries.next(reader) {
                        let entry: ntfs::NtfsIndexEntry<ntfs::indexes::NtfsFileNameIndex> = entry?;
                        let key = entry.key().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key error: {}", e)))?;
                        if let Some(key) = key {
                            if key.name().to_string_lossy() == *component && key.is_directory() {
                                let id = entry.file_reference().file_record_number();
                                current_dir = ntfs.file(reader, id).map_err(|e| {
                                    io::Error::new(io::ErrorKind::Other, e.to_string())
                                })?;
                                found = true;
                                break;
                            }
                        }
                    }
                    if !found {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"));
                    }
                }

                // Look for the file in the final directory.
                let index = current_dir
                    .directory_index(reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let mut entries = index.entries();
                while let Some(entry) = entries.next(reader) {
                    let entry: ntfs::NtfsIndexEntry<ntfs::indexes::NtfsFileNameIndex> = entry?;
                    let key = entry.key().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key error: {}", e)))?;
                    if let Some(key) = key {
                        // Check if entry name matches file name.
                        if key.name().to_string_lossy() == *file_name {
                            // Convert entry to file.
                            let id = entry.file_reference().file_record_number();
                            let file = ntfs
                                .file(reader, id)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                            // Get data attribute (content).
                            let data = file.data(reader, "");
                            if let Some(attr_res) = data {
                                let attr_item = attr_res
                                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                let attr = attr_item.to_attribute().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                let mut value = attr
                                    .value(reader)
                                    .map_err(|e: ntfs::NtfsError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                // Seek to the requested offset.
                                value.seek(reader, SeekFrom::Start(offset)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                // Read data into buffer.
                                return value.read(reader, buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
                            }
                        }
                    }
                }
                // File not found.
                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            }
            // Handle ExFAT file system.
            SupportedFileSystem::ExFat(root_items) => {
                let mut loaded_dir: Vec<exfat::directory::Item<DecryptedReader>> = Vec::new();
                let mut is_root = true;

                for component in dir_components {
                    let mut found_dir_items = None;

                    if is_root {
                        for item in root_items.iter() {
                            if let exfat::directory::Item::Directory(dir) = item {
                                if dir.name() == *component {
                                    found_dir_items = Some(dir.open().map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?);
                                    break;
                                }
                            }
                        }
                    } else {
                        for item in loaded_dir.iter() {
                            if let exfat::directory::Item::Directory(dir) = item {
                                if dir.name() == *component {
                                    found_dir_items = Some(dir.open().map_err(|e| {
                                        io::Error::new(io::ErrorKind::Other, e.to_string())
                                    })?);
                                    break;
                                }
                            }
                        }
                    }

                    if let Some(items) = found_dir_items {
                        loaded_dir = items;
                        is_root = false;
                    } else {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"));
                    }
                }

                if is_root {
                    for item in root_items.iter_mut() {
                        if let exfat::directory::Item::File(file) = item {
                            if file.name() == *file_name {
                                let reader_opt = file.open().map_err(|e| {
                                    io::Error::new(io::ErrorKind::Other, e.to_string())
                                })?;
                                if let Some(mut reader) = reader_opt {
                                    reader.seek(SeekFrom::Start(offset))?;
                                    return reader.read(buf);
                                } else {
                                    return Ok(0);
                                }
                            }
                        }
                    }
                } else {
                    for item in loaded_dir.iter_mut() {
                        if let exfat::directory::Item::File(file) = item {
                            if file.name() == *file_name {
                                let reader_opt = file.open().map_err(|e| {
                                    io::Error::new(io::ErrorKind::Other, e.to_string())
                                })?;
                                if let Some(mut reader) = reader_opt {
                                    reader.seek(SeekFrom::Start(offset))?;
                                    return reader.read(buf);
                                } else {
                                    return Ok(0);
                                }
                            }
                        }
                    }
                }

                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            }
        }
    }
}
