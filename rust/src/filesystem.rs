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
    // Logical position of this reader (decoupled from inner reader).
    position: u64,
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
            // Copy position state
            position: self.position,
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
            position: 0,
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
        
        // Seek to the sector offset in the underlying reader.
        // We only seek when we need to fill the window.
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
        if read_len < buffer.len() {
             // For security/determinism, zero out the rest.
             for i in read_len..buffer.len() {
                 buffer[i] = 0;
             }
        }

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

        // Use internal position
        let current_pos = self.position;

        if current_pos >= self.volume.size() {
            return Ok(0);
        }
        
        // Calculate sector index.
        let sector_index = current_pos / self.sector_size;
        let offset_in_sector = (current_pos % self.sector_size) as usize;

        // Ensure the correct sector is loaded and decrypted.
        self.read_sector(sector_index)?;

        // Calculate available bytes in this sector.
        let available = self.sector_size as usize - offset_in_sector;
        let to_read = std::cmp::min(buf.len(), available);

        // Copy decrypted data.
        let buffer = self.sector_buffer.as_ref().unwrap();
        buf[..to_read].copy_from_slice(&buffer[offset_in_sector..offset_in_sector + to_read]);

        // Advance internal position.
        self.position += to_read as u64;

        // Note: inner reader position is left undefined (at end of sector read usually).
        // We do NOT seek it back. This saves valueable arithmetic/JNI logic if any.

        Ok(to_read)
    }
}

// Implement Seek trait for DecryptedReader.
impl Seek for DecryptedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => {
                 let size = self.volume.size();
                 // helper for sealed arithmetic
                 if p >= 0 {
                     size.checked_add(p as u64).ok_or(io::Error::new(io::ErrorKind::Other, "Overflow"))?
                 } else {
                     size.checked_sub(p.unsigned_abs()).ok_or(io::Error::new(io::ErrorKind::Other, "Underflow"))?
                 }
            }
            SeekFrom::Current(p) => {
                if p >= 0 {
                    self.position.checked_add(p as u64).ok_or(io::Error::new(io::ErrorKind::Other, "Overflow"))?
                } else {
                    self.position.checked_sub(p.unsigned_abs()).ok_or(io::Error::new(io::ErrorKind::Other, "Underflow"))?
                }
            }
        };
        self.position = new_pos;
        Ok(new_pos)
    }
}

// Enum representing supported file systems.
pub enum SupportedFileSystem {
    // NTFS file system wrapper.
    Ntfs(Box<Ntfs<DecryptedReader>>), 
    // ExFAT file system wrapper.
    ExFat(Box<exfat::ExFat<DecryptedReader>>),
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
                // Get the underlying reader
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
                    // Iterate through entries in the directory (NTFS uses B-Tree like structure)
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

                // We are now at the target directory. Get its index/entries.
                let index = current_dir
                    .directory_index(reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let mut results = Vec::new();
                // Iterate through entries to collect file info.
                let mut entries = index.entries();
                
                // For NTFS we iterate. Should validly limit for pagination if needed, but for now standard iteration.
                // NOTE: NTFS entries iterator might be efficient, but large directories can still be slow.
                // However, unlike ExFat code previously, this iterates one by one.
                while let Some(entry_res) = entries.next(reader) {
                    // Handle individual entry errors
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
                        // Get the name.
                        let name = key.name().to_string_lossy();
                        if name == "." || name == ".." {
                            continue;
                        }
    
                        results.push(FileInfo {
                            name: name.to_string(),
                            is_dir: key.is_directory(),
                            size: key.data_size(),
                        });
                    }
                }
                Ok(results)
            }
            // Handle ExFAT file system.
            SupportedFileSystem::ExFat(exfat) => {
                // EXFAT TRAVERSAL
                // We start with root directory iterator
                // Currently exfat crate `root_directory()` returns an Iterator of items.
                // We cannot "seek" inside iterator unless we consume it.
                // To traverse, we find the Directory item and open it.
                
                // Note: exfat crate usage pattern:
                // `exfat.root_directory()` -> impl Iterator<Item=Item<R>>
                // Item can be File/Directory.
                // Directory has `open()` which returns a new Iterator (directory content).
                
                // We need to store the current iterator? No, we just need to drill down.
                // But `root_directory()` takes `&self` (ref to ExFat struct).
                // It returns an iterator that borrows from ExFat instance?
                // Or works with the reader?
                
                // Strategy:
                // 1. Get root directory iterator.
                // 2. Iterate to find component.
                // 3. If found (Dir), open it -> get new iterator.
                // 4. Repeat.
                
                // Since `exfat` crate iterators are lazy, this handles the OOM issue (we don't collect until the end).
                
                // Problem: We need to traverse efficiently.
                // Since this is listing files, we drill down to `path` then collect `path` children.
                
                // Root iterator
                // We use a recursive approach or loop?
                // `exfat.root_directory()` gives root items.
                
                // We need to hold the "Current Directory Iterator" logic.
                // Since `exfat::directory::Directory` properties `open()` returns `Result<impl Iterator>`.
                // We can't type-erase `impl Iterator` easily without Box<dyn Iterator>.
                
                // Let's iterate manually.
                
                // Need to find the target directory first.
                // For root (empty components), we just list root.
                
                if components.is_empty() {
                    let mut results = Vec::new();
                    let root_iter = exfat.root_directory()
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    
                    for item in root_iter {
                        match item {
                             exfat::directory::Item::Directory(d) => results.push(FileInfo { 
                                 name: d.name().to_string(), 
                                 is_dir: true, 
                                 size: 0 
                             }),
                             exfat::directory::Item::File(f) => results.push(FileInfo { 
                                 name: f.name().to_string(), 
                                 is_dir: false, 
                                 size: f.len() 
                             }),
                        }
                    }
                    return Ok(results);
                }
                
                // Drill down
                // This is bit tricky because each level gives us an iterator we must consume to find the next dir.
                // And `exfat` crate structures.
                
                // We need to implement a helper to "find directory in iterator".
                
                // Since we can't easily recurse with different iterator types (roots vs subdirs might differ in type signature in some crates, but usually `exfat` is consistent?),
                // In `exfat` 0.1, `root_directory` returns `Result<Iter<'a, R>>`.
                // `Directory::open` returns `Result<Iter<'a, R>>`.
                // Usage: `let mut iter = exfat.root_directory()?;`
                
                // Let's implement the loop.
                let mut current_iter = exfat.root_directory()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                // We need to process components one by one.
                // But `open()` creates a NEW iterator.
                // We can't assign `current_iter = new_iter` if they are derived from different lifecycles or ownerships?
                // Actually they borrow `reader` from `exfat` struct usually.
                
                // For the loop to work, we need an intermediate `found_dir` object.
                // `exfat::directory::Directory`.
                
                let mut target_dir_content: Option<Vec<FileInfo>> = None;
                
                // We have to restart logic for drill down.
                // Since we can't easily keep the iterator "state" across components in a simple loop due to Rust type system (if `open` returns distinct type or lifetime issues),
                // We will rely on recursion or just careful logic.
                // Actually, `exfat` crate `Iter` type is likely `exfat::directory::Iter<'a, R>`.
                
                // Let's try to simulate checking each component.
                
                // Currently `exfat` 0.1 doesn't seem to support arbitrary path lookup, we have to iterate.
                
                // Recursive lookup helper?
                fn find_dir<'a, R: io::Read + io::Seek>(
                    mut iter: exfat::directory::Iter<'a, R>,
                    components: &[&str],
                ) -> io::Result<Vec<FileInfo>> {
                    if components.is_empty() {
                        // Current iter is the target. List it.
                        let mut results = Vec::new();
                         for item in iter {
                            match item {
                                 exfat::directory::Item::Directory(d) => results.push(FileInfo { 
                                     name: d.name().to_string(), 
                                     is_dir: true, 
                                     size: 0 
                                 }),
                                 exfat::directory::Item::File(f) => results.push(FileInfo { 
                                     name: f.name().to_string(), 
                                     is_dir: false, 
                                     size: f.len() 
                                 }),
                            }
                        }
                        return Ok(results);
                    }
                    
                    let target_name = components[0];
                    let remaining = &components[1..];
                    
                    for item in iter {
                         if let exfat::directory::Item::Directory(d) = item {
                             if d.name() == target_name {
                                 let sub_iter = d.open().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                 return find_dir(sub_iter, remaining);
                             }
                         }
                    }
                    Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"))
                }
                
                let root_iter = exfat.root_directory()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                
                find_dir(root_iter, &components)
            }
        }
    }

    // Method to read data from a specific file.
    pub fn read_file(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let path = path.trim_matches('/');
 
        if path.contains("..") {
             return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Path traversal detected"));
        }
        
        let components: Vec<&str> = if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty path"));
        } else {
            path.split('/').filter(|s| !s.is_empty()).collect()
        };

        let (file_name, dir_components) = components.split_last().ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path components"))?;

        match self {
            SupportedFileSystem::Ntfs(ntfs) => {
                let reader = ntfs.get_mut();
                reader.seek(SeekFrom::Start(0))?;
                
                let mut current_dir = ntfs
                    .root_directory(reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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
                        if key.name().to_string_lossy() == *file_name {
                            let id = entry.file_reference().file_record_number();
                            let file = ntfs
                                .file(reader, id)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                            let data = file.data(reader, "");
                            if let Some(attr_res) = data {
                                let attr_item = attr_res
                                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                let attr = attr_item.to_attribute().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                let mut value = attr
                                    .value(reader)
                                    .map_err(|e: ntfs::NtfsError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                value.seek(reader, SeekFrom::Start(offset)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                return value.read(reader, buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
                            }
                        }
                    }
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            }
            // Handle ExFAT file system.
            SupportedFileSystem::ExFat(exfat) => {
                 // Helper to find file recursively
                 // We can reuse logic or copy paste. Recursion is cleanest given iterators.
                 
                 fn find_read_file<'a, R: io::Read + io::Seek>(
                    mut iter: exfat::directory::Iter<'a, R>,
                    components: &[&str],
                    offset: u64,
                    buf: &mut [u8]
                 ) -> io::Result<usize> {
                     if components.is_empty() {
                         // We expect a file name as last component
                         return Err(io::Error::new(io::ErrorKind::NotFound, "File not specified"));
                     }
                     
                     let target = components[0];
                     let is_last = components.len() == 1;
                     
                     for item in iter {
                         match item {
                             exfat::directory::Item::Directory(d) => {
                                 if !is_last && d.name() == target {
                                     let sub_iter = d.open().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                     return find_read_file(sub_iter, &components[1..], offset, buf);
                                 }
                             },
                             exfat::directory::Item::File(f) => {
                                 if is_last && f.name() == target {
                                     let reader_opt = f.open().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
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
                     Err(io::Error::new(io::ErrorKind::NotFound, "File or Path not found"))
                 }
                 
                 let root_iter = exfat.root_directory()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    
                 // Reconstruct full path components (dirs + filename)
                 let mut all_components = Vec::new();
                 all_components.extend_from_slice(dir_components);
                 all_components.push(*file_name);
                 
                 find_read_file(root_iter, &all_components, offset, buf)
            }
        }
    }
}
