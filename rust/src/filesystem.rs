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
#[derive(Clone)]
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
    sector_buffer: Vec<u8>,
}

impl Drop for DecryptedReader {
    fn drop(&mut self) {
        self.sector_buffer.zeroize();
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
            // Allocate buffer for one sector.
            sector_buffer: vec![0; sector_size as usize],
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
        self.inner.seek(SeekFrom::Start(offset))?;

        // Read encrypted data into the buffer.
        self.inner.read_exact(&mut self.sector_buffer)?;

        // Decrypt the data in-place using the volume's decrypt_sector method.
        self.volume
            .decrypt_sector(sector_index, &mut self.sector_buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decrypt error: {}", e)))?;

        // Update the current sector index.
        self.current_sector_index = sector_index;
        // Return success.
        Ok(())
    }
}

// Implement Read trait for DecryptedReader.
impl Read for DecryptedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If the output buffer is empty, return 0.
        if buf.is_empty() {
            return Ok(0);
        }

        // Get the current position in the stream.
        let current_pos = self.inner.stream_position()?;
        // Calculate the sector index containing the current position.
        let sector_index = current_pos / self.sector_size;
        // Calculate the offset within that sector.
        let offset_in_sector = (current_pos % self.sector_size) as usize;

        // Ensure the correct sector is loaded and decrypted.
        self.read_sector(sector_index)?;

        // Calculate how many bytes are available in the current sector from the current offset.
        let available = self.sector_size as usize - offset_in_sector;
        // Determine how many bytes to read (min of requested and available).
        let to_read = std::cmp::min(buf.len(), available);

        // Copy the decrypted data to the output buffer.
        buf[..to_read]
            .copy_from_slice(&self.sector_buffer[offset_in_sector..offset_in_sector + to_read]);

        // Advance the underlying reader's position.
        // Note: read_sector seeks to the start of the sector, so we need to restore/advance position.
        // Actually, read_sector seeks to 'offset'. After read_exact, position is at end of sector.
        // But we want to simulate a continuous stream.
        // We update the position to reflect the bytes "read".
        self.inner
            .seek(SeekFrom::Start(current_pos + to_read as u64))?;

        // Return the number of bytes read.
        Ok(to_read)
    }
}

// Implement Seek trait for DecryptedReader.
impl Seek for DecryptedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Delegate seek to the underlying reader.
        self.inner.seek(pos)
    }
}

// Enum representing supported file systems.
pub enum SupportedFileSystem {
    // NTFS file system wrapper.
    Ntfs(DecryptedReader),
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
        // Split the path into components.
        let components: Vec<&str> = if path.is_empty() {
            // If path is empty, it's the root directory.
            Vec::new()
        } else {
            // Split by forward slash.
            path.split('/').collect()
        };

        match self {
            // Handle NTFS file system.
            SupportedFileSystem::Ntfs(reader) => {
                reader.seek(SeekFrom::Start(0))?;
                let ntfs = Ntfs::new(&mut *reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                // Start at the root directory.
                let mut current_dir = ntfs
                    .root_directory(&mut *reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                // Traverse the directory structure based on path components.
                for component in components {
                    // Get the index of the current directory.
                    let index = current_dir
                        .directory_index(&mut *reader)
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
                                current_dir = ntfs.file(&mut *reader, id).map_err(|e| {
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
                    .directory_index(&mut *reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let mut results = Vec::new();
                // Iterate through entries to collect file info.
                let mut entries = index.entries();
                while let Some(entry_res) = entries.next(&mut *reader) {
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
        // Split path into components.
        let components: Vec<&str> = if path.is_empty() {
            // Cannot read root as a file.
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty path"));
        } else {
            path.split('/').collect()
        };

        // Separate the file name from the directory path components.
        let (file_name, dir_components) = components.split_last().ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path components"))?;

        match self {
            // Handle NTFS file system.
            SupportedFileSystem::Ntfs(reader) => {
                reader.seek(SeekFrom::Start(0))?;
                let ntfs = Ntfs::new(&mut *reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                // Start at root.
                let mut current_dir = ntfs
                    .root_directory(&mut *reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                // Traverse directories.
                for component in dir_components {
                    let index = current_dir
                        .directory_index(&mut *reader)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    let mut found = false;
                    let mut entries = index.entries();
                    while let Some(entry) = entries.next(&mut *reader) {
                        let entry: ntfs::NtfsIndexEntry<ntfs::indexes::NtfsFileNameIndex> = entry?;
                        let key = entry.key().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key error: {}", e)))?;
                        if let Some(key) = key {
                            if key.name().to_string_lossy() == *component && key.is_directory() {
                                let id = entry.file_reference().file_record_number();
                                current_dir = ntfs.file(&mut *reader, id).map_err(|e| {
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
                    .directory_index(&mut *reader)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                let mut entries = index.entries();
                while let Some(entry) = entries.next(&mut *reader) {
                    let entry: ntfs::NtfsIndexEntry<ntfs::indexes::NtfsFileNameIndex> = entry?;
                    let key = entry.key().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key error: {}", e)))?;
                    if let Some(key) = key {
                        // Check if entry name matches file name.
                        if key.name().to_string_lossy() == *file_name {
                            // Convert entry to file.
                            let id = entry.file_reference().file_record_number();
                            let file = ntfs
                                .file(&mut *reader, id)
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                            // Get data attribute (content).
                            let data = file.data(&mut *reader, "");
                            if let Some(attr_res) = data {
                                let attr_item = attr_res
                                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                let attr = attr_item.to_attribute().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                let mut value = attr
                                    .value(&mut *reader)
                                    .map_err(|e: ntfs::NtfsError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                // Seek to the requested offset.
                                value.seek(&mut *reader, SeekFrom::Start(offset)).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                                // Read data into buffer.
                                return value.read(&mut *reader, buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()));
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
