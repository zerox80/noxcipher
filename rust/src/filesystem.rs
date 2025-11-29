// Import standard I/O traits and types.
use std::io::{self, Read, Seek, SeekFrom};
// Import Arc for shared ownership.
use std::sync::Arc;
// Import Volume struct from volume module.
use crate::volume::Volume;
// Import CallbackReader from io_callback module.
use crate::io_callback::CallbackReader;
// Import NTFS implementation.
use ntfs::Ntfs;
// Import ExFAT implementation.
use exfat::ExFat;

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
        self.volume.decrypt_sector(sector_index, &mut self.sector_buffer)
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
        buf[..to_read].copy_from_slice(&self.sector_buffer[offset_in_sector..offset_in_sector + to_read]);
        
        // Advance the underlying reader's position.
        // Note: read_sector seeks to the start of the sector, so we need to restore/advance position.
        // Actually, read_sector seeks to 'offset'. After read_exact, position is at end of sector.
        // But we want to simulate a continuous stream.
        // We update the position to reflect the bytes "read".
        self.inner.seek(SeekFrom::Start(current_pos + to_read as u64))?;
        
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
    Ntfs(Ntfs<DecryptedReader>),
    // ExFAT file system wrapper.
    ExFat(ExFat<DecryptedReader>),
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
            SupportedFileSystem::Ntfs(ntfs) => {
                // Start at the root directory.
                let mut current_dir = ntfs.root_directory();
                
                // Traverse the directory structure based on path components.
                for component in components {
                    // Get the index of the current directory.
                    let index = current_dir.directory_index();
                    let mut found = false;
                    // Iterate through entries in the directory.
                    for entry in index.entries() {
                        let entry = entry?;
                        // Check if the entry name matches the current component.
                        if entry.name().to_string_lossy() == component {
                            // If it's a directory, descend into it.
                            if entry.is_directory() {
                                current_dir = entry.to_directory()?;
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
                let index = current_dir.directory_index();
                let mut results = Vec::new();
                // Iterate through entries to collect file info.
                for entry in index.entries() {
                    let entry = entry?;
                    // Get the name of the entry.
                    let name = entry.name().to_string_lossy();
                    // Skip current and parent directory entries.
                    if name == "." || name == ".." { continue; }
                    
                    // Determine if it's a directory.
                    let is_dir = entry.is_directory();
                    // Get the size of the entry.
                    let size = entry.data_size();
                    // Add to results.
                    results.push(FileInfo { name: name.into_owned(), is_dir, size });
                }
                // Return the list of files.
                Ok(results)
            },
            // Handle ExFAT file system.
            SupportedFileSystem::ExFat(exfat) => {
                // Start at the root directory.
                let mut current_dir = exfat.root_directory();
                
                // Traverse the directory structure.
                for component in components {
                    let mut found = false;
                    // Iterate through entries in the current directory.
                    for entry in current_dir.entries() {
                        let entry = entry?;
                        // Check if entry name matches component.
                        if entry.name() == component {
                            // If it's a directory, descend into it.
                            if entry.is_dir() {
                                current_dir = entry.to_dir()?;
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

                // We are at the target directory. Collect entries.
                let mut results = Vec::new();
                for entry in current_dir.entries() {
                    let entry = entry?;
                    let name = entry.name();
                    // Skip special entries if any (ExFAT usually doesn't have . and .. in iteration like NTFS/FAT might, but good to be safe or maybe not needed).
                     if name == "." || name == ".." { continue; }
                     // Add to results.
                     results.push(FileInfo { name: name.to_string(), is_dir: entry.is_dir(), size: entry.len() });
                }
                // Return the list of files.
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
        let (file_name, dir_components) = components.split_last().unwrap();

        match self {
            // Handle NTFS file system.
            SupportedFileSystem::Ntfs(ntfs) => {
                // Start at root.
                let mut current_dir = ntfs.root_directory();
                // Traverse directories.
                for component in dir_components {
                    let index = current_dir.directory_index();
                    let mut found = false;
                    for entry in index.entries() {
                        let entry = entry?;
                        if entry.name().to_string_lossy() == *component {
                            if entry.is_directory() {
                                current_dir = entry.to_directory()?;
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
                let index = current_dir.directory_index();
                for entry in index.entries() {
                    let entry = entry?;
                    // Check if entry name matches file name.
                    if entry.name().to_string_lossy() == *file_name {
                         // Convert entry to file.
                         let file = entry.to_file()?;
                         // Get data attribute (content).
                         let mut data = file.data(ntfs, "");
                         if let Some(mut attr) = data {
                             // Seek to the requested offset.
                             attr.seek(SeekFrom::Start(offset))?;
                             // Read data into buffer.
                             return attr.read(buf);
                         }
                    }
                }
                // File not found.
                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            },
            // Handle ExFAT file system.
            SupportedFileSystem::ExFat(exfat) => {
                // Start at root.
                let mut current_dir = exfat.root_directory();
                // Traverse directories.
                for component in dir_components {
                    let mut found = false;
                    for entry in current_dir.entries() {
                        let entry = entry?;
                        if entry.name() == *component {
                            if entry.is_dir() {
                                current_dir = entry.to_dir()?;
                                found = true;
                                break;
                            }
                        }
                    }
                    if !found {
                         return Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"));
                    }
                }

                // Look for the file.
                for entry in current_dir.entries() {
                    let entry = entry?;
                    if entry.name() == *file_name {
                        // Ensure it is a file, not a directory.
                        if !entry.is_dir() {
                            // Convert to file.
                            let mut file = entry.to_file()?;
                            // Seek to offset.
                            file.seek(SeekFrom::Start(offset))?;
                            // Read data.
                            return file.read(buf);
                        }
                    }
                }
                // File not found.
                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            }
        }
    }
}
