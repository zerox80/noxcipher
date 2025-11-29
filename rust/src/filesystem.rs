use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;
use crate::volume::Volume;
use crate::io_callback::CallbackReader;
use ntfs::Ntfs;
use exfat::ExFat;

#[derive(Clone)]
pub struct DecryptedReader {
    inner: CallbackReader,
    volume: Arc<Volume>,
    sector_size: u64,
    current_sector_index: u64,
    sector_buffer: Vec<u8>,
}

impl DecryptedReader {
    pub fn new(inner: CallbackReader, volume: Arc<Volume>) -> Self {
        let sector_size = volume.sector_size() as u64;
        Self {
            inner,
            volume,
            sector_size,
            current_sector_index: u64::MAX, // Invalid
            sector_buffer: vec![0; sector_size as usize],
        }
    }

    fn read_sector(&mut self, sector_index: u64) -> io::Result<()> {
        if self.current_sector_index == sector_index {
            return Ok(());
        }

        let offset = sector_index * self.sector_size;
        self.inner.seek(SeekFrom::Start(offset))?;
        
        // Read encrypted data
        self.inner.read_exact(&mut self.sector_buffer)?;
        
        // Decrypt in-place
        self.volume.decrypt_sector(sector_index, &mut self.sector_buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decrypt error: {}", e)))?;
            
        self.current_sector_index = sector_index;
        Ok(())
    }
}

impl Read for DecryptedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let current_pos = self.inner.stream_position()?;
        let sector_index = current_pos / self.sector_size;
        let offset_in_sector = (current_pos % self.sector_size) as usize;
        
        self.read_sector(sector_index)?;
        
        let available = self.sector_size as usize - offset_in_sector;
        let to_read = std::cmp::min(buf.len(), available);
        
        buf[..to_read].copy_from_slice(&self.sector_buffer[offset_in_sector..offset_in_sector + to_read]);
        
        self.inner.seek(SeekFrom::Start(current_pos + to_read as u64))?;
        
        Ok(to_read)
    }
}

impl Seek for DecryptedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub enum SupportedFileSystem {
    Ntfs(Ntfs<DecryptedReader>),
    ExFat(ExFat<DecryptedReader>),
}

pub struct FileInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

impl SupportedFileSystem {
    pub fn list_files(&mut self, path: &str) -> io::Result<Vec<FileInfo>> {
        let path = path.trim_matches('/');
        let components: Vec<&str> = if path.is_empty() {
            Vec::new()
        } else {
            path.split('/').collect()
        };

        match self {
            SupportedFileSystem::Ntfs(ntfs) => {
                let mut current_dir = ntfs.root_directory();
                
                for component in components {
                    let index = current_dir.directory_index();
                    let mut found = false;
                    for entry in index.entries() {
                        let entry = entry?;
                        if entry.name().to_string_lossy() == component {
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

                let index = current_dir.directory_index();
                let mut results = Vec::new();
                for entry in index.entries() {
                    let entry = entry?;
                    let name = entry.name().to_string_lossy();
                    if name == "." || name == ".." { continue; }
                    
                    let is_dir = entry.is_directory();
                    let size = entry.data_size();
                    results.push(FileInfo { name: name.into_owned(), is_dir, size });
                }
                Ok(results)
            },
            SupportedFileSystem::ExFat(exfat) => {
                let mut current_dir = exfat.root_directory();
                
                for component in components {
                    let mut found = false;
                    for entry in current_dir.entries() {
                        let entry = entry?;
                        if entry.name() == component {
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

                let mut results = Vec::new();
                for entry in current_dir.entries() {
                    let entry = entry?;
                    let name = entry.name();
                     if name == "." || name == ".." { continue; }
                     results.push(FileInfo { name: name.to_string(), is_dir: entry.is_dir(), size: entry.len() });
                }
                Ok(results)
            }
        }
    }

    pub fn read_file(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let path = path.trim_matches('/');
        let components: Vec<&str> = if path.is_empty() {
             return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty path"));
        } else {
            path.split('/').collect()
        };
        
        let (file_name, dir_components) = components.split_last().unwrap();

        match self {
            SupportedFileSystem::Ntfs(ntfs) => {
                let mut current_dir = ntfs.root_directory();
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
                
                let index = current_dir.directory_index();
                for entry in index.entries() {
                    let entry = entry?;
                    if entry.name().to_string_lossy() == *file_name {
                         let file = entry.to_file()?;
                         let mut data = file.data(ntfs, "");
                         if let Some(mut attr) = data {
                             attr.seek(SeekFrom::Start(offset))?;
                             return attr.read(buf);
                         }
                    }
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            },
            SupportedFileSystem::ExFat(exfat) => {
                let mut current_dir = exfat.root_directory();
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

                for entry in current_dir.entries() {
                    let entry = entry?;
                    if entry.name() == *file_name {
                        if !entry.is_dir() {
                            let mut file = entry.to_file()?;
                            file.seek(SeekFrom::Start(offset))?;
                            return file.read(buf);
                        }
                    }
                }
                Err(io::Error::new(io::ErrorKind::NotFound, "File not found"))
            }
        }
    }
}
