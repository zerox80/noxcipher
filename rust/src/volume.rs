use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Mutex;
use std::io::{Read, Seek, SeekFrom};
use std::fmt;
use std::collections::HashMap;

#[derive(Debug)]
pub enum VolumeError {
    Io(std::io::Error),
    NotUnlocked,
    InvalidPassword,
    FileNotFound,
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VolumeError::Io(err) => write!(f, "IO Error: {}", err),
            VolumeError::NotUnlocked => write!(f, "Volume not unlocked"),
            VolumeError::InvalidPassword => write!(f, "Invalid password"),
            VolumeError::FileNotFound => write!(f, "File not found"),
        }
    }
}

impl From<std::io::Error> for VolumeError {
    fn from(err: std::io::Error) -> Self {
        VolumeError::Io(err)
    }
}

lazy_static::lazy_static! {
    pub static ref VOLUME_MANAGER: Mutex<VolumeManager> = Mutex::new(VolumeManager::new());
    static ref MOCK_FILES: HashMap<&'static str, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert("readme.txt", b"This is a secure volume.\n".to_vec());
        m.insert("secret.bin", vec![0xCA, 0xFE, 0xBA, 0xBE]);
        m.insert("photos/vacation.jpg", vec![0xFF, 0xD8, 0xFF, 0xE0]); // Mock JPEG header
        m
    };
}

pub struct VolumeManager {
    // We use Option<File> which automatically closes the FD on drop/replace
    file: Option<File>,
}

impl VolumeManager {
    pub fn new() -> Self {
        Self { file: None }
    }

    pub fn unlock(&mut self, fd: RawFd, password: &[u8]) -> Result<(), VolumeError> {
        // SAFETY: We duplicate the FD so we own a copy.
        let new_fd = unsafe { libc::dup(fd) };
        if new_fd < 0 {
             return Err(VolumeError::Io(std::io::Error::last_os_error()));
        }

        let mut file = unsafe { File::from_raw_fd(new_fd) };
        
        // Verify we can read
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            return Err(VolumeError::Io(e));
        }

        // Mock Password Check (TODO: Real decryption)
        if password.is_empty() {
             return Err(VolumeError::InvalidPassword);
        }

        self.file = Some(file); // Old file is dropped and closed automatically
        log::info!("Volume unlocked successfully. Using duped fd: {}", new_fd);
        Ok(())
    }

    pub fn list_files(&self, path: &str) -> Result<Vec<String>, VolumeError> {
        if self.file.is_none() {
            return Err(VolumeError::NotUnlocked);
        }
        
        // Check if FD is still valid by attempting a seek (cheap check)
        // This handles the case where the device was detached but we still hold the FD object.
        if let Some(file) = self.file.as_ref() {
             // We need mutable access to seek, but we only have &self. 
             // However, File internal state is mutable. But Rust File requires &mut for seek.
             // We can try metadata() which takes &self.
             if file.metadata().is_err() {
                 return Err(VolumeError::Io(std::io::Error::from_raw_os_error(libc::EBADF)));
             }
        }

        // Mock file system structure based on MOCK_FILES
        let mut files = Vec::new();
        let normalized_path = path.trim_start_matches('/');
        
        // Simple mock directory listing
        if normalized_path.is_empty() {
             files.push("readme.txt".to_string());
             files.push("secret.bin".to_string());
             files.push("photos/".to_string());
        } else if normalized_path == "photos" || normalized_path == "photos/" {
             files.push("vacation.jpg".to_string());
        }
        
        Ok(files)
    }

    pub fn read_file(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>, VolumeError> {
        if self.file.is_none() {
            return Err(VolumeError::NotUnlocked);
        }

        // Check FD validity
        if let Some(file) = self.file.as_ref() {
             if file.metadata().is_err() {
                 return Err(VolumeError::Io(std::io::Error::from_raw_os_error(libc::EBADF)));
             }
        }
        
        let normalized_path = path.trim_start_matches('/');
        // Handle "photos/vacation.jpg" vs just "vacation.jpg" if inside photos/
        // For this simple mock, we'll just check if the key ends with the requested filename or matches exactly
        
        let content = MOCK_FILES.iter()
            .find(|(k, _)| *k == normalized_path || k.ends_with(normalized_path))
            .map(|(_, v)| v)
            .ok_or(VolumeError::FileNotFound)?;

        // Simulate reading from the "file"
        let start = offset as usize;
        if start >= content.len() {
            return Ok(Vec::new());
        }
        let end = std::cmp::min(start + length, content.len());
        Ok(content[start..end].to_vec())
    }
}
