use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Mutex;
use std::io::{Read, Seek, SeekFrom};
use std::fmt;

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

pub struct VolumeManager {
    file: Option<std::mem::ManuallyDrop<File>>,
}

use std::mem::ManuallyDrop;

impl VolumeManager {
    pub fn new() -> Self {
        Self { file: None }
    }

    pub fn unlock(&mut self, fd: RawFd, password: &str) -> Result<(), VolumeError> {
        // SAFETY: We take ownership temporarily to check the password.
        // If we fail, we MUST release ownership back to the caller (by returning the raw FD)
        // so we don't close it.
        let mut file = unsafe { File::from_raw_fd(fd) };
        
        // Verify we can read
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            let _ = file.into_raw_fd(); // Release ownership
            return Err(VolumeError::Io(e));
        }

        // Simple "Password Check" (In reality, this would attempt decryption)
        if password.is_empty() {
            let _ = file.into_raw_fd(); // Release ownership
            return Err(VolumeError::InvalidPassword);
        }

        self.file = Some(ManuallyDrop::new(file));
        log::info!("Volume unlocked successfully with fd: {}", fd);
        Ok(())
    }

    pub fn list_files(&self, _path: &str) -> Result<Vec<String>, VolumeError> {
        if self.file.is_none() {
            return Err(VolumeError::NotUnlocked);
        }
        
        // Since we don't have a real filesystem driver, we expose the raw volume as a single file.
        Ok(vec!["raw_volume.img".to_string()])
    }

    pub fn read_file(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>, VolumeError> {
        match &self.file {
            Some(file) => {
                // Removed hardcoded path check to allow reading any file reported by list_files
                // if path != "raw_volume.img" {
                //     return Err(VolumeError::FileNotFound);
                // }

                use std::os::unix::fs::FileExt;
                
                let mut buffer = vec![0u8; length];
                let bytes_read = file.read_at(&mut buffer, offset)?;
                buffer.truncate(bytes_read);
                Ok(buffer)
            }
            None => Err(VolumeError::NotUnlocked),
        }
    }
}

// Global state
lazy_static::lazy_static! {
    pub static ref VOLUME_MANAGER: Mutex<VolumeManager> = Mutex::new(VolumeManager::new());
}
