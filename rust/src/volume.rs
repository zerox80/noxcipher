use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Mutex;
use std::io::{Read, Seek, SeekFrom, Write};
use std::fmt;

#[derive(Debug)]
pub enum VolumeError {
    Io(std::io::Error),
    NotUnlocked,
    InvalidPassword,
    FileNotFound,
    FsError(String),
    InvalidPath, // Bug 8 Fix: Added specific error for invalid paths
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VolumeError::Io(err) => write!(f, "IO Error: {}", err),
            VolumeError::NotUnlocked => write!(f, "Volume not unlocked"),
            VolumeError::InvalidPassword => write!(f, "Invalid password"),
            VolumeError::FileNotFound => write!(f, "File not found"),
            VolumeError::FsError(msg) => write!(f, "Filesystem Error: {}", msg),
            VolumeError::InvalidPath => write!(f, "Invalid path containing traversal"),
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
}

// Wrapper to implement fatfs::IoBase for std::fs::File
struct StdIoWrapper {
    inner: File,
}

impl StdIoWrapper {
    fn new(file: File) -> Self {
        Self { inner: file }
    }
}

impl Read for StdIoWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for StdIoWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for StdIoWrapper {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl fatfs::IoBase for StdIoWrapper {
    type Error = std::io::Error;
}

pub struct VolumeManager {
    // Bug 5 Fix: Store the FileSystem instance to avoid re-opening it.
    // We need to store it in an Option because it's initialized later.
    // fatfs::FileSystem owns the IO stream (StdIoWrapper).
    fs: Option<fatfs::FileSystem<StdIoWrapper>>,
}

// Send is required for Mutex. fatfs::FileSystem is Send if IO is Send. File is Send.
unsafe impl Send for VolumeManager {}

impl VolumeManager {
    pub fn new() -> Self {
        Self { fs: None }
    }

    pub fn unlock(&mut self, fd: RawFd, _password: &[u8]) -> Result<(), VolumeError> {
        // SAFETY: We duplicate the FD so we own a copy.
        let new_fd = unsafe { libc::dup(fd) };
        if new_fd < 0 {
             return Err(VolumeError::Io(std::io::Error::last_os_error()));
        }

        // Verify we can read
        let mut file = unsafe { File::from_raw_fd(new_fd) };
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            return Err(VolumeError::Io(e));
        }

        // In a real app, we would use the password to mount a dm-crypt/LUKS volume here.
        // For this fix, we assume the FD points to a FAT32 volume directly (or decrypted device).
        
        // Create wrapper and FS
        let wrapper = StdIoWrapper::new(file);
        let fs = fatfs::FileSystem::new(wrapper, fatfs::FsOptions::new())
            .map_err(|e| VolumeError::FsError(format!("{:?}", e)))?;

        self.fs = Some(fs);
        
        log::info!("Volume unlocked successfully. FS initialized.");
        Ok(())
    }

    pub fn list_files(&self, path: &str) -> Result<Vec<String>, VolumeError> {
        // Bug 2 Fix: Prevent path traversal
        if path.contains("..") {
            return Err(VolumeError::InvalidPath);
        }

        let fs = self.fs.as_ref().ok_or(VolumeError::NotUnlocked)?;
        let root = fs.root_dir();
        
        // Bug 6 Fix: Correctly handle root path and subdirectories
        let dir = if path == "/" || path.is_empty() {
            root
        } else {
            // Trim leading slash if present, as open_dir expects relative path
            let relative_path = path.trim_start_matches('/');
            if relative_path.is_empty() {
                root
            } else {
                root.open_dir(relative_path).map_err(|_| VolumeError::FileNotFound)?
            }
        };

        let mut files = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(|e| VolumeError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))))?;
            // Bug 10 Fix: Append slash to directories to indicate type
            let name = if entry.is_dir() {
                format!("{}/", entry.file_name())
            } else {
                entry.file_name()
            };
            files.push(name);
        }
        
        Ok(files)
    }

    pub fn read_file(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>, VolumeError> {
        // Bug 2 Fix: Prevent path traversal
        if path.contains("..") {
            return Err(VolumeError::InvalidPath);
        }

        // Bug 10 Fix: Prevent unbounded allocation (OOM attack)
        // Limit read size to a reasonable maximum (e.g., 16MB)
        const MAX_READ_SIZE: usize = 16 * 1024 * 1024;
        if length > MAX_READ_SIZE {
            return Err(VolumeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Read length too large")));
        }

        let fs = self.fs.as_ref().ok_or(VolumeError::NotUnlocked)?;
        let root = fs.root_dir();
        
        // Handle path correctly
        let relative_path = path.trim_start_matches('/');
        let mut file = root.open_file(relative_path).map_err(|_| VolumeError::FileNotFound)?;
        
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).map_err(VolumeError::Io)?;
        }
        
        let mut buffer = vec![0u8; length];
        let bytes_read = file.read(&mut buffer).map_err(VolumeError::Io)?;
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
}

// Drop is handled automatically for fs (which drops wrapper, which drops File, which closes FD)
