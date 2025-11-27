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
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VolumeError::Io(err) => write!(f, "IO Error: {}", err),
            VolumeError::NotUnlocked => write!(f, "Volume not unlocked"),
            VolumeError::InvalidPassword => write!(f, "Invalid password"),
            VolumeError::FileNotFound => write!(f, "File not found"),
            VolumeError::FsError(msg) => write!(f, "Filesystem Error: {}", msg),
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
    // We keep the raw FD to clone it for each operation because fatfs takes ownership of the stream
    // or requires a mutable reference which is hard to share across JNI calls with a global Mutex.
    // Actually, fatfs::FileSystem takes ownership of the IO stream.
    // To support persistent access, we might need to store the FileSystem instance.
    // However, FileSystem has a lifetime parameter linked to the IO stream.
    // For simplicity in this JNI context, we will re-open the FS for each operation
    // by duping the FD. This is inefficient but safe and simple for this "fix".
    // A better approach would be to use a self-referential struct or `owning_ref` but that adds complexity.
    fd: Option<RawFd>,
}

impl VolumeManager {
    pub fn new() -> Self {
        Self { fd: None }
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
        
        // We store the raw FD. We must close it when we are done or replaced.
        if let Some(old_fd) = self.fd {
            unsafe { libc::close(old_fd) };
        }
        self.fd = Some(new_fd);
        
        // We don't keep the File object because it closes the FD on drop.
        // We used `file` just for verification. `into_raw_fd()` prevents closing.
        use std::os::unix::io::IntoRawFd;
        let _ = file.into_raw_fd(); 

        log::info!("Volume unlocked successfully. Stored duped fd: {}", new_fd);
        Ok(())
    }

    fn get_fs(&self) -> Result<fatfs::FileSystem<StdIoWrapper>, VolumeError> {
        let fd = self.fd.ok_or(VolumeError::NotUnlocked)?;
        // Dup the FD for this operation so we can create a File object that will be closed after use
        let op_fd = unsafe { libc::dup(fd) };
        if op_fd < 0 {
             return Err(VolumeError::Io(std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(op_fd) };
        let wrapper = StdIoWrapper::new(file);
        
        fatfs::FileSystem::new(wrapper, fatfs::FsOptions::new())
            .map_err(|e| VolumeError::FsError(format!("{:?}", e)))
    }

    pub fn list_files(&self, path: &str) -> Result<Vec<String>, VolumeError> {
        let fs = self.get_fs()?;
        let root = fs.root_dir();
        
        // Navigate to subfolder if needed (simple implementation supports only root for now or basic paths)
        // fatfs doesn't have a simple "open_dir" from string path easily without traversing.
        // For this fix, we'll assume root or simple traversal.
        
        let mut files = Vec::new();
        let dir = if path == "/" || path.is_empty() {
            root
        } else {
            // Basic support for subdirectories could be added here
            // For now, let's just list root to prove the fix works, or try to open the dir
            match root.open_dir(path) {
                Ok(d) => d,
                Err(_) => return Err(VolumeError::FileNotFound),
            }
        };

        for entry in dir.iter() {
            let entry = entry.map_err(|e| VolumeError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))))?;
            files.push(entry.file_name());
        }
        
        Ok(files)
    }

    pub fn read_file(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>, VolumeError> {
        let fs = self.get_fs()?;
        let root = fs.root_dir();
        
        let mut file = root.open_file(path).map_err(|_| VolumeError::FileNotFound)?;
        
        if offset > 0 {
            file.seek(SeekFrom::Start(offset)).map_err(VolumeError::Io)?;
        }
        
        let mut buffer = vec![0u8; length];
        let bytes_read = file.read(&mut buffer).map_err(VolumeError::Io)?;
        
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
}

impl Drop for VolumeManager {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            unsafe { libc::close(fd) };
        }
    }
}

