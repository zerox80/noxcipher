#[derive(Debug)]
pub enum NoxError {
    MountFailed,
    InvalidPassword,
    IoError(std::io::Error),
    CryptoError,
}

impl From<std::io::Error> for NoxError {
    fn from(err: std::io::Error) -> Self {
        NoxError::IoError(err)
    }
}
