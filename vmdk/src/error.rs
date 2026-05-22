use thiserror::Error;

pub type Result<T> = std::result::Result<T, VmdkError>;

#[derive(Debug, Error)]
pub enum VmdkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a VMware VMDK file: bad magic number")]
    BadMagic,
    #[error("unsupported VMDK version: {0}")]
    UnsupportedVersion(u32),
    #[error("compressed VMDKs are not supported")]
    CompressedNotSupported,
    #[error("VMDK file too small")]
    FileTooSmall,
}
