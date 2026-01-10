// File Operations for RSA Encryption/Decryption
// Handles reading, writing, and chunked processing of files

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Errors that can occur during file operations
#[derive(Debug)]
pub enum FileError {
    IoError(io::Error),
    InvalidFileSize,
    FileTooLarge,
    InvalidChunk,
    KeySizeMismatch { expected: usize, actual: usize },
    CryptoError(String),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileError::IoError(e) => write!(f, "IO error: {}", e),
            FileError::InvalidFileSize => write!(f, "Invalid file size"),
            FileError::FileTooLarge => write!(f, "File too large"),
            FileError::InvalidChunk => write!(f, "Invalid chunk"),
            FileError::KeySizeMismatch { expected, actual } => {
                write!(f, "Key size mismatch: expected {}, got {}", expected, actual)
            }
            FileError::CryptoError(e) => write!(f, "Crypto error: {}", e),
        }
    }
}

impl std::error::Error for FileError {}

impl From<io::Error> for FileError {
    fn from(e: io::Error) -> Self {
        FileError::IoError(e)
    }
}

/// Result type for file operations
pub type FileResult<T> = Result<T, FileError>;

/// Configuration for file encryption/decryption
#[derive(Clone, Debug)]
pub struct FileConfig {
    pub chunk_size: usize,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            chunk_size: 190,
        }
    }
}

/// A progress indicator for file operations
#[derive(Clone, Debug)]
pub struct Progress {
    pub current: u64,
    pub total: u64,
    pub percent: f64,
}

impl Progress {
    pub fn new(current: u64, total: u64) -> Self {
        let percent = if total > 0 {
            (current as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Self {
            current,
            total,
            percent,
        }
    }
}

/// Read entire file into memory
pub fn read_file(path: &PathBuf) -> FileResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

/// Write data to file
pub fn write_file(path: &PathBuf, data: &[u8]) -> FileResult<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Append data to file
pub fn append_file(path: &PathBuf, data: &[u8]) -> FileResult<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Get file size in bytes
pub fn get_file_size(path: &PathBuf) -> FileResult<u64> {
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.len())
}

/// Format file size for display
pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Set progress callback
impl FileConfig {
    pub fn with_progress<F>(mut self, _callback: F) -> Self
    where
        F: Fn(f64) + 'static,
    {
        self
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
}
