use crate::FilePath;
use digest::Digest;
use std::{
    fmt, fs,
    io::{self, Read},
};



/// Represents failures encountered during the file hashing process.
///
/// This error type is returned by [`hash_reader`]. It distinguishes between configuration gaps (unimplemented features)
/// and environmental issues (filesystem permissions).
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Indicates an attempt to use a feature that is defined but not yet functional.
    ///
    /// Currently, this is returned when a [`FilePath::Remote`] variant is passed 
    /// to the hasher. Remote file streaming is planned for a future release.
    #[error("Remote hashing is not yet implemented")]
    NotImplemented,

    /// Encapsulates failures at the OS or filesystem level.
    ///
    /// This variant is commonly triggered if the file at the provided path 
    /// does not exist, the process lacks read permissions, or the disk 
    /// encounters a hardware failure during streaming.
    ///
    /// # Diagnostic Note
    /// The underlying [`std::io::Error`] provides specific OS error codes 
    /// (e.g., `PermissionDenied` or `NotFound`) to aid in debugging.
    #[error("IO Error: {0}")]
    Io(#[from] io::Error),
}

/// Computes the hash of a given file
/// 
/// This function is generic over any type that implements the [`Digest`] trait,
/// allowing support for all of the sha2 exposed hashing algorithms. It
/// uses a buffer of 8KB to minimize memory usage.
/// 
/// # Error
/// - [`HashError::Io``]: Returned if the file couldn't be read or opened
/// - [`HashError::NotImplemented`]: Returned if the file path is a [`Remote`] which is not implemented yet
/// # Exemples
/// ```
/// use sha2::Sha256;
/// use task_scheduler::{
///     crypto::hash_reader,
///     FilePath,
/// };
/// 
/// let path = FilePath::Local(String::from("/tmp/test.txt"));
/// let result = hash_reader::<Sha256>(&path);
/// ```
pub fn hash_reader<D>(path: &FilePath) -> Result<String, HashError>
where
    D: Digest,
    digest::Output<D>: fmt::LowerHex,
{
    let mut src = match path {
        FilePath::Local(p) => fs::File::open(p)?,
        FilePath::Remote(_) => return Err(HashError::NotImplemented),
    };

    let mut hasher = D::new();
    let mut buffer = [0u8; 8192];

    loop {
        let count = src.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}
