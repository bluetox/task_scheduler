use digest::Digest;
use std::{fmt, fs};
use std::io::{self, Read};
use crate::FilePath;

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("Remote hashing is not yet implemented")]
    NotImplemented,
    #[error("IO Error: {0}")]
    Io(#[from] io::Error),
}

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
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}