use crate::workers::Task;
use crate::protocol::PacketSize;
use crate::{FilePath, HashAlgorithms};
use std::fmt;
use std::string::FromUtf8Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio::time::timeout;
use crate::constants::*;

#[derive(Debug)]
pub enum PacketError {
    TooShort,
    Utf8Error(FromUtf8Error),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::TooShort => write!(f, "Packet too short"),
            PacketError::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
        }
    }
}

impl From<FromUtf8Error> for PacketError {
    fn from(e: FromUtf8Error) -> Self {
        PacketError::Utf8Error(e)
    }
}

#[derive(Debug)]
pub struct TaskPacket {
    task: Task,
    payload: Vec<u8>,
}
impl TaskPacket {
    pub fn task(&self) -> &Task {
        &self.task
    }
    pub fn payload(&self) -> &Vec<u8> {
        &self.payload
    }
}
#[derive(Debug)]
pub struct HashingPacket {
    algorithm: HashAlgorithms,
    path: FilePath,
}

impl HashingPacket {
    fn from_bytes(v: Vec<u8>) -> Self {
        assert!(v.len() >= 2, "Packet too short to parse");

        let algorithm = match v[0] {
            HASH_BLAKE3_CODE => HashAlgorithms::BLAKE3,
            HASH_SHA256_CODE => HashAlgorithms::SHA256,
            HASH_SHAKE256_CODE => HashAlgorithms::SHAKE256,
            _ => HashAlgorithms::UNIMPLEMENTED,
        };

        let path = match v[1] {
            0 => FilePath::Local(
                String::from_utf8(v[2..].to_vec()).unwrap_or_else(|_| "<invalid utf8>".to_string()),
            ),
            1 => FilePath::Remote(
                String::from_utf8(v[2..].to_vec()).unwrap_or_else(|_| "<invalid utf8>".to_string()),
            ),
            _ => FilePath::Local(
                String::from_utf8(v[2..].to_vec()).unwrap_or_else(|_| "<invalid utf8>".to_string()),
            ),
        };

        Self { algorithm, path }
    }
    pub fn algorithm(&self) -> &HashAlgorithms {
        &self.algorithm
    }

    pub fn path(&self) -> &FilePath {
        &self.path
    }

    pub fn try_from_bytes(v: Vec<u8>) -> Result<Self, PacketError> {
        if v.len() < 2 {
            return Err(PacketError::TooShort);
        }

        let algorithm = match v[0] {
            HASH_BLAKE3_CODE => HashAlgorithms::BLAKE3,
            HASH_SHA256_CODE => HashAlgorithms::SHA256,
            HASH_SHAKE256_CODE => HashAlgorithms::SHAKE256,
            _ => HashAlgorithms::UNIMPLEMENTED,
        };

        let path = match v[1] {
            0 => FilePath::Local(String::from_utf8(v[2..].to_vec())?),
            1 => FilePath::Remote(String::from_utf8(v[2..].to_vec())?),
            _ => FilePath::Local(String::from_utf8(v[2..].to_vec())?),
        };

        Ok(Self { algorithm, path })
    }
}

pub async fn read_task(stream: &mut TcpStream) -> tokio::io::Result<TaskPacket> {
    let read_timeout = Duration::from_secs(5);
    let read_future = async {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = PacketSize::from_slice(&len_buf);

        let mut opcode_buf = [0u8; 1];
        stream.read_exact(&mut opcode_buf).await?;

        let task = Task::from_byte(opcode_buf[0]).ok_or_else(|| {
            tokio::io::Error::new(tokio::io::ErrorKind::InvalidData, "Unknown task")
        })?;

        let mut payload = vec![0u8; packet_len.into()];
        stream.read_exact(&mut payload).await?;
        Ok(TaskPacket { task, payload })
    };

    timeout(read_timeout, read_future).await?
}
