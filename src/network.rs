use crate::{FilePath, HashAlgorithms, constants::*, protocol::PacketSize};
use bincode::Options;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{Duration, timeout},
};
fn bincode_config() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_PACKET_SIZE as u64)
        .with_big_endian()
        .with_fixint_encoding()
}
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Packet too short must be more that two bytes")]
    PacketTooShort,

    #[error("Packet exceeds maximum size of {0} bytes")]
    PacketTooLarge(usize),

    #[error("Bincode failure: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Request has timed out {0}")]
    TimeOutError(#[from] tokio::time::error::Elapsed),

    #[error("Structure was too big to send")]
    InternalLimitExceeded,

    #[error("Unknown OpCode: {0}")]
    UnknownOpCode(u8),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProtocolMessage {
    TaskRequest(TaskRequest),
    TaskResponse(TaskResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskResponse {
    Success(String),
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskRequest {
    HashPacket(HashingPacket),
}

impl ProtocolMessage {
    pub fn into_packet(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload_size = bincode_config()
            .serialized_size(self)
            .map_err(|e| ProtocolError::Bincode(e))? as usize;

        if payload_size > MAX_PACKET_SIZE {
            return Err(ProtocolError::PacketTooLarge(payload_size));
        }

        let mut buffer = Vec::with_capacity(4 + payload_size);

        buffer.extend_from_slice(&(payload_size as u32).to_be_bytes());

        bincode_config()
            .serialize_into(&mut buffer, self)
            .map_err(|e| ProtocolError::Bincode(e))?;

        Ok(buffer)
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct HashingPacket {
    pub algorithm: HashAlgorithms,
    pub path: FilePath,
}

impl HashingPacket {
    pub fn algorithm(&self) -> &HashAlgorithms {
        &self.algorithm
    }

    pub fn path(&self) -> &FilePath {
        &self.path
    }
}

pub async fn read_protocol(stream: &mut TcpStream) -> Result<ProtocolMessage, ProtocolError> {
    let read_timeout = Duration::from_secs(5);
    let read_future = async {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_size = PacketSize::from_slice(&len_buf)?;

        let len = packet_size.into();

        if len > MAX_PACKET_SIZE {
            return Err(ProtocolError::PacketTooLarge(len));
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;
        let task: ProtocolMessage = bincode_config().deserialize(&payload)?;

        Ok(task)
    };

    timeout(read_timeout, read_future).await?
}
