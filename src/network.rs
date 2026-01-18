use crate::{FilePath, HashAlgorithms, constants::*, protocol::PacketSize};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{Duration, timeout},
};

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

    #[error("Unknown OpCode: {0}")]
    UnknownOpCode(u8),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProtocolMessage {
    TaskRequest(TaskRequest),
    TaskResponse(TaskResponse)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskResponse {
    Success(String),
    Failed
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TaskRequest {
    HashPacket(HashingPacket),
}

impl ProtocolMessage {
    pub fn into_packet(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut buffer = vec![0u8; 2];

        bincode::serialize_into(&mut buffer, &self)?;

        let payload_len = (buffer.len() - 2) as u16;

        let len_bytes = payload_len.to_be_bytes();
        buffer[0] = len_bytes[0];
        buffer[1] = len_bytes[1];

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
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = PacketSize::from_slice(&len_buf);

        let mut payload = vec![0u8; packet_len.into()];
        stream.read_exact(&mut payload).await?;
        let task: ProtocolMessage = bincode::deserialize(&payload)?;
        Ok(task)
    };

    timeout(read_timeout, read_future).await?
}
