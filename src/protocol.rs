use crate::{FilePath, HashAlgorithms, constants::*};
use bincode::Options;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{Duration, timeout},
};

/// Represents failures encountered when reading or writing packets.
/// 
/// This enum categorizes errors arising from network I/O, serialization 
/// mismatches, or security violations (e.g., oversized packets).
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Indicates an incoming buffer is smaller than the required 4-byte header.
    /// 
    /// This is typically returned by [`PacketSize::from_slice`] when the stream 
    /// is closed prematurely.
    #[error("Packet too short; must be at least {MIN_PACKET_SIZE} bytes")]
    PacketTooShort,

    /// Indicates a packet exceeds the security limit [`MAX_PACKET_SIZE`].
    /// 
    /// This prevents an attacker from triggering an Out-of-Memory (OOM) 
    /// condition by claiming a massive payload size in the header.
    #[error("Packet exceeds maximum size of {0} bytes")]
    PacketTooLarge(usize),

    /// Errors occurring during Bincode serialization or deserialization.
    #[error("Bincode failure: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),

    /// Underlying TCP/IP socket errors.
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Triggered when a network operation exceeds the 5-second deadline.
    #[error("Request has timed out: {0}")]
    TimeOutError(#[from] tokio::time::error::Elapsed),

    /// Internal error indicating the serialized structure is physically too large 
    /// to be represented by the protocol.
    #[error("Structure was too big to send")]
    InternalLimitExceeded,
}

/// Top-level container for all network communication.
///
/// This enum follows the Request-Response pattern used by the orchestrator 
/// and worker nodes.
#[derive(Debug, Serialize, Deserialize)]
pub enum ProtocolMessage {
    /// A command sent to a worker to begin a hashing task.
    TaskRequest(TaskRequest),
    /// A response sent back from a worker containing results or failure status.
    TaskResponse(TaskResponse),
}

impl ProtocolMessage {
    /// Serializes the message into a length-prefixed binary frame.
    /// 
    /// The frame consists of a 4-byte Big-Endian length header followed by 
    /// the Bincode-serialized payload.
    ///
    /// # Errors
    /// Returns [`ProtocolError::PacketTooLarge`] if the serialized size 
    /// exceeds [`MAX_PACKET_SIZE`].
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

/// Represents the final outcome of a worker's hashing operation.
///
/// This response is sent back to the orchestrator once the task execution 
/// is complete. It distinguishes between a successfully computed hash 
/// and a terminal failure.
#[derive(Debug, Serialize, Deserialize)]
pub enum TaskResponse {
    /// Indicates the task completed successfully.
    /// 
    /// The contained [`String`] is the hex-encoded result of the hashing 
    /// algorithm applied to the target file.
    Success(String),

    /// Indicates the task could not be completed.
    /// 
    /// This may occur due to missing files, insufficient permissions, 
    /// or unsupported hashing algorithms on the worker side.
    Failed,
}

/// The primary dispatch mechanism for worker assignments.
///
/// This enum acts as a container for all possible work units in the system. 
/// Using an enum ensures that the dispatcher can handle diverse task types 
/// through a single, type-safe interface.
#[derive(Debug, Serialize, Deserialize)]
pub enum TaskRequest {
    /// A request to perform a cryptographic hash on a specific file.
    /// 
    /// The wrapped [`HashingPacket`] defines the target algorithm and 
    /// the file location (local or remote) required for execution.
    HashPacket(HashingPacket),
}

/// Data payload containing the parameters for a hashing operation.
///
/// This structure encapsulates everything a worker needs to execute a task:
/// the specific cryptographic algorithm to use and the location of the target file.
/// It is designed to be serialized as part of a [`TaskRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct HashingPacket {
    /// The cryptographic hash function to be applied (e.g., SHA-256, BLAKE3).
    pub algorithm: HashAlgorithms,
    /// The location of the file to be processed.
    pub path: FilePath,
}

impl HashingPacket {
    /// Returns a reference to the selected [`HashAlgorithms`].
    #[inline]
    pub fn algorithm(&self) -> &HashAlgorithms {
        &self.algorithm
    }

    /// Returns a reference to the target [`FilePath`].
    #[inline]
    pub fn path(&self) -> &FilePath {
        &self.path
    }
}

fn bincode_config() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_PACKET_SIZE as u64)
        .with_big_endian()
        .with_fixint_encoding()
}

/// Reads a [`ProtocolMessage`] from a TCP stream with a 5-second timeout.
/// 
/// This function performs two reads:
/// 1. Reads 4 bytes to determine the payload length.
/// 2. Reads the exact number of bytes specified in the header.
///
/// # Security
/// To prevent resource exhaustion, this function enforces [`MAX_PACKET_SIZE`] 
/// and drops connections that do not complete the transfer within the timeout.
///
/// # Errors
/// Returns [`ProtocolError::TimeOutError`] if the client is too slow.
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

/// A type-safe wrapper representing the size of a protocol packet.
///
/// This struct handles the conversion between the 4-byte network representation 
/// (Big-Endian) and the internal `u32` representation. Using this wrapper 
/// prevents logic errors where raw integers might be used without validation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketSize(u32);

impl PacketSize {
    /// Attempts to parse a `PacketSize` from a raw byte slice.
    ///
    /// This function expects at least 4 bytes in Big-Endian order.
    ///
    /// # Errors
    /// Returns [`ProtocolError::PacketTooShort`] if the input slice has fewer 
    /// than 4 bytes (the minimum required for a `u32` header).
    ///
    /// # Examples
    /// ```
    /// # use task_scheduler::network::PacketSize;
    /// let raw_header = [0, 0, 0, 100]; // 100 bytes in Big-Endian
    /// let size = PacketSize::from_slice(&raw_header).unwrap();
    /// assert_eq!(usize::from(size), 100);
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < 4 {
            return Err(ProtocolError::PacketTooShort);
        }

        let bytes = [slice[0], slice[1], slice[2], slice[3]];
        let len = u32::from_be_bytes(bytes);

        Ok(PacketSize(len))
    }

    /// Converts the packet size into its 4-byte Big-Endian network representation.
    ///
    /// This is used when prefixing a payload before sending it over a [`TcpStream`].
    #[inline]
    #[must_use]
    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl From<PacketSize> for usize {
    fn from(ps: PacketSize) -> Self {
        ps.0 as usize
    }
}

impl From<u32> for PacketSize {
    fn from(val: u32) -> Self {
        PacketSize(val)
    }
}
