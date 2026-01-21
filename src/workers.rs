use crate::{
    FilePath, HashAlgorithms, ServerMetrics, crypto::HashError, crypto::hash_reader,
    protocol::{HashingPacket, ProtocolMessage},
};
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::fs;
use std::io::Read;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{Mutex, mpsc, oneshot};

/// High-level classification of tasks supported by the worker pool.
///
/// This enum is used to categorize work before it is dispatched, allowing 
/// for specialized handling or priority queuing of different task types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Task {
    /// A task dedicated to calculating file checksums.
    Hashing,
    /// Placeholder for future non-hashing operations (e.g., File Compression).
    Other,
}

/// Orchestrates a thread pool for executing CPU-bound cryptographic tasks.
///
/// This module implements the "Fan-out" pattern. It consumes [`WorkItem`]s from a 
/// shared queue and distributes them across a fixed number of asynchronous workers.
/// Heavy hashing operations are offloaded to a blocking thread pool to prevent 
/// starving the asynchronous runtime.

/// A unit of work consisting of a task payload and a feedback channel.
///
/// Each `WorkItem` contains a [`HashingPacket`] and a [`oneshot::Sender`] used to 
/// communicate the result back to the original request handler.
pub struct WorkItem {
    packet: HashingPacket,
    responder: oneshot::Sender<ProtocolMessage>,
}

impl WorkItem {
    /// Creates a new work envelope for the worker pool.
    ///
    /// # Arguments
    /// * `packet` - The data defining the task to be performed.
    /// * `responder` - A [`oneshot::Sender`] used to transmit the result back 
    ///   to the client's connection handler.
    #[inline]
    #[must_use]
    pub fn new(packet: HashingPacket, responder: oneshot::Sender<ProtocolMessage>) -> Self {
        Self { packet, responder }
    }

    /// Provides a read-only reference to the task's data packet.
    pub fn packet(&self) -> &HashingPacket {
        &self.packet
    }
}

/// Initializes and starts a pool of worker tasks.
///
/// # Arguments
/// * `receiver` - An MPSC channel receiver used to listen for incoming tasks.
/// * `num_workers` - The number of concurrent asynchronous tasks to spawn.
/// * `metrics` - Shared atomic counters for tracking system health and throughput.
///
/// # Threading
/// Each worker runs in an infinite loop, asynchronously waiting for tasks. When a 
/// task is received, it uses [`tokio::task::spawn_blocking`] to handle the 
/// computationally expensive hashing, ensuring the orchestrator remains responsive.
pub async fn start_worker_pool(
    receiver: mpsc::Receiver<WorkItem>,
    num_workers: usize,
    metrics: Arc<ServerMetrics>,
) {
    let receiver = Arc::new(Mutex::new(receiver));

    for _id in 0..num_workers {
        let rx = Arc::clone(&receiver);
        let metrics = Arc::clone(&metrics);
        
        tokio::spawn(async move {
            loop {
                let work = {
                    let mut lock = rx.lock().await;
                    lock.recv().await
                };

                if let Some(item) = work {
                    let WorkItem { packet, responder } = item;
                    let metrics_clone = Arc::clone(&metrics);

                    let result = tokio::task::spawn_blocking(move || {
                        metrics_clone.processed_tasks.fetch_add(1, Ordering::Relaxed);

                        let algo = packet.algorithm();
                        let path = packet.path();

                        match algo {
                            HashAlgorithms::SHA224 => hash_reader::<Sha224>(path),
                            HashAlgorithms::SHA256 => hash_reader::<Sha256>(path),
                            HashAlgorithms::SHA384 => hash_reader::<Sha384>(path),
                            HashAlgorithms::SHA512 => hash_reader::<Sha512>(path),
                            HashAlgorithms::SHA512_224 => hash_reader::<Sha512_224>(path),
                            HashAlgorithms::SHA512_256 => hash_reader::<Sha512_256>(path),

                            HashAlgorithms::SHA3_224 => hash_reader::<Sha3_224>(path),
                            HashAlgorithms::SHA3_256 => hash_reader::<Sha3_256>(path),
                            HashAlgorithms::SHA3_384 => hash_reader::<Sha3_384>(path),
                            HashAlgorithms::SHA3_512 => hash_reader::<Sha3_512>(path),

                            HashAlgorithms::BLAKE3 => {
                                let mut src = match path {
                                    FilePath::Local(p) => fs::File::open(p).map_err(HashError::Io)?,
                                    FilePath::Remote(_) => return Err(HashError::NotImplemented),
                                };

                                let mut hasher = blake3::Hasher::new();
                                let mut buffer = [0u8; 8192];
                                loop {
                                    let count = src.read(&mut buffer).map_err(HashError::Io)?;
                                    if count == 0 { break; }
                                    hasher.update(&buffer[..count]);
                                }
                                Ok(hasher.finalize().to_hex().to_string())
                            }
                            _ => Err(HashError::NotImplemented),
                        }
                    })
                    .await;

                    let final_response = match result {
                        Ok(Ok(h)) => ProtocolMessage::TaskResponse(crate::protocol::TaskResponse::Success(h)),
                        Ok(Err(_)) => ProtocolMessage::TaskResponse(crate::protocol::TaskResponse::Failed),
                        Err(_) => ProtocolMessage::TaskResponse(crate::protocol::TaskResponse::Failed),
                    };

                    let _ = responder.send(final_response);
                } else {
                    break;
                }
            }
        });
    }
}