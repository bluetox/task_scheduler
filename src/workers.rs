use crate::{
    FilePath, HashAlgorithms, ServerMetrics, constants::*, crypto::HashError, crypto::hash_reader,
    network::{HashingPacket, ProtocolMessage},
};
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use std::fs;
use std::io::Read;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{Mutex, mpsc, oneshot};

#[derive(Debug, Copy, Clone)]
pub enum Task {
    Hashing,
    Other,
}

impl Task {
    pub fn from_byte(byte: u8) -> Option<Task> {
        match byte {
            HASHING_TASK_CODE => Some(Task::Hashing),
            OTHER_TASK_CODE => Some(Task::Other),
            _ => None,
        }
    }
}

pub struct WorkItem {
    packet: HashingPacket,
    responder: oneshot::Sender<ProtocolMessage>,
}

impl WorkItem {
    #[inline]
    pub fn new(packet: HashingPacket, responder: oneshot::Sender<ProtocolMessage>) -> Self {
        Self { packet, responder }
    }

    pub fn packet(&self) -> &HashingPacket {
        &self.packet
    }
}
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
                        Ok(Ok(h)) => ProtocolMessage::TaskResponse(crate::network::TaskResponse::Success(h)),
                        Ok(Err(_)) => ProtocolMessage::TaskResponse(crate::network::TaskResponse::Failed),
                        Err(_) => ProtocolMessage::TaskResponse(crate::network::TaskResponse::Failed),
                    };

                    let _ = responder.send(final_response);
                } else {
                    break;
                }
            }
        });
    }
}