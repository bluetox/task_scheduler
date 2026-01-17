use crate::HashAlgorithms;
use crate::ServerMetrics;
use crate::constants::*;
use crate::crypto::hash_reader;
use crate::network::HashingPacket;
use sha2::Sha256;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

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
    responder: oneshot::Sender<String>,
}

impl WorkItem {
    #[inline]
    pub fn new(packet: HashingPacket, responder: oneshot::Sender<String>) -> Self {
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

    for id in 0..num_workers {
        let rx = Arc::clone(&receiver);
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            println!("Worker {} started", id);
            loop {
                let work = {
                    let mut lock = rx.lock().await;
                    lock.recv().await
                };

                if let Some(item) = work {
                    let metrics = Arc::clone(&metrics);

                    // 1. Destructure the WorkItem to separate ownership
                    let WorkItem { packet, responder } = item;

                    let result = tokio::task::spawn_blocking(move || {
                        metrics.processed_tasks.fetch_add(1, Ordering::Relaxed);

                        // 2. Now only 'packet' is moved into this closure
                        match packet.algorithm() {
                            &HashAlgorithms::BLAKE3 => "blake3_placeholder".to_string(),
                            _ => hash_reader::<Sha256>(packet.path())
                                .unwrap_or_else(|e| format!("Error: {}", e)),
                        }
                    })
                    .await
                    .unwrap();

                    // 3. 'responder' is still available here because it wasn't moved into the closure!
                    let _ = responder.send(result);
                } else {
                    break;
                }
            }
        });
    }
}
