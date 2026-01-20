#![allow(dead_code)]

use crate::workers::start_worker_pool;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener},
    sync::{mpsc, oneshot},
};

pub mod constants;
pub mod crypto;
pub mod network;
pub mod protocol;
pub mod workers;

pub struct ServerMetrics {
    pub processed_tasks: AtomicUsize,
    pub active_connections: AtomicUsize,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            processed_tasks: AtomicUsize::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum HashAlgorithms {
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,

    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,

    BLAKE3,

    UNIMPLEMENTED,
}
#[derive(Debug, Deserialize, Serialize)]
pub enum FilePath {
    Local(String),
    Remote(String),
}

use crate::network::{read_protocol, ProtocolMessage, TaskRequest};
use crate::workers::WorkItem;


pub async fn run_server_on(listener: TcpListener, num_workers: usize) -> tokio::io::Result<()> {
    let metrics = Arc::new(ServerMetrics::new());
    let (tx, rx) = mpsc::channel::<WorkItem>(100);

    start_worker_pool(rx, num_workers, Arc::clone(&metrics)).await;

    loop {
        let (mut socket, addr) = listener.accept().await?;
        let task_sender = tx.clone();
        let conn_metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            conn_metrics
                .active_connections
                .fetch_add(1, Ordering::SeqCst);
            println!(
                "Client {} connected. Active: {}",
                addr,
                conn_metrics.active_connections.load(Ordering::SeqCst)
            );

            loop {
                let packet = match read_protocol(&mut socket).await {
                    Ok(p) => p,
                    Err(e) => {
                        println!("Protocol read error from {}: {:?}", addr, e);
                        break;
                    }
                };
                let task = match packet {
                    ProtocolMessage::TaskRequest(t) => t,
                    ProtocolMessage::TaskResponse(_) => continue,
                };
                match task {
                    TaskRequest::HashPacket(p) => {
                        let (resp_tx, resp_rx) = oneshot::channel();
                        let work = WorkItem::new(p, resp_tx);

                        let _ = task_sender.send(work).await;

                        if let Ok(result) = resp_rx.await {
                            let packet = match result.into_packet() {
                                Ok(p) => p,
                                Err(_) => {
                                    println!("Invalid response from worker");
                                    continue;
                                }
                            };

                            match socket.write_all(&packet).await {
                                Ok(()) => {}
                                Err(e) => {
                                    println!("Failed to write to the socket: {}", e);
                                    break;
                                }
                            }

                            let total = conn_metrics.processed_tasks.load(Ordering::SeqCst);
                            let active = conn_metrics.active_connections.load(Ordering::SeqCst);
                            println!(
                                "Task Complete. Total Processed: {}, Active Now: {}",
                                total, active
                            );
                        }
                    }
                }
            }

            conn_metrics
                .active_connections
                .fetch_sub(1, Ordering::SeqCst);
            println!("Client {} disconnected", addr);
        });
    }
}

pub async fn run_server(addr: &str, num_workers: usize) -> tokio::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Server listening on {}", addr);
    run_server_on(listener, num_workers).await
}

