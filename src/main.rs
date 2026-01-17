#![allow(dead_code)]

use crate::network::HashingPacket;
use crate::network::read_task;
use crate::workers::Task;
use crate::workers::WorkItem;
use crate::workers::start_worker_pool;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
mod constants;
mod network;
mod protocol;
mod crypto;
mod workers;

struct ServerMetrics {
    processed_tasks: AtomicUsize,
    active_connections: AtomicUsize,
}

impl ServerMetrics {
    fn new() -> Self {
        Self {
            processed_tasks: AtomicUsize::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }
}

#[derive(Debug, PartialEq)]
enum HashAlgorithms {
    SHAKE256,
    SHA256,
    BLAKE3,
    UNIMPLEMENTED,
}

#[derive(Debug)]
enum FilePath {
    Local(String),
    Remote(String),
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on 127.0.0.1:8080");
    let metrics = Arc::new(ServerMetrics::new());
    let (tx, rx) = mpsc::channel::<WorkItem>(100);

    start_worker_pool(rx, 10, Arc::clone(&metrics)).await;

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
                let packet = match read_task(&mut socket).await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                if let Task::Hashing = packet.task() {
                    if let Ok(hash_req) = HashingPacket::try_from_bytes(packet.payload().clone()) {
                        let (resp_tx, resp_rx) = oneshot::channel();
                        let work = WorkItem::new(hash_req, resp_tx);

                        let _ = task_sender.send(work).await;

                        if let Ok(result) = resp_rx.await {
                            let _ = socket.write_all(result.as_bytes()).await;

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
