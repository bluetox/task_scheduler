#![allow(dead_code)]
#![deny(missing_docs)]

//! # Task Scheduler
//! 
//! A Task Scheduler build to be highly modulable, performant and asynchrous
//! 
//! This crate provides the core networking, crypto and protocol logic
//! for distributing tasks between a central orchestrator and workers.
//! 
//! ## Features
//! - **Asynchronous I/O**: Built on the [Tokio](https://tokio.rs) runtime.
//! - **Robust Protocol**: A custom protocol that uses bincode serialization to make parsing fast and safe.
//! - **Security**: Enforced packet size limits and read timeouts to prevent DoS.
//! - **Type-Safe**: Unified [`ProtocolMessage`] enum for all client-server communication for easy packet handling.
//!
//! ## Architecture
//! The project is divided into three main pillars:
//! 2. [`protocol`]: Defines the data structures and enums shared by client and server as well as the packet logic.
//! 3. [`workers`]: Contains the logic to dispatch and execute tasks.


use crate::workers::start_worker_pool;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener},
    sync::{mpsc, oneshot},
};



/// Global constants used in the protocol
/// 
/// This module defines the constants used in the protocol such as [`MAX_PACKET_SIZE`]
pub mod constants;
/// Module to handle cryptographic tasks
/// 
/// This modules defines function related to encryption as well as 
/// §any tasks around crypto.
pub mod crypto;
/// Module to centralize all of the protocol logic
/// 
/// This module defines any function or structure related to the network 
/// protocol.
pub mod protocol;
/// Module that handles the dispatching of tasks
/// 
/// This module defines the functions and helpers that do the actual
/// task dispatch.
pub mod workers;


/// Thread-safe metrics for monitoring the orchestrator's state.
///
/// This structure uses atomic integers to allow high-concurrency updates
/// without the overhead of locking. It is typically wrapped in an [`std::sync::Arc`]
/// and shared between the listener loop and worker tasks.
pub struct ServerMetrics {
    /// The total number of tasks successfully processed since the server started.
    pub processed_tasks: AtomicU64,
    /// The number of clients currently connected to the orchestrator.
    pub active_connections: AtomicU64,
}

impl ServerMetrics {
    /// Creates a new instance of [`ServerMetrics`] with all counters initialized to zero.
    #[inline]
    pub fn new() -> Self {
        Self {
            processed_tasks: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }
}

/// Supported hash algorithms used by the protocol for integrity checks
/// and selection based on client/server capabilities.
#[allow(missing_docs)]
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
/// Represents a path to a resource in the system or remotely fetched.
#[derive(Debug, Deserialize, Serialize)]
pub enum FilePath {
    /// Local is used for files on the computer
    Local(String),
    /// Remote is for links online
    Remote(String),
}

use crate::protocol::{read_protocol, ProtocolMessage, TaskRequest};
use crate::workers::WorkItem;


/// Start the server loop on an existing TCP listener.
///
/// This function accepts incoming connections, updates connection metrics, and delegates
/// work items to a worker pool. It returns when the underlying I/O fails or the connection
/// is closed.
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

/// Bind to the given address and start the server with a worker pool.
///
/// This function creates a TCP listener on the provided address and delegates all
/// incoming work to the worker pool managed by [`run_server_on`].
pub async fn run_server(addr: &str, num_workers: usize) -> tokio::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Server listening on {}", addr);
    run_server_on(listener, num_workers).await
}

