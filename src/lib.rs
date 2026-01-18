#![allow(dead_code)]

use crate::{
    network::{HashingPacket},
    workers::{Task, WorkItem, start_worker_pool},
};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
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

