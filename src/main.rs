use std::sync::{Arc, atomic::Ordering};
use task_scheduler::{
    ServerMetrics,
    network::{ProtocolMessage, TaskRequest, read_protocol},
    workers::{WorkItem, start_worker_pool},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, oneshot},
};

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
                let packet = match read_protocol(&mut socket).await {
                    Ok(p) => p,
                    Err(_) => break,
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
