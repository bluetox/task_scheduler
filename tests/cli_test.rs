use task_scheduler::{
    FilePath, HashAlgorithms,
    network::{HashingPacket, TaskRequest, read_protocol, ProtocolMessage},
};
use tokio::{fs::read, io::AsyncReadExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::test]
async fn test_client_example() {
    
    let task = ProtocolMessage::TaskRequest(TaskRequest::HashPacket(HashingPacket {
        algorithm: HashAlgorithms::SHAKE128,
        path: FilePath::Local(String::from(
            "/home/bluetox/Developpement/rust/task_scheduler/Cargo.toml",
        )),
    }));
    let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
    stream.write(&task.into_packet().unwrap()).await.unwrap();
    let packet = read_protocol(&mut stream).await.unwrap();
    println!("Packet: {:?}", packet);
}
