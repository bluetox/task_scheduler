use task_scheduler::{
    FilePath, HashAlgorithms,
    protocol::{HashingPacket, TaskRequest, read_protocol, ProtocolMessage},
};
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

#[tokio::test]
async fn fake_path() {
    
    let task = ProtocolMessage::TaskRequest(TaskRequest::HashPacket(HashingPacket {
        algorithm: HashAlgorithms::SHA224,
        path: FilePath::Local(String::from(
            "/dev/zero",
        )),
    }));
    let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
    stream.write(&task.into_packet().unwrap()).await.unwrap();
    let packet = read_protocol(&mut stream).await.unwrap();
    println!("Packet: {:?}", packet);
}

use rand::{RngCore, rng};

#[tokio::test]
async fn test_random_junk_bytes() {
    let mut stream = TcpStream::connect("127.0.0.1:8080").await
        .expect("Server must be running for this test");

    let mut junk_payload = vec![0u8; 100]; 
    rng().fill_bytes(&mut junk_payload);

    let mut malicious_packet = Vec::new();
    malicious_packet.extend_from_slice(&65000u16.to_be_bytes());
    malicious_packet.extend_from_slice(&junk_payload);

    stream.write_all(&malicious_packet).await.unwrap();


    let result = read_protocol(&mut stream).await;

    match result {
        Ok(_) => panic!("Server accepted invalid junk bytes! Security risk."),
        Err(e) => {
            println!("Test Passed: Server correctly rejected junk. Error: {:?}", e);
        }
    }
}