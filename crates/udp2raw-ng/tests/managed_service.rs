use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use udp2raw_ng::{ServiceBuilder, ServiceConfig};
use udp2raw_ng_core::{EngineConfig, Psk};
use udp2raw_ng_net::memory_transport_pair;

fn psk() -> Psk {
    Psk::new(vec![9; 32]).expect("valid psk")
}

async fn unused_loopback_address() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
    let address = socket.local_addr().expect("probe address");
    drop(socket);
    address
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_transport_services_tunnel_udp_and_stop_cleanly() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.expect("upstream bind");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        let (length, peer) = upstream
            .recv_from(&mut buffer)
            .await
            .expect("upstream receive");
        upstream
            .send_to(&buffer[..length], peer)
            .await
            .expect("upstream echo");
    });

    let client_listen = unused_loopback_address().await;
    let server_listen = unused_loopback_address().await;
    let (client_transport, server_transport) = memory_transport_pair(64).expect("transport");
    let server_peer = server_transport.local_peer();

    let client_service = ServiceBuilder::new(
        ServiceConfig {
            engine: EngineConfig::client(),
            queue_capacity: 64,
            packet_workers: 1,
        },
        client_transport,
    )
    .build_client(psk(), server_peer, client_listen)
    .expect("client service");
    let server_service = ServiceBuilder::new(
        ServiceConfig {
            engine: EngineConfig::server(),
            queue_capacity: 64,
            packet_workers: 1,
        },
        server_transport,
    )
    .build_server(psk(), server_listen, upstream_address)
    .expect("server service");

    let client_shutdown = client_service.shutdown_handle();
    let server_shutdown = server_service.shutdown_handle();
    let client_task = tokio::spawn(client_service.run());
    let server_task = tokio::spawn(server_service.run());

    let application = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("application bind");
    application
        .connect(client_listen)
        .await
        .expect("application connect");
    application
        .send(b"managed round trip")
        .await
        .expect("send request");
    let mut response = [0_u8; 1024];
    let length = timeout(Duration::from_secs(3), application.recv(&mut response))
        .await
        .expect("response timeout")
        .expect("application receive");
    assert_eq!(&response[..length], b"managed round trip");

    client_shutdown.shutdown();
    server_shutdown.shutdown();
    timeout(Duration::from_secs(1), client_task)
        .await
        .expect("client shutdown timeout")
        .expect("client join")
        .expect("client service result");
    timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server shutdown timeout")
        .expect("server join")
        .expect("server service result");
    echo_task.await.expect("echo join");
}

#[test]
fn managed_udp_harness_requires_one_engine_owner() {
    let mut config = ServiceConfig {
        engine: EngineConfig::client(),
        queue_capacity: 1,
        packet_workers: 2,
    };
    assert!(config.validate().is_err());
    config.packet_workers = 1;
    assert!(config.validate().is_ok());
}
