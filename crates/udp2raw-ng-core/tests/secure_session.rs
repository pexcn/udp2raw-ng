use std::net::SocketAddr;
use std::time::Instant;

use udp2raw_ng_core::{
    CipherSuite, ClientEngine, EngineConfig, EngineError, PeerId, Psk, RecordError, ServerEngine,
    SessionId, SessionState, TunnelAction, TunnelEvent,
};

fn psk(byte: u8) -> Psk {
    Psk::new(vec![byte; 32]).expect("valid psk")
}

fn configs(suite: CipherSuite) -> (EngineConfig, EngineConfig) {
    let mut client = EngineConfig::client();
    client.cipher_suite = suite;
    let mut server = EngineConfig::server();
    server.cipher_suite = suite;
    (client, server)
}

fn tunnel_frame(actions: &[TunnelAction]) -> (PeerId, Vec<u8>) {
    actions
        .iter()
        .find_map(|action| match action {
            TunnelAction::SendTunnelFrame { peer_id, bytes } => Some((*peer_id, bytes.clone())),
            _ => None,
        })
        .expect("send action")
}

fn establish(suite: CipherSuite) -> (ClientEngine, ServerEngine, PeerId, PeerId, SessionId) {
    let now = Instant::now();
    let client_peer = PeerId::new(10);
    let server_peer = PeerId::new(20);
    let (client_config, server_config) = configs(suite);
    let mut client = ClientEngine::new(client_config, psk(7), server_peer).expect("client");
    let mut server = ServerEngine::new(server_config, psk(7)).expect("server");

    let start = client.handle(TunnelEvent::Start, now).expect("start");
    let (_, client_hello) = tunnel_frame(&start);
    let server_hello_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: client_hello,
            },
            now,
        )
        .expect("client hello");
    let (_, server_hello) = tunnel_frame(&server_hello_actions);
    let finish_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: server_hello,
            },
            now,
        )
        .expect("server hello");
    let session_id = client.session_id().expect("client session");
    let (_, finish) = tunnel_frame(&finish_actions);
    let established = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: finish,
            },
            now,
        )
        .expect("finish");
    assert!(established.iter().any(|action| matches!(
        action,
        TunnelAction::SessionEstablished { session_id: id, .. } if *id == session_id
    )));
    assert_eq!(client.state(), SessionState::Ready);
    assert_eq!(server.session_state(session_id), Some(SessionState::Ready));
    (client, server, client_peer, server_peer, session_id)
}

#[test]
fn all_cipher_suites_support_authenticated_bidirectional_data() {
    for suite in [
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::XChaCha20Poly1305,
        CipherSuite::Aes128Gcm,
        CipherSuite::Aes256Gcm,
        CipherSuite::NoneAuthenticated,
    ] {
        let now = Instant::now();
        let (mut client, mut server, client_peer, server_peer, session_id) = establish(suite);
        let local_peer: SocketAddr = "127.0.0.1:31000".parse().expect("address");
        let actions = client
            .handle(
                TunnelEvent::ClientDatagram {
                    local_peer,
                    payload: b"request".to_vec(),
                },
                now,
            )
            .expect("seal request");
        let conversation_id = actions
            .iter()
            .find_map(|action| match action {
                TunnelAction::ConversationOpened {
                    conversation_id, ..
                } => Some(*conversation_id),
                _ => None,
            })
            .expect("conversation");
        let (_, request) = tunnel_frame(&actions);
        let delivered = server
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: client_peer,
                    bytes: request,
                },
                now,
            )
            .expect("open request");
        assert!(delivered.iter().any(|action| matches!(
            action,
            TunnelAction::DeliverToUpstream { payload, .. } if payload == b"request"
        )));

        let response_actions = server
            .handle(
                TunnelEvent::ServerDatagram {
                    session_id,
                    conversation_id,
                    payload: b"response".to_vec(),
                },
                now,
            )
            .expect("seal response");
        let (_, response) = tunnel_frame(&response_actions);
        let delivered = client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes: response,
                },
                now,
            )
            .expect("open response");
        assert_eq!(
            delivered,
            vec![TunnelAction::DeliverToClient {
                local_peer,
                payload: b"response".to_vec(),
            }]
        );
    }
}

#[test]
fn tampering_and_replay_never_deliver_plaintext() {
    let now = Instant::now();
    let (mut client, mut server, client_peer, _, _) = establish(CipherSuite::ChaCha20Poly1305);
    let local_peer: SocketAddr = "127.0.0.1:31001".parse().expect("address");
    let actions = client
        .handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: b"secret".to_vec(),
            },
            now,
        )
        .expect("seal");
    let (_, valid) = tunnel_frame(&actions);
    let mut tampered = valid.clone();
    let last = tampered.last_mut().expect("tag byte");
    *last ^= 1;
    assert!(matches!(
        server.handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: tampered,
            },
            now,
        ),
        Err(EngineError::Record(RecordError::Crypto(_)))
    ));

    let delivered = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: valid.clone(),
            },
            now,
        )
        .expect("valid frame after failed authentication");
    assert!(delivered.iter().any(|action| matches!(
        action,
        TunnelAction::DeliverToUpstream { payload, .. } if payload == b"secret"
    )));
    assert!(matches!(
        server.handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: valid,
            },
            now,
        ),
        Err(EngineError::Record(RecordError::Replay(_)))
    ));
}

#[test]
fn wrong_psk_and_suite_mismatch_block_handshake() {
    let now = Instant::now();
    let client_peer = PeerId::new(30);
    let server_peer = PeerId::new(40);
    let (client_config, server_config) = configs(CipherSuite::ChaCha20Poly1305);
    let mut client = ClientEngine::new(client_config, psk(1), server_peer).expect("client");
    let mut server = ServerEngine::new(server_config, psk(2)).expect("server");
    let start = client.handle(TunnelEvent::Start, now).expect("start");
    let (_, client_hello) = tunnel_frame(&start);
    let server_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: client_hello,
            },
            now,
        )
        .expect("server hello");
    let (_, server_hello) = tunnel_frame(&server_actions);
    assert!(
        client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes: server_hello,
                },
                now,
            )
            .is_err()
    );
    assert_eq!(client.state(), SessionState::Handshaking);

    let (mut client_config, mut server_config) = configs(CipherSuite::Aes128Gcm);
    server_config.cipher_suite = CipherSuite::Aes256Gcm;
    client_config.cipher_suite = CipherSuite::Aes128Gcm;
    let mut client = ClientEngine::new(client_config, psk(3), server_peer).expect("client");
    let mut server = ServerEngine::new(server_config, psk(3)).expect("server");
    let start = client.handle(TunnelEvent::Start, now).expect("start");
    let (_, hello) = tunnel_frame(&start);
    assert!(
        server
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: client_peer,
                    bytes: hello,
                },
                now,
            )
            .is_err()
    );
}

#[test]
fn application_data_is_rejected_before_ready() {
    let (config, _) = configs(CipherSuite::ChaCha20Poly1305);
    let mut client = ClientEngine::new(config, psk(9), PeerId::new(2)).expect("client");
    let local_peer: SocketAddr = "127.0.0.1:32000".parse().expect("address");
    assert!(matches!(
        client.handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: vec![1],
            },
            Instant::now(),
        ),
        Err(EngineError::SessionNotReady)
    ));
}
