use std::net::SocketAddr;
use std::time::{Duration, Instant};

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

fn tunnel_frames(actions: &[TunnelAction]) -> Vec<(PeerId, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|action| match action {
            TunnelAction::SendTunnelFrame { peer_id, bytes } => Some((*peer_id, bytes.clone())),
            _ => None,
        })
        .collect()
}

fn establish(suite: CipherSuite) -> (ClientEngine, ServerEngine, PeerId, PeerId, SessionId) {
    let (client_config, server_config) = configs(suite);
    establish_with_configs(Instant::now(), client_config, server_config)
}

fn establish_with_configs(
    now: Instant,
    client_config: EngineConfig,
    server_config: EngineConfig,
) -> (ClientEngine, ServerEngine, PeerId, PeerId, SessionId) {
    let client_peer = PeerId::new(10);
    let server_peer = PeerId::new(20);
    let mut client = ClientEngine::new(client_config, psk(7), server_peer).expect("client");
    let mut server = ServerEngine::new(server_config, psk(7)).expect("server");

    let start = client.handle(TunnelEvent::Start, now).expect("start");
    let (_, client_hello) = tunnel_frame(&start);
    let retry_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: client_hello,
            },
            now,
        )
        .expect("initial client hello");
    let (_, retry) = tunnel_frame(&retry_actions);
    let retried_hello_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: retry,
            },
            now,
        )
        .expect("hello retry");
    let (_, retried_hello) = tunnel_frame(&retried_hello_actions);
    let server_hello_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: retried_hello,
            },
            now,
        )
        .expect("cookie client hello");
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
    let frames = tunnel_frames(&established);
    let (_, ack) = frames.first().cloned().expect("handshake ack");
    let client_established = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: ack,
            },
            now,
        )
        .expect("handshake ack");
    assert!(client_established.iter().any(|action| matches!(
        action,
        TunnelAction::SessionEstablished { session_id: id, .. } if *id == session_id
    )));
    for (_, bytes) in frames.into_iter().skip(1) {
        client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes,
                },
                now,
            )
            .expect("post-handshake protected frame");
    }
    assert_eq!(client.state(), SessionState::Ready);
    assert_eq!(server.session_state(session_id), Some(SessionState::Ready));
    (client, server, client_peer, server_peer, session_id)
}

fn reconnect(
    client: &mut ClientEngine,
    server: &mut ServerEngine,
    client_peer: PeerId,
    server_peer: PeerId,
    now: Instant,
) -> (SessionId, Vec<TunnelAction>, Vec<TunnelAction>) {
    let reconnect = client
        .handle(TunnelEvent::Reconnect, now)
        .expect("start reconnect");
    let (_, hello) = tunnel_frame(&reconnect);
    let retry_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: hello,
            },
            now,
        )
        .expect("reconnect challenge");
    let (_, retry) = tunnel_frame(&retry_actions);
    let cookie_hello_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: retry,
            },
            now,
        )
        .expect("reconnect cookie hello");
    let (_, cookie_hello) = tunnel_frame(&cookie_hello_actions);
    let server_hello_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: cookie_hello,
            },
            now,
        )
        .expect("reconnect server hello");
    let (_, server_hello) = tunnel_frame(&server_hello_actions);
    let finish_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: server_hello,
            },
            now,
        )
        .expect("reconnect finish");
    let new_session_id = client.session_id().expect("new session id");
    let (_, finish) = tunnel_frame(&finish_actions);
    let server_established = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: finish,
            },
            now,
        )
        .expect("reconnect establish");
    let (_, ack) = tunnel_frame(&server_established);
    let client_established = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: ack,
            },
            now,
        )
        .expect("reconnect ack");
    (new_session_id, server_established, client_established)
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
    let retry_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: client_hello,
            },
            now,
        )
        .expect("hello retry");
    let (_, retry) = tunnel_frame(&retry_actions);
    assert!(
        client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes: retry,
                },
                now,
            )
            .is_err()
    );
    assert_eq!(client.state(), SessionState::Handshaking);

    let (client_config, mut server_config) = configs(CipherSuite::ChaCha20Poly1305);
    server_config.require_handshake_cookie = false;
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
fn lost_handshake_messages_are_retried_and_ack_is_idempotent() {
    let now = Instant::now();
    let client_peer = PeerId::new(50);
    let server_peer = PeerId::new(60);
    let (client_config, server_config) = configs(CipherSuite::ChaCha20Poly1305);
    let retry_interval = client_config.handshake_retry_interval;
    let mut client = ClientEngine::new(client_config, psk(11), server_peer).expect("client");
    let mut server = ServerEngine::new(server_config, psk(11)).expect("server");

    let start = client.handle(TunnelEvent::Start, now).expect("start");
    let (_, initial_hello) = tunnel_frame(&start);
    let retry_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: initial_hello,
            },
            now,
        )
        .expect("retry");
    let (_, retry) = tunnel_frame(&retry_actions);
    let cookie_hello_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: retry,
            },
            now,
        )
        .expect("cookie hello");
    let (_, cookie_hello) = tunnel_frame(&cookie_hello_actions);

    let retransmit = client
        .handle(
            TunnelEvent::TimeAdvanced(now + retry_interval),
            now + retry_interval,
        )
        .expect("retry timer");
    let (_, retried_cookie_hello) = tunnel_frame(&retransmit);
    assert_eq!(retried_cookie_hello, cookie_hello);

    let first_server_hello = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: cookie_hello,
            },
            now + retry_interval,
        )
        .expect("server hello");
    let (_, first_server_hello) = tunnel_frame(&first_server_hello);
    let duplicate_server_hello = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: retried_cookie_hello,
            },
            now + retry_interval,
        )
        .expect("duplicate hello");
    let (_, duplicate_server_hello) = tunnel_frame(&duplicate_server_hello);
    assert_eq!(duplicate_server_hello, first_server_hello);

    let finish_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: first_server_hello,
            },
            now + retry_interval,
        )
        .expect("finish");
    let session_id = client.session_id().expect("session id");
    assert_eq!(client.state(), SessionState::Handshaking);
    let (_, finish) = tunnel_frame(&finish_actions);
    let server_established = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: finish.clone(),
            },
            now + retry_interval,
        )
        .expect("server establish");
    let (_, first_ack) = tunnel_frame(&server_established);

    let finish_retry = client
        .handle(
            TunnelEvent::TimeAdvanced(now + retry_interval + retry_interval),
            now + retry_interval + retry_interval,
        )
        .expect("finish retry");
    let (_, retried_finish) = tunnel_frame(&finish_retry);
    assert_eq!(retried_finish, finish);
    let duplicate_finish_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: retried_finish,
            },
            now + retry_interval + retry_interval,
        )
        .expect("duplicate finish");
    let (_, duplicate_ack) = tunnel_frame(&duplicate_finish_actions);
    assert_eq!(duplicate_ack, first_ack);

    client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: first_ack.clone(),
            },
            now + retry_interval + retry_interval,
        )
        .expect("ack");
    assert_eq!(client.state(), SessionState::Ready);
    assert!(
        client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes: first_ack,
                },
                now + retry_interval + retry_interval,
            )
            .expect("duplicate ack")
            .is_empty()
    );
    assert_eq!(server.session_state(session_id), Some(SessionState::Ready));
}

#[test]
fn handshake_times_out_without_confirmation() {
    let now = Instant::now();
    let mut config = EngineConfig::client();
    config.handshake_retry_interval = Duration::from_millis(10);
    config.handshake_timeout = Duration::from_millis(30);
    config.handshake_max_attempts = 2;
    let mut client = ClientEngine::new(config, psk(12), PeerId::new(70)).expect("client");
    client.handle(TunnelEvent::Start, now).expect("start");
    client
        .handle(
            TunnelEvent::TimeAdvanced(now + Duration::from_millis(10)),
            now + Duration::from_millis(10),
        )
        .expect("first retry");
    client
        .handle(
            TunnelEvent::TimeAdvanced(now + Duration::from_millis(20)),
            now + Duration::from_millis(20),
        )
        .expect("attempt limit");
    assert_eq!(client.state(), SessionState::Closed);
}

#[test]
fn cookie_challenge_is_stateless_peer_bound_and_expires() {
    let now = Instant::now();
    let client_peer = PeerId::new(80);
    let other_peer = PeerId::new(81);
    let server_peer = PeerId::new(82);
    let (client_config, mut server_config) = configs(CipherSuite::ChaCha20Poly1305);
    server_config.handshake_cookie_lifetime = Duration::from_millis(20);
    let mut client = ClientEngine::new(client_config, psk(13), server_peer).expect("client");
    let mut server = ServerEngine::new(server_config, psk(13)).expect("server");

    let start = client.handle(TunnelEvent::Start, now).expect("start");
    let (_, hello) = tunnel_frame(&start);
    let retry_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: hello,
            },
            now,
        )
        .expect("challenge");
    let (_, retry) = tunnel_frame(&retry_actions);
    let cookie_hello_actions = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: retry,
            },
            now,
        )
        .expect("cookie hello");
    let (_, cookie_hello) = tunnel_frame(&cookie_hello_actions);

    let wrong_peer_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: other_peer,
                bytes: cookie_hello.clone(),
            },
            now,
        )
        .expect("wrong peer gets a new challenge");
    let (_, wrong_peer_reply) = tunnel_frame(&wrong_peer_actions);
    assert_eq!(
        udp2raw_ng_core::WireFrame::decode(&wrong_peer_reply)
            .expect("retry frame")
            .frame_type,
        udp2raw_ng_core::FrameType::HelloRetry
    );

    let expired_actions = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: cookie_hello,
            },
            now + Duration::from_millis(21),
        )
        .expect("expired cookie gets a new challenge");
    let (_, expired_reply) = tunnel_frame(&expired_actions);
    assert_eq!(
        udp2raw_ng_core::WireFrame::decode(&expired_reply)
            .expect("retry frame")
            .frame_type,
        udp2raw_ng_core::FrameType::HelloRetry
    );
}

#[test]
fn per_peer_pending_handshake_limit_is_enforced_after_cookie_validation() {
    let now = Instant::now();
    let client_peer = PeerId::new(90);
    let server_peer = PeerId::new(91);
    let (client_config, mut server_config) = configs(CipherSuite::ChaCha20Poly1305);
    server_config.max_pending_handshakes_per_peer = 1;
    let mut server = ServerEngine::new(server_config, psk(14)).expect("server");

    for attempt in 0..2 {
        let mut client =
            ClientEngine::new(client_config.clone(), psk(14), server_peer).expect("client");
        let start = client.handle(TunnelEvent::Start, now).expect("start");
        let (_, hello) = tunnel_frame(&start);
        let retry_actions = server
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: client_peer,
                    bytes: hello,
                },
                now,
            )
            .expect("challenge");
        let (_, retry) = tunnel_frame(&retry_actions);
        let cookie_hello_actions = client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes: retry,
                },
                now,
            )
            .expect("cookie hello");
        let (_, cookie_hello) = tunnel_frame(&cookie_hello_actions);
        let result = server.handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: cookie_hello,
            },
            now,
        );
        if attempt == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(EngineError::PerPeerPendingHandshakeCapacity)
            ));
        }
    }
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

#[test]
fn authenticated_heartbeats_keep_client_and_server_sessions_alive() {
    let now = Instant::now();
    let (mut client_config, mut server_config) = configs(CipherSuite::ChaCha20Poly1305);
    client_config.heartbeat_interval = Duration::from_millis(10);
    client_config.session_timeout = Duration::from_millis(35);
    server_config.heartbeat_interval = Duration::from_millis(10);
    server_config.session_timeout = Duration::from_millis(35);
    server_config.session_idle_timeout = Duration::from_millis(25);
    let (mut client, mut server, client_peer, server_peer, session_id) =
        establish_with_configs(now, client_config, server_config);

    for elapsed in [10, 20, 30, 40] {
        let at = now + Duration::from_millis(elapsed);
        let heartbeat_actions = client
            .handle(TunnelEvent::TimeAdvanced(at), at)
            .expect("heartbeat timer");
        let (_, heartbeat) = tunnel_frame(&heartbeat_actions);
        assert_eq!(
            udp2raw_ng_core::WireFrame::decode(&heartbeat)
                .expect("heartbeat frame")
                .frame_type,
            udp2raw_ng_core::FrameType::Heartbeat
        );

        let reply_actions = server
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: client_peer,
                    bytes: heartbeat,
                },
                at,
            )
            .expect("server heartbeat");
        let (_, reply) = tunnel_frame(&reply_actions);
        client
            .handle(
                TunnelEvent::TunnelFrame {
                    peer_id: server_peer,
                    bytes: reply,
                },
                at,
            )
            .expect("client heartbeat reply");

        let server_expiry = server
            .handle(
                TunnelEvent::TimeAdvanced(at + Duration::from_millis(9)),
                at + Duration::from_millis(9),
            )
            .expect("server idle timer");
        assert!(!server_expiry.iter().any(|action| matches!(
            action,
            TunnelAction::SessionClosed { session_id: id, .. } if *id == session_id
        )));
        assert_eq!(client.state(), SessionState::Ready);
        assert_eq!(server.session_state(session_id), Some(SessionState::Ready));
    }
}

#[test]
fn client_timeout_closes_old_session_and_starts_reconnect() {
    let now = Instant::now();
    let (mut client_config, server_config) = configs(CipherSuite::ChaCha20Poly1305);
    client_config.heartbeat_interval = Duration::from_millis(10);
    client_config.session_timeout = Duration::from_millis(30);
    let (mut client, _, _, server_peer, old_session_id) =
        establish_with_configs(now, client_config, server_config);

    let timed_out_at = now + Duration::from_millis(30);
    let actions = client
        .handle(TunnelEvent::TimeAdvanced(timed_out_at), timed_out_at)
        .expect("session timeout");

    assert_eq!(client.state(), SessionState::Reconnecting);
    assert_eq!(client.session_id(), None);
    assert!(actions.iter().any(|action| matches!(
        action,
        TunnelAction::SessionClosed { peer_id, session_id }
            if *peer_id == server_peer && *session_id == old_session_id
    )));
    let (_, hello) = tunnel_frame(&actions);
    assert_eq!(
        udp2raw_ng_core::WireFrame::decode(&hello)
            .expect("reconnect hello")
            .frame_type,
        udp2raw_ng_core::FrameType::ClientHello
    );
}

#[test]
fn manual_reconnect_resumes_server_conversation_across_new_session() {
    let now = Instant::now();
    let (mut client, mut server, client_peer, server_peer, old_session_id) =
        establish(CipherSuite::ChaCha20Poly1305);
    let local_peer: SocketAddr = "127.0.0.1:33000".parse().expect("address");
    let request_actions = client
        .handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: b"before reconnect".to_vec(),
            },
            now,
        )
        .expect("initial request");
    let conversation_id = request_actions
        .iter()
        .find_map(|action| match action {
            TunnelAction::ConversationOpened {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        })
        .expect("conversation id");
    let (_, request) = tunnel_frame(&request_actions);
    let opened = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: request,
            },
            now,
        )
        .expect("open conversation and issue credential");
    let credential = tunnel_frames(&opened)
        .into_iter()
        .next()
        .expect("resumption credential");
    client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: credential.1,
            },
            now,
        )
        .expect("store resumption credential");

    let (new_session_id, server_established, client_established) =
        reconnect(&mut client, &mut server, client_peer, server_peer, now);
    assert_ne!(new_session_id, old_session_id);
    assert_eq!(client.state(), SessionState::Ready);
    assert!(server_established.iter().any(|action| matches!(
        action,
        TunnelAction::SessionEstablished { session_id, resumed: true, .. }
            if *session_id == new_session_id
    )));
    assert!(server_established.iter().any(|action| matches!(
        action,
        TunnelAction::SessionResumed {
            old_session_id: old,
            new_session_id: new,
            ..
        } if *old == old_session_id && *new == new_session_id
    )));
    assert!(client_established.iter().any(|action| matches!(
        action,
        TunnelAction::SessionEstablished { resumed: true, .. }
    )));
    assert_eq!(server.session_state(old_session_id), None);

    let after = client
        .handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: b"after reconnect".to_vec(),
            },
            now,
        )
        .expect("request after reconnect");
    assert!(
        !after
            .iter()
            .any(|action| matches!(action, TunnelAction::ConversationOpened { .. }))
    );
    let (_, request) = tunnel_frame(&after);
    let delivered = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: request,
            },
            now,
        )
        .expect("deliver after reconnect");
    assert!(delivered.iter().any(|action| matches!(
        action,
        TunnelAction::DeliverToUpstream {
            session_id,
            conversation_id: id,
            payload,
        } if *session_id == new_session_id
            && *id == conversation_id
            && payload == b"after reconnect"
    )));
    assert!(
        !delivered
            .iter()
            .any(|action| matches!(action, TunnelAction::ConversationOpened { .. }))
    );

    let response_actions = server
        .handle(
            TunnelEvent::ServerDatagram {
                session_id: new_session_id,
                conversation_id,
                payload: b"response after migration".to_vec(),
            },
            now,
        )
        .expect("upstream response after migration");
    let (_, response) = tunnel_frame(&response_actions);
    let client_delivery = client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: response,
            },
            now,
        )
        .expect("client receives migrated response");
    assert!(client_delivery.iter().any(|action| matches!(
        action,
        TunnelAction::DeliverToClient { payload, .. }
            if payload == b"response after migration"
    )));
}

#[test]
fn expired_resumption_credential_falls_back_and_closes_stale_client_mapping() {
    let now = Instant::now();
    let (mut client_config, mut server_config) = configs(CipherSuite::ChaCha20Poly1305);
    client_config.conversation_idle_timeout = Duration::from_secs(5);
    server_config.conversation_idle_timeout = Duration::from_secs(5);
    server_config.resumption_lifetime = Duration::from_millis(20);
    let (mut client, mut server, client_peer, server_peer, old_session_id) =
        establish_with_configs(now, client_config, server_config);
    let local_peer: SocketAddr = "127.0.0.1:33002".parse().expect("address");
    let request_actions = client
        .handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: b"credential source".to_vec(),
            },
            now,
        )
        .expect("request");
    let conversation_id = request_actions
        .iter()
        .find_map(|action| match action {
            TunnelAction::ConversationOpened {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        })
        .expect("conversation");
    let (_, request) = tunnel_frame(&request_actions);
    let opened = server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: request,
            },
            now,
        )
        .expect("issue credential");
    let (_, credential) = tunnel_frame(&opened);
    client
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: server_peer,
                bytes: credential,
            },
            now,
        )
        .expect("store credential");

    let reconnect_at = now + Duration::from_millis(21);
    let (new_session_id, server_established, client_established) = reconnect(
        &mut client,
        &mut server,
        client_peer,
        server_peer,
        reconnect_at,
    );
    assert_ne!(new_session_id, old_session_id);
    assert!(server_established.iter().any(|action| matches!(
        action,
        TunnelAction::SessionEstablished { resumed: false, .. }
    )));
    assert!(
        !server_established
            .iter()
            .any(|action| matches!(action, TunnelAction::SessionResumed { .. }))
    );
    assert!(client_established.iter().any(|action| matches!(
        action,
        TunnelAction::ConversationClosed {
            session_id: None,
            conversation_id: id,
        } if *id == conversation_id
    )));

    let after = client
        .handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: b"fresh conversation".to_vec(),
            },
            reconnect_at,
        )
        .expect("fresh request");
    assert!(after.iter().any(|action| matches!(
        action,
        TunnelAction::ConversationOpened { conversation_id: id, .. }
            if *id != conversation_id
    )));
}

#[test]
fn reconnect_handshake_timeout_closes_client() {
    let now = Instant::now();
    let (mut client_config, server_config) = configs(CipherSuite::ChaCha20Poly1305);
    client_config.handshake_retry_interval = Duration::from_millis(10);
    client_config.handshake_timeout = Duration::from_millis(30);
    client_config.handshake_max_attempts = 2;
    let (mut client, _, _, _, old_session_id) =
        establish_with_configs(now, client_config, server_config);
    client
        .handle(TunnelEvent::Reconnect, now)
        .expect("start reconnect");

    let closed_at = now + Duration::from_millis(30);
    let actions = client
        .handle(TunnelEvent::TimeAdvanced(closed_at), closed_at)
        .expect("reconnect timeout");
    assert_eq!(client.state(), SessionState::Closed);
    assert_eq!(client.session_id(), None);
    assert!(!actions.iter().any(|action| matches!(
        action,
        TunnelAction::SessionClosed { session_id, .. } if *session_id == old_session_id
    )));
}

#[test]
fn server_moves_idle_session_to_resumable_state_before_conversation_expiry() {
    let now = Instant::now();
    let (client_config, mut server_config) = configs(CipherSuite::ChaCha20Poly1305);
    server_config.conversation_idle_timeout = Duration::from_millis(40);
    server_config.session_idle_timeout = Duration::from_millis(20);
    let (mut client, mut server, client_peer, _, session_id) =
        establish_with_configs(now, client_config, server_config);
    let local_peer: SocketAddr = "127.0.0.1:33001".parse().expect("address");
    let request_actions = client
        .handle(
            TunnelEvent::ClientDatagram {
                local_peer,
                payload: b"active conversation".to_vec(),
            },
            now,
        )
        .expect("request");
    let (_, request) = tunnel_frame(&request_actions);
    server
        .handle(
            TunnelEvent::TunnelFrame {
                peer_id: client_peer,
                bytes: request,
            },
            now,
        )
        .expect("open conversation");

    let early = server
        .handle(
            TunnelEvent::TimeAdvanced(now + Duration::from_millis(20)),
            now + Duration::from_millis(20),
        )
        .expect("early session timer");
    assert!(early.iter().any(|action| matches!(
        action,
        TunnelAction::SessionClosed { session_id: id, .. } if *id == session_id
    )));
    assert!(
        !early
            .iter()
            .any(|action| matches!(action, TunnelAction::ConversationClosed { .. }))
    );
    assert_eq!(server.session_state(session_id), None);

    let expired = server
        .handle(
            TunnelEvent::TimeAdvanced(now + Duration::from_millis(40)),
            now + Duration::from_millis(40),
        )
        .expect("conversation and session expiry");
    assert!(expired.is_empty());
    assert_eq!(server.session_state(session_id), None);
}
