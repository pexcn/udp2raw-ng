use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::crypto::{Direction, SessionKeys};
use crate::handshake::{
    ClientFinish, ClientHello, HelloRetry, ServerHello, session_keys, verify_cookie,
};
use crate::record::{RecordOpener, RecordSealer};
use crate::{
    CipherSuite, ConversationId, EngineConfig, EngineError, FrameType, PeerId, Psk, Role,
    SessionId, WireFrame,
};

/// High-level authenticated session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Idle,
    Handshaking,
    Ready,
    Reconnecting,
    Closed,
}

/// Inputs accepted by the synchronous engine.
#[derive(Debug)]
pub enum TunnelEvent {
    Start,
    Reconnect,
    ClientDatagram {
        local_peer: SocketAddr,
        payload: Vec<u8>,
    },
    ServerDatagram {
        session_id: SessionId,
        conversation_id: ConversationId,
        payload: Vec<u8>,
    },
    TunnelFrame {
        peer_id: PeerId,
        bytes: Vec<u8>,
    },
    TimeAdvanced(Instant),
    CloseConversation {
        session_id: Option<SessionId>,
        conversation_id: ConversationId,
    },
}

/// Side effects the host must execute.
#[derive(Debug, Eq, PartialEq)]
pub enum TunnelAction {
    SendTunnelFrame {
        peer_id: PeerId,
        bytes: Vec<u8>,
    },
    DeliverToClient {
        local_peer: SocketAddr,
        payload: Vec<u8>,
    },
    DeliverToUpstream {
        session_id: SessionId,
        conversation_id: ConversationId,
        payload: Vec<u8>,
    },
    SessionEstablished {
        peer_id: PeerId,
        session_id: SessionId,
        cipher_suite: CipherSuite,
    },
    SessionClosed {
        peer_id: PeerId,
        session_id: SessionId,
    },
    ConversationOpened {
        session_id: Option<SessionId>,
        conversation_id: ConversationId,
    },
    ConversationClosed {
        session_id: Option<SessionId>,
        conversation_id: ConversationId,
    },
    ScheduleTimer(Duration),
}

#[derive(Debug)]
struct ClientConversation {
    id: ConversationId,
    last_activity: Instant,
}

enum ClientHandshakePhase {
    AwaitingServerHello,
    AwaitingServerAck {
        server_hello: ServerHello,
        finish_bytes: Vec<u8>,
    },
}

struct ClientHandshake {
    hello: ClientHello,
    phase: ClientHandshakePhase,
    started_at: Instant,
    last_sent_at: Instant,
    attempts: usize,
}

struct ClientSession {
    id: SessionId,
    sealer: RecordSealer,
    opener: RecordOpener,
    last_received_at: Instant,
    last_heartbeat_sent_at: Instant,
}

pub struct ClientEngine {
    config: EngineConfig,
    psk: Psk,
    server_peer: PeerId,
    state: SessionState,
    handshake: Option<ClientHandshake>,
    session: Option<ClientSession>,
    by_peer: HashMap<SocketAddr, ClientConversation>,
    by_id: HashMap<ConversationId, SocketAddr>,
}

impl ClientEngine {
    pub fn new(config: EngineConfig, psk: Psk, server_peer: PeerId) -> Result<Self, EngineError> {
        config.validate()?;
        if config.role != Role::Client {
            return Err(EngineError::InvalidRole);
        }
        Ok(Self {
            config,
            psk,
            server_peer,
            state: SessionState::Idle,
            handshake: None,
            session: None,
            by_peer: HashMap::new(),
            by_id: HashMap::new(),
        })
    }

    pub const fn state(&self) -> SessionState {
        self.state
    }

    pub fn session_id(&self) -> Option<SessionId> {
        self.session.as_ref().map(|session| session.id)
    }

    pub fn handle(
        &mut self,
        event: TunnelEvent,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        match event {
            TunnelEvent::Start => self.start(now),
            TunnelEvent::Reconnect => self.reconnect(now),
            TunnelEvent::ClientDatagram {
                local_peer,
                payload,
            } => self.handle_local(local_peer, payload, now),
            TunnelEvent::TunnelFrame { peer_id, bytes } => self.handle_tunnel(peer_id, bytes, now),
            TunnelEvent::TimeAdvanced(at) => Ok(self.expire(at)),
            TunnelEvent::CloseConversation {
                session_id,
                conversation_id,
            } => {
                if session_id.is_some() && session_id != self.session_id() {
                    return Err(EngineError::UnknownSession);
                }
                Ok(self.close(conversation_id).into_iter().collect())
            }
            TunnelEvent::ServerDatagram { .. } => Err(EngineError::InvalidRole),
        }
    }

    fn start(&mut self, now: Instant) -> Result<Vec<TunnelAction>, EngineError> {
        if self.state != SessionState::Idle {
            return Err(EngineError::SessionNotReady);
        }
        self.begin_handshake(now, SessionState::Handshaking)
    }

    fn reconnect(&mut self, now: Instant) -> Result<Vec<TunnelAction>, EngineError> {
        if self.state != SessionState::Ready {
            return Err(EngineError::SessionNotReady);
        }
        Ok(self.begin_reconnect(now))
    }

    fn begin_handshake(
        &mut self,
        now: Instant,
        state: SessionState,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let hello = ClientHello::generate(self.config.cipher_suite)?;
        let bytes = hello.frame().encode()?;
        self.handshake = Some(ClientHandshake {
            hello,
            phase: ClientHandshakePhase::AwaitingServerHello,
            started_at: now,
            last_sent_at: now,
            attempts: 1,
        });
        self.state = state;
        Ok(vec![
            TunnelAction::SendTunnelFrame {
                peer_id: self.server_peer,
                bytes,
            },
            TunnelAction::ScheduleTimer(self.config.handshake_retry_interval),
        ])
    }

    fn handle_local(
        &mut self,
        local_peer: SocketAddr,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if self.state != SessionState::Ready {
            return Err(EngineError::SessionNotReady);
        }
        if payload.len() > self.config.max_frame_payload {
            return Err(EngineError::PayloadTooLarge);
        }
        let mut actions = Vec::with_capacity(2);
        let conversation_id = if let Some(conversation) = self.by_peer.get_mut(&local_peer) {
            conversation.last_activity = now;
            conversation.id
        } else {
            if self.by_peer.len() >= self.config.max_conversations {
                return Err(EngineError::ConversationCapacity);
            }
            let id = ConversationId::generate()?;
            self.by_peer.insert(
                local_peer,
                ClientConversation {
                    id,
                    last_activity: now,
                },
            );
            self.by_id.insert(id, local_peer);
            actions.push(TunnelAction::ConversationOpened {
                session_id: self.session_id(),
                conversation_id: id,
            });
            id
        };
        let session = self.session.as_mut().ok_or(EngineError::SessionNotReady)?;
        let bytes = session
            .sealer
            .seal(FrameType::Data, Some(conversation_id), &payload)?;
        actions.push(TunnelAction::SendTunnelFrame {
            peer_id: self.server_peer,
            bytes,
        });
        Ok(actions)
    }

    fn handle_tunnel(
        &mut self,
        peer_id: PeerId,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if peer_id != self.server_peer {
            return Err(EngineError::UnexpectedPeer);
        }
        let envelope = WireFrame::decode(&bytes)?;
        if envelope.frame_type == FrameType::HelloRetry {
            return self.handle_hello_retry(envelope, now);
        }
        if envelope.frame_type == FrameType::ServerHello {
            return self.handle_server_hello(envelope, now);
        }
        if self.state != SessionState::Ready && !self.is_handshaking() {
            return Err(EngineError::SessionNotReady);
        }
        let was_handshaking = self.is_handshaking();
        let session = self.session.as_mut().ok_or(EngineError::SessionNotReady)?;
        let frame = match session.opener.open(&bytes) {
            Ok(frame) => frame,
            Err(crate::RecordError::Replay(crate::ReplayError::Duplicate))
                if envelope.frame_type == FrameType::HandshakeAck
                    && self.state == SessionState::Ready =>
            {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };
        if frame.frame_type == FrameType::HandshakeAck {
            if !was_handshaking {
                return Ok(Vec::new());
            }
            self.handshake = None;
            self.state = SessionState::Ready;
            session.last_received_at = now;
            session.last_heartbeat_sent_at = now;
            return Ok(vec![
                TunnelAction::SessionEstablished {
                    peer_id: self.server_peer,
                    session_id: session.id,
                    cipher_suite: self.config.cipher_suite,
                },
                TunnelAction::ScheduleTimer(self.config.heartbeat_interval),
            ]);
        }
        if self.state != SessionState::Ready {
            return Err(EngineError::SessionNotReady);
        }
        session.last_received_at = now;
        if frame.frame_type == FrameType::Heartbeat {
            return Ok(Vec::new());
        }
        if frame.frame_type != FrameType::Data {
            return Ok(Vec::new());
        }
        let id = frame
            .conversation_id
            .ok_or(EngineError::UnknownConversation)?;
        let local_peer = *self
            .by_id
            .get(&id)
            .ok_or(EngineError::UnknownConversation)?;
        if let Some(conversation) = self.by_peer.get_mut(&local_peer) {
            conversation.last_activity = now;
        }
        Ok(vec![TunnelAction::DeliverToClient {
            local_peer,
            payload: frame.plaintext,
        }])
    }

    fn handle_hello_retry(
        &mut self,
        frame: WireFrame,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if !self.is_handshaking() {
            return Err(EngineError::Handshake(
                crate::HandshakeError::UnexpectedMessage,
            ));
        }
        let handshake = self
            .handshake
            .as_mut()
            .ok_or(EngineError::SessionNotReady)?;
        if !matches!(handshake.phase, ClientHandshakePhase::AwaitingServerHello) {
            return Err(EngineError::Handshake(
                crate::HandshakeError::UnexpectedMessage,
            ));
        }
        let retry = HelloRetry::decode(&frame)?;
        handshake.hello = retry.verify_and_apply(&self.psk, &handshake.hello)?;
        let bytes = handshake.hello.frame().encode()?;
        handshake.last_sent_at = now;
        handshake.attempts = handshake.attempts.saturating_add(1);
        Ok(vec![
            TunnelAction::SendTunnelFrame {
                peer_id: self.server_peer,
                bytes,
            },
            TunnelAction::ScheduleTimer(self.config.handshake_retry_interval),
        ])
    }

    fn handle_server_hello(
        &mut self,
        frame: WireFrame,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if !self.is_handshaking() {
            return Err(EngineError::Handshake(
                crate::HandshakeError::UnexpectedMessage,
            ));
        }
        let handshake = self
            .handshake
            .as_mut()
            .ok_or(EngineError::SessionNotReady)?;
        let server_hello = ServerHello::decode(&frame)?;
        server_hello.verify(&self.psk, &handshake.hello, frame.session_id)?;
        let current_session_id = self.session.as_ref().map(|session| session.id);
        if let ClientHandshakePhase::AwaitingServerAck {
            server_hello: expected,
            finish_bytes,
        } = &handshake.phase
        {
            if expected.encode_payload() != server_hello.encode_payload()
                || current_session_id != Some(frame.session_id)
            {
                return Err(EngineError::Handshake(
                    crate::HandshakeError::UnexpectedMessage,
                ));
            }
            handshake.last_sent_at = now;
            handshake.attempts = handshake.attempts.saturating_add(1);
            return Ok(vec![
                TunnelAction::SendTunnelFrame {
                    peer_id: self.server_peer,
                    bytes: finish_bytes.clone(),
                },
                TunnelAction::ScheduleTimer(self.config.handshake_retry_interval),
            ]);
        }
        let finish =
            ClientFinish::create(&self.psk, &handshake.hello, &server_hello, frame.session_id)?;
        let finish_bytes = finish.frame(frame.session_id).encode()?;
        let keys = session_keys(&self.psk, &handshake.hello, &server_hello, frame.session_id)?;
        let SessionKeys {
            client_to_server,
            server_to_client,
        } = keys;
        self.session = Some(ClientSession {
            id: frame.session_id,
            sealer: RecordSealer::new(
                self.config.cipher_suite,
                Direction::ClientToServer,
                frame.session_id,
                client_to_server,
            ),
            opener: RecordOpener::new(
                self.config.cipher_suite,
                Direction::ServerToClient,
                frame.session_id,
                server_to_client,
                self.config.replay_window_size,
            ),
            last_received_at: now,
            last_heartbeat_sent_at: now,
        });
        handshake.phase = ClientHandshakePhase::AwaitingServerAck {
            server_hello,
            finish_bytes: finish_bytes.clone(),
        };
        handshake.last_sent_at = now;
        handshake.attempts = handshake.attempts.saturating_add(1);
        Ok(vec![
            TunnelAction::SendTunnelFrame {
                peer_id: self.server_peer,
                bytes: finish_bytes,
            },
            TunnelAction::ScheduleTimer(self.config.handshake_retry_interval),
        ])
    }

    fn expire(&mut self, now: Instant) -> Vec<TunnelAction> {
        let mut actions = Vec::new();
        if self.is_handshaking() {
            let should_close = self.handshake.as_ref().is_some_and(|handshake| {
                now.saturating_duration_since(handshake.started_at) >= self.config.handshake_timeout
                    || (handshake.attempts >= self.config.handshake_max_attempts
                        && now.saturating_duration_since(handshake.last_sent_at)
                            >= self.config.handshake_retry_interval)
            });
            if should_close {
                let closed_session = self.session.take().map(|session| session.id);
                self.handshake = None;
                self.state = SessionState::Closed;
                if let Some(session_id) = closed_session {
                    actions.push(TunnelAction::SessionClosed {
                        peer_id: self.server_peer,
                        session_id,
                    });
                }
            } else if let Some(handshake) = self.handshake.as_mut()
                && now.saturating_duration_since(handshake.last_sent_at)
                    >= self.config.handshake_retry_interval
                && handshake.attempts < self.config.handshake_max_attempts
            {
                let bytes = match &handshake.phase {
                    ClientHandshakePhase::AwaitingServerHello => handshake.hello.frame().encode(),
                    ClientHandshakePhase::AwaitingServerAck { finish_bytes, .. } => {
                        Ok(finish_bytes.clone())
                    }
                };
                if let Ok(bytes) = bytes {
                    handshake.last_sent_at = now;
                    handshake.attempts += 1;
                    actions.push(TunnelAction::SendTunnelFrame {
                        peer_id: self.server_peer,
                        bytes,
                    });
                    actions.push(TunnelAction::ScheduleTimer(
                        self.config.handshake_retry_interval,
                    ));
                }
            }
        } else if self.state == SessionState::Ready {
            let timed_out = self.session.as_ref().is_some_and(|session| {
                now.saturating_duration_since(session.last_received_at)
                    >= self.config.session_timeout
            });
            if timed_out {
                actions.extend(self.begin_reconnect(now));
            } else if self.session.as_ref().is_some_and(|session| {
                now.saturating_duration_since(session.last_heartbeat_sent_at)
                    >= self.config.heartbeat_interval
            }) {
                let heartbeat = self
                    .session
                    .as_mut()
                    .expect("ready client has a session")
                    .sealer
                    .seal(FrameType::Heartbeat, None, &[]);
                match heartbeat {
                    Ok(bytes) => {
                        self.session
                            .as_mut()
                            .expect("ready client has a session")
                            .last_heartbeat_sent_at = now;
                        actions.push(TunnelAction::SendTunnelFrame {
                            peer_id: self.server_peer,
                            bytes,
                        });
                        actions.push(TunnelAction::ScheduleTimer(self.config.heartbeat_interval));
                    }
                    Err(_) => actions.extend(self.begin_reconnect(now)),
                }
            }
        }
        let timeout = self.config.conversation_idle_timeout;
        let expired: Vec<_> = self
            .by_peer
            .iter()
            .filter_map(|(peer, conversation)| {
                (now.saturating_duration_since(conversation.last_activity) >= timeout)
                    .then_some((*peer, conversation.id))
            })
            .collect();
        actions.extend(expired.into_iter().map(|(peer, id)| {
            self.by_peer.remove(&peer);
            self.by_id.remove(&id);
            TunnelAction::ConversationClosed {
                session_id: self.session_id(),
                conversation_id: id,
            }
        }));
        actions
    }

    fn begin_reconnect(&mut self, now: Instant) -> Vec<TunnelAction> {
        let mut actions = Vec::new();
        if let Some(session) = self.session.take() {
            actions.push(TunnelAction::SessionClosed {
                peer_id: self.server_peer,
                session_id: session.id,
            });
        }
        self.handshake = None;
        match self.begin_handshake(now, SessionState::Reconnecting) {
            Ok(handshake_actions) => actions.extend(handshake_actions),
            Err(_) => self.state = SessionState::Closed,
        }
        actions
    }

    fn is_handshaking(&self) -> bool {
        matches!(
            self.state,
            SessionState::Handshaking | SessionState::Reconnecting
        )
    }

    fn close(&mut self, id: ConversationId) -> Option<TunnelAction> {
        let peer = self.by_id.remove(&id)?;
        self.by_peer.remove(&peer);
        Some(TunnelAction::ConversationClosed {
            session_id: self.session_id(),
            conversation_id: id,
        })
    }
}

struct PendingHandshake {
    peer_id: PeerId,
    created_at: Instant,
    client_hello: ClientHello,
    server_hello: ServerHello,
}

struct ServerSession {
    peer_id: PeerId,
    sealer: RecordSealer,
    opener: RecordOpener,
    handshake_ack: Vec<u8>,
    client_finish: Vec<u8>,
    conversations: HashMap<ConversationId, Instant>,
    last_activity: Instant,
    expires_at: Instant,
}

pub struct ServerEngine {
    config: EngineConfig,
    psk: Psk,
    cookie_secret: Zeroizing<[u8; 32]>,
    clock_origin: Option<Instant>,
    pending: HashMap<SessionId, PendingHandshake>,
    sessions: HashMap<SessionId, ServerSession>,
}

impl ServerEngine {
    pub fn new(config: EngineConfig, psk: Psk) -> Result<Self, EngineError> {
        config.validate()?;
        if config.role != Role::Server {
            return Err(EngineError::InvalidRole);
        }
        let mut cookie_secret = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(cookie_secret.as_mut())
            .map_err(|_| EngineError::RandomnessUnavailable)?;
        Ok(Self {
            config,
            psk,
            cookie_secret,
            clock_origin: None,
            pending: HashMap::new(),
            sessions: HashMap::new(),
        })
    }

    pub fn session_state(&self, session_id: SessionId) -> Option<SessionState> {
        if self.sessions.contains_key(&session_id) {
            Some(SessionState::Ready)
        } else if self.pending.contains_key(&session_id) {
            Some(SessionState::Handshaking)
        } else {
            None
        }
    }

    pub fn handle(
        &mut self,
        event: TunnelEvent,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        match event {
            TunnelEvent::TunnelFrame { peer_id, bytes } => self.handle_tunnel(peer_id, bytes, now),
            TunnelEvent::ServerDatagram {
                session_id,
                conversation_id,
                payload,
            } => self.handle_upstream(session_id, conversation_id, payload, now),
            TunnelEvent::CloseConversation {
                session_id,
                conversation_id,
            } => {
                let session_id = session_id.ok_or(EngineError::UnknownSession)?;
                self.close(session_id, conversation_id)
            }
            TunnelEvent::TimeAdvanced(at) => Ok(self.expire(at)),
            TunnelEvent::Start | TunnelEvent::Reconnect | TunnelEvent::ClientDatagram { .. } => {
                Err(EngineError::InvalidRole)
            }
        }
    }

    fn handle_tunnel(
        &mut self,
        peer_id: PeerId,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let frame = WireFrame::decode(&bytes)?;
        match frame.frame_type {
            FrameType::ClientHello => self.handle_client_hello(peer_id, frame, now),
            FrameType::ClientFinish => self.handle_client_finish(peer_id, frame, now),
            _ if frame.frame_type.is_protected() => {
                self.handle_record(peer_id, frame.session_id, bytes, now)
            }
            _ => Err(EngineError::Handshake(
                crate::HandshakeError::UnexpectedMessage,
            )),
        }
    }

    fn handle_client_hello(
        &mut self,
        peer_id: PeerId,
        frame: WireFrame,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let hello = ClientHello::decode(&frame)?;
        if hello.suite != self.config.cipher_suite {
            return Err(EngineError::Handshake(
                crate::HandshakeError::CipherSuiteMismatch,
            ));
        }
        if self.config.require_handshake_cookie {
            let origin = self.clock_origin.get_or_insert(now);
            let now_ms = u64::try_from(now.saturating_duration_since(*origin).as_millis())
                .unwrap_or(u64::MAX);
            if verify_cookie(
                self.cookie_secret.as_ref(),
                &hello,
                peer_id,
                now_ms,
                self.config.handshake_cookie_lifetime,
            )
            .is_err()
            {
                let retry = HelloRetry::create(
                    &self.psk,
                    self.cookie_secret.as_ref(),
                    &hello,
                    peer_id,
                    now_ms,
                )?;
                return Ok(vec![TunnelAction::SendTunnelFrame {
                    peer_id,
                    bytes: retry.frame().encode()?,
                }]);
            }
        }
        if let Some((session_id, pending)) = self.pending.iter().find(|(_, pending)| {
            pending.peer_id == peer_id
                && pending.client_hello.encode_payload() == hello.encode_payload()
        }) {
            return Ok(vec![TunnelAction::SendTunnelFrame {
                peer_id,
                bytes: pending.server_hello.frame(*session_id).encode()?,
            }]);
        }
        if self.pending.len() >= self.config.max_pending_handshakes {
            return Err(EngineError::PendingHandshakeCapacity);
        }
        if self
            .pending
            .values()
            .filter(|pending| pending.peer_id == peer_id)
            .count()
            >= self.config.max_pending_handshakes_per_peer
        {
            return Err(EngineError::PerPeerPendingHandshakeCapacity);
        }
        let session_id = loop {
            let candidate = SessionId::generate()?;
            if candidate != SessionId::from_u128(0)
                && !self.pending.contains_key(&candidate)
                && !self.sessions.contains_key(&candidate)
            {
                break candidate;
            }
        };
        let server_hello = ServerHello::create(&self.psk, &hello, session_id)?;
        let bytes = server_hello.frame(session_id).encode()?;
        self.pending.insert(
            session_id,
            PendingHandshake {
                peer_id,
                created_at: now,
                client_hello: hello,
                server_hello,
            },
        );
        Ok(vec![
            TunnelAction::SendTunnelFrame { peer_id, bytes },
            TunnelAction::ScheduleTimer(self.config.handshake_timeout),
        ])
    }

    fn handle_client_finish(
        &mut self,
        peer_id: PeerId,
        frame: WireFrame,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if let Some(session) = self.sessions.get(&frame.session_id) {
            if session.peer_id != peer_id {
                return Err(EngineError::UnexpectedPeer);
            }
            if session.client_finish != frame.encode()? {
                return Err(EngineError::Handshake(
                    crate::HandshakeError::AuthenticationFailed,
                ));
            }
            return Ok(vec![TunnelAction::SendTunnelFrame {
                peer_id,
                bytes: session.handshake_ack.clone(),
            }]);
        }
        if self.sessions.len() >= self.config.max_sessions {
            return Err(EngineError::SessionCapacity);
        }
        let pending = self
            .pending
            .get(&frame.session_id)
            .ok_or(crate::HandshakeError::UnknownPendingHandshake)?;
        if pending.peer_id != peer_id {
            return Err(EngineError::UnexpectedPeer);
        }
        let finish = ClientFinish::decode(&frame)?;
        finish.verify(
            &self.psk,
            &pending.client_hello,
            &pending.server_hello,
            frame.session_id,
        )?;
        let keys = session_keys(
            &self.psk,
            &pending.client_hello,
            &pending.server_hello,
            frame.session_id,
        )?;
        let SessionKeys {
            client_to_server,
            server_to_client,
        } = keys;
        let mut sealer = RecordSealer::new(
            self.config.cipher_suite,
            Direction::ServerToClient,
            frame.session_id,
            server_to_client,
        );
        let handshake_ack = sealer.seal(FrameType::HandshakeAck, None, &[])?;
        let client_finish = frame.encode()?;
        self.sessions.insert(
            frame.session_id,
            ServerSession {
                peer_id,
                sealer,
                opener: RecordOpener::new(
                    self.config.cipher_suite,
                    Direction::ClientToServer,
                    frame.session_id,
                    client_to_server,
                    self.config.replay_window_size,
                ),
                handshake_ack: handshake_ack.clone(),
                client_finish,
                conversations: HashMap::new(),
                last_activity: now,
                expires_at: now + self.config.session_idle_timeout,
            },
        );
        self.pending.remove(&frame.session_id);
        Ok(vec![
            TunnelAction::SendTunnelFrame {
                peer_id,
                bytes: handshake_ack,
            },
            TunnelAction::SessionEstablished {
                peer_id,
                session_id: frame.session_id,
                cipher_suite: self.config.cipher_suite,
            },
            TunnelAction::ScheduleTimer(self.config.session_idle_timeout),
        ])
    }

    fn handle_record(
        &mut self,
        peer_id: PeerId,
        session_id: SessionId,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(EngineError::UnknownSession)?;
        if session.peer_id != peer_id {
            return Err(EngineError::UnexpectedPeer);
        }
        let frame = session.opener.open(&bytes)?;
        session.last_activity = now;
        session.expires_at = now + self.config.session_idle_timeout;
        if frame.frame_type == FrameType::Heartbeat {
            let bytes = session.sealer.seal(FrameType::Heartbeat, None, &[])?;
            return Ok(vec![
                TunnelAction::SendTunnelFrame { peer_id, bytes },
                TunnelAction::ScheduleTimer(self.config.session_idle_timeout),
            ]);
        }
        if frame.frame_type != FrameType::Data {
            return Ok(Vec::new());
        }
        let conversation_id = frame
            .conversation_id
            .ok_or(EngineError::UnknownConversation)?;
        let mut actions = Vec::with_capacity(2);
        let is_new = !session.conversations.contains_key(&conversation_id);
        if is_new {
            if session.conversations.len() >= self.config.max_conversations {
                return Err(EngineError::ConversationCapacity);
            }
            session.conversations.insert(conversation_id, now);
            actions.push(TunnelAction::ConversationOpened {
                session_id: Some(session_id),
                conversation_id,
            });
        } else {
            session.conversations.insert(conversation_id, now);
        }
        actions.push(TunnelAction::DeliverToUpstream {
            session_id,
            conversation_id,
            payload: frame.plaintext,
        });
        actions.push(TunnelAction::ScheduleTimer(
            self.config.session_idle_timeout,
        ));
        Ok(actions)
    }

    fn handle_upstream(
        &mut self,
        session_id: SessionId,
        conversation_id: ConversationId,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if payload.len() > self.config.max_frame_payload {
            return Err(EngineError::PayloadTooLarge);
        }
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(EngineError::UnknownSession)?;
        if !session.conversations.contains_key(&conversation_id) {
            return Err(EngineError::UnknownConversation);
        }
        session.last_activity = now;
        session.expires_at = now + self.config.session_idle_timeout;
        let bytes = session
            .sealer
            .seal(FrameType::Data, Some(conversation_id), &payload)?;
        Ok(vec![
            TunnelAction::SendTunnelFrame {
                peer_id: session.peer_id,
                bytes,
            },
            TunnelAction::ScheduleTimer(self.config.session_idle_timeout),
        ])
    }

    fn close(
        &mut self,
        session_id: SessionId,
        conversation_id: ConversationId,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(EngineError::UnknownSession)?;
        if session.conversations.remove(&conversation_id).is_none() {
            return Err(EngineError::UnknownConversation);
        }
        Ok(vec![TunnelAction::ConversationClosed {
            session_id: Some(session_id),
            conversation_id,
        }])
    }

    fn expire(&mut self, now: Instant) -> Vec<TunnelAction> {
        let handshake_timeout = self.config.handshake_timeout;
        self.pending.retain(|_, pending| {
            now.saturating_duration_since(pending.created_at) < handshake_timeout
        });

        let conversation_timeout = self.config.conversation_idle_timeout;
        let mut actions = Vec::new();
        for (session_id, session) in &mut self.sessions {
            let expired: Vec<_> = session
                .conversations
                .iter()
                .filter_map(|(conversation_id, last_activity)| {
                    (now.saturating_duration_since(*last_activity) >= conversation_timeout)
                        .then_some(*conversation_id)
                })
                .collect();
            for conversation_id in expired {
                session.conversations.remove(&conversation_id);
                actions.push(TunnelAction::ConversationClosed {
                    session_id: Some(*session_id),
                    conversation_id,
                });
            }
        }
        let session_timeout = self.config.session_idle_timeout;
        let expired_sessions: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (session.conversations.is_empty()
                    && now >= session.expires_at
                    && now.saturating_duration_since(session.last_activity) >= session_timeout)
                    .then_some((*session_id, session.peer_id))
            })
            .collect();
        for (session_id, peer_id) in expired_sessions {
            self.sessions.remove(&session_id);
            actions.push(TunnelAction::SessionClosed {
                peer_id,
                session_id,
            });
        }
        actions
    }
}
