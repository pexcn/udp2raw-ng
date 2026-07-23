use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{Direction, SessionKeys};
use crate::handshake::{
    ClientFinish, ClientHello, HelloRetry, ResumptionCredential, ServerHello,
    issue_resumption_credential, session_keys, verify_cookie, verify_resumption_credential,
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

/// Why a locally received UDP datagram was intentionally discarded before it
/// could be placed in a protected tunnel record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientDatagramDropReason {
    /// The bounded handshaking/reconnection queue was already full.
    ReconnectQueueFull,
    /// The datagram waited too long for an authenticated session.
    ReconnectQueueExpired,
    /// The handshake ended without establishing a session.
    SessionClosed,
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
        resumed: bool,
    },
    SessionResumed {
        peer_id: PeerId,
        old_session_id: SessionId,
        new_session_id: SessionId,
    },
    SessionClosed {
        peer_id: PeerId,
        session_id: SessionId,
    },
    /// The server can no longer resume the session, so a host may release
    /// resources retained solely for its recovery window.
    SessionRecoveryExpired {
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
    ClientDatagramDropped {
        local_peer: SocketAddr,
        reason: ClientDatagramDropReason,
    },
    ScheduleTimer(Duration),
}

#[derive(Debug)]
struct ClientConversation {
    id: ConversationId,
    last_activity: Instant,
    resumption: Option<(SessionId, ResumptionCredential)>,
}

struct QueuedClientDatagram {
    local_peer: SocketAddr,
    payload: Zeroizing<Vec<u8>>,
    queued_at: Instant,
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
    resumed: bool,
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
    queued_datagrams: VecDeque<QueuedClientDatagram>,
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
            queued_datagrams: VecDeque::new(),
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
        let resumption = if state == SessionState::Reconnecting {
            let mut credentials = self.by_peer.values().filter_map(|conversation| {
                conversation
                    .resumption
                    .map(|(session_id, credential)| (conversation.id, session_id, credential))
            });
            credentials.next().and_then(|(_, session_id, credential)| {
                (self.by_peer.values().all(|conversation| {
                    conversation
                        .resumption
                        .is_some_and(|(candidate, _)| candidate == session_id)
                }))
                .then_some(credential)
            })
        } else {
            None
        };
        let hello = ClientHello::generate(self.config.cipher_suite, resumption)?;
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
        mut payload: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        if payload.len() > self.config.max_frame_payload {
            return Err(EngineError::PayloadTooLarge);
        }
        if self.state != SessionState::Ready {
            if self.is_handshaking() {
                if self.queued_datagrams.len() >= self.config.reconnect_queue_capacity {
                    return Ok(vec![TunnelAction::ClientDatagramDropped {
                        local_peer,
                        reason: ClientDatagramDropReason::ReconnectQueueFull,
                    }]);
                }
                self.queued_datagrams.push_back(QueuedClientDatagram {
                    local_peer,
                    payload: Zeroizing::new(payload),
                    queued_at: now,
                });
                return Ok(vec![TunnelAction::ScheduleTimer(
                    self.config.reconnect_queue_timeout,
                )]);
            }
            return Err(EngineError::SessionNotReady);
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
                    resumption: None,
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
            .seal(FrameType::Data, Some(conversation_id), &payload);
        payload.zeroize();
        let bytes = bytes?;
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
            let attempted_resumption = self
                .handshake
                .as_ref()
                .is_some_and(|handshake| handshake.hello.resumption.is_some());
            let resumed = session.resumed;
            self.handshake = None;
            self.state = SessionState::Ready;
            session.last_received_at = now;
            let mut actions = Vec::new();
            if attempted_resumption && !resumed {
                let stale: Vec<_> = self
                    .by_peer
                    .drain()
                    .map(|(_, conversation)| conversation.id)
                    .collect();
                self.by_id.clear();
                actions.extend(stale.into_iter().map(|conversation_id| {
                    TunnelAction::ConversationClosed {
                        session_id: None,
                        conversation_id,
                    }
                }));
            }
            actions.push(TunnelAction::SessionEstablished {
                peer_id: self.server_peer,
                session_id: session.id,
                cipher_suite: self.config.cipher_suite,
                resumed,
            });
            actions.extend(self.flush_queued_datagrams(now));
            actions.push(TunnelAction::ScheduleTimer(self.config.session_timeout));
            return Ok(actions);
        }
        if self.state != SessionState::Ready {
            return Err(EngineError::SessionNotReady);
        }
        session.last_received_at = now;
        if frame.frame_type == FrameType::ResumptionCredential {
            let id = frame
                .conversation_id
                .ok_or(EngineError::UnknownConversation)?;
            let local_peer = *self
                .by_id
                .get(&id)
                .ok_or(EngineError::UnknownConversation)?;
            let credential = ResumptionCredential::from_bytes(
                frame
                    .plaintext
                    .try_into()
                    .map_err(|_| crate::HandshakeError::InvalidResumptionCredential)?,
            );
            if let Some(conversation) = self.by_peer.get_mut(&local_peer) {
                conversation.resumption = Some((session.id, credential));
                conversation.last_activity = now;
            }
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
            resumed: server_hello.resumed,
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
                actions
                    .extend(self.clear_queued_datagrams(ClientDatagramDropReason::SessionClosed));
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
            }
        }
        actions.extend(self.expire_queued_datagrams(now));
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

    fn flush_queued_datagrams(&mut self, now: Instant) -> Vec<TunnelAction> {
        let mut actions = Vec::new();
        while let Some(mut queued) = self.queued_datagrams.pop_front() {
            if now.saturating_duration_since(queued.queued_at)
                >= self.config.reconnect_queue_timeout
            {
                actions.push(TunnelAction::ClientDatagramDropped {
                    local_peer: queued.local_peer,
                    reason: ClientDatagramDropReason::ReconnectQueueExpired,
                });
                continue;
            }
            let payload = std::mem::take(&mut *queued.payload);
            match self.handle_local(queued.local_peer, payload, now) {
                Ok(mut queued_actions) => actions.append(&mut queued_actions),
                Err(_) => actions.push(TunnelAction::ClientDatagramDropped {
                    local_peer: queued.local_peer,
                    reason: ClientDatagramDropReason::SessionClosed,
                }),
            }
        }
        actions
    }

    fn expire_queued_datagrams(&mut self, now: Instant) -> Vec<TunnelAction> {
        let mut actions = Vec::new();
        while self.queued_datagrams.front().is_some_and(|queued| {
            now.saturating_duration_since(queued.queued_at) >= self.config.reconnect_queue_timeout
        }) {
            let queued = self
                .queued_datagrams
                .pop_front()
                .expect("queued datagram is present");
            actions.push(TunnelAction::ClientDatagramDropped {
                local_peer: queued.local_peer,
                reason: ClientDatagramDropReason::ReconnectQueueExpired,
            });
        }
        if !self.queued_datagrams.is_empty() {
            actions.push(TunnelAction::ScheduleTimer(
                self.config.reconnect_queue_timeout,
            ));
        }
        actions
    }

    fn clear_queued_datagrams(&mut self, reason: ClientDatagramDropReason) -> Vec<TunnelAction> {
        self.queued_datagrams
            .drain(..)
            .map(|queued| TunnelAction::ClientDatagramDropped {
                local_peer: queued.local_peer,
                reason,
            })
            .collect()
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

#[derive(Clone)]
struct PendingHandshake {
    peer_id: PeerId,
    created_at: Instant,
    client_hello: ClientHello,
    server_hello: ServerHello,
    resume_from: Option<SessionId>,
}

struct HandshakeRateBucket {
    tokens: usize,
    last_refill_at: Instant,
}

struct ServerSession {
    peer_id: PeerId,
    sealer: RecordSealer,
    opener: RecordOpener,
    handshake_ack: Vec<u8>,
    client_finish: Vec<u8>,
    conversations: HashMap<ConversationId, Instant>,
    resumption_credential: Option<(ResumptionCredential, Instant)>,
    last_activity: Instant,
    expires_at: Instant,
}

struct ResumableSession {
    conversations: HashMap<ConversationId, Instant>,
    expires_at: Instant,
}

pub struct ServerEngine {
    config: EngineConfig,
    psk: Psk,
    cookie_secret: Zeroizing<[u8; 32]>,
    clock_origin: Option<Instant>,
    pending: HashMap<SessionId, PendingHandshake>,
    sessions: HashMap<SessionId, ServerSession>,
    resumable: HashMap<SessionId, ResumableSession>,
    handshake_rate_buckets: HashMap<PeerId, HandshakeRateBucket>,
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
            resumable: HashMap::new(),
            handshake_rate_buckets: HashMap::new(),
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
        if !self.allow_handshake_attempt(peer_id, now) {
            return Err(EngineError::HandshakeRateLimited);
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
            if candidate != SessionId::from_u64(0)
                && !self.pending.contains_key(&candidate)
                && !self.sessions.contains_key(&candidate)
                && !self.resumable.contains_key(&candidate)
            {
                break candidate;
            }
        };
        let now_ms = self.now_ms(now);
        let resume_from = hello.resumption.and_then(|credential| {
            verify_resumption_credential(self.cookie_secret.as_ref(), credential, now_ms)
                .ok()
                .and_then(|(old_session_id, conversation_id)| {
                    let active_matches =
                        self.sessions.get(&old_session_id).is_some_and(|session| {
                            session.conversations.contains_key(&conversation_id)
                                && session.resumption_credential.is_some()
                        });
                    let resumable_matches = self
                        .resumable
                        .get(&old_session_id)
                        .is_some_and(|state| state.conversations.contains_key(&conversation_id));
                    (active_matches || resumable_matches).then_some(old_session_id)
                })
        });
        let resume_from = resume_from.filter(|old_session_id| {
            !self
                .pending
                .values()
                .any(|pending| pending.resume_from == Some(*old_session_id))
        });
        let server_hello =
            ServerHello::create(&self.psk, &hello, session_id, resume_from.is_some())?;
        let bytes = server_hello.frame(session_id).encode()?;
        self.pending.insert(
            session_id,
            PendingHandshake {
                peer_id,
                created_at: now,
                client_hello: hello,
                server_hello,
                resume_from,
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
        let pending = self
            .pending
            .get(&frame.session_id)
            .cloned()
            .ok_or(crate::HandshakeError::UnknownPendingHandshake)?;
        if pending.peer_id != peer_id {
            return Err(EngineError::UnexpectedPeer);
        }
        let replaces_active_session = pending
            .resume_from
            .is_some_and(|session_id| self.sessions.contains_key(&session_id));
        if self.sessions.len() >= self.config.max_sessions && !replaces_active_session {
            return Err(EngineError::SessionCapacity);
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
        let resume_from = pending.resume_from;
        let conversations = resume_from.map_or_else(HashMap::new, |old_session_id| {
            self.sessions
                .remove(&old_session_id)
                .map(|session| session.conversations)
                .or_else(|| {
                    self.resumable
                        .remove(&old_session_id)
                        .map(|state| state.conversations)
                })
                .unwrap_or_default()
        });
        let resumption_credential = if conversations.is_empty() {
            None
        } else {
            pending
                .client_hello
                .resumption
                .map(|credential| (credential, now + self.config.resumption_lifetime))
        };
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
                conversations,
                resumption_credential,
                last_activity: now,
                expires_at: now + self.config.session_idle_timeout,
            },
        );
        self.pending.remove(&frame.session_id);
        let mut actions = vec![
            TunnelAction::SendTunnelFrame {
                peer_id,
                bytes: handshake_ack,
            },
            TunnelAction::SessionEstablished {
                peer_id,
                session_id: frame.session_id,
                cipher_suite: self.config.cipher_suite,
                resumed: resume_from.is_some(),
            },
        ];
        if let Some(old_session_id) = resume_from {
            actions.push(TunnelAction::SessionResumed {
                peer_id,
                old_session_id,
                new_session_id: frame.session_id,
            });
        }
        actions.push(TunnelAction::ScheduleTimer(
            self.config.session_idle_timeout,
        ));
        Ok(actions)
    }

    fn handle_record(
        &mut self,
        peer_id: PeerId,
        session_id: SessionId,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let now_ms = self.now_ms(now);
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
        let should_refresh_credential =
            session
                .resumption_credential
                .as_ref()
                .is_none_or(|(_, expires_at)| {
                    expires_at.saturating_duration_since(now) <= self.config.resumption_lifetime / 2
                });
        if should_refresh_credential {
            let lifetime_ms =
                u64::try_from(self.config.resumption_lifetime.as_millis()).unwrap_or(u64::MAX);
            let credential = issue_resumption_credential(
                self.cookie_secret.as_ref(),
                session_id,
                conversation_id,
                now_ms,
                now_ms.saturating_add(lifetime_ms),
            )?;
            session.resumption_credential =
                Some((credential, now + self.config.resumption_lifetime));
            let conversations: Vec<_> = session.conversations.keys().copied().collect();
            for conversation_id in conversations {
                let bytes = session.sealer.seal(
                    FrameType::ResumptionCredential,
                    Some(conversation_id),
                    credential.as_bytes(),
                )?;
                actions.push(TunnelAction::SendTunnelFrame { peer_id, bytes });
            }
        } else if is_new {
            let credential = session
                .resumption_credential
                .as_ref()
                .map(|(credential, _)| *credential)
                .expect("active session has a resumption credential");
            let bytes = session.sealer.seal(
                FrameType::ResumptionCredential,
                Some(conversation_id),
                credential.as_bytes(),
            )?;
            actions.push(TunnelAction::SendTunnelFrame { peer_id, bytes });
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
                (now >= session.expires_at
                    && now.saturating_duration_since(session.last_activity) >= session_timeout)
                    .then_some((*session_id, session.peer_id))
            })
            .collect();
        for (session_id, peer_id) in expired_sessions {
            if let Some(session) = self.sessions.remove(&session_id) {
                if !session.conversations.is_empty() {
                    self.resumable.insert(
                        session_id,
                        ResumableSession {
                            conversations: session.conversations,
                            expires_at: now + self.config.resumption_lifetime,
                        },
                    );
                }
            }
            actions.push(TunnelAction::SessionClosed {
                peer_id,
                session_id,
            });
        }
        let expired_resumable: Vec<_> = self
            .resumable
            .iter()
            .filter_map(|(session_id, state)| (now >= state.expires_at).then_some(*session_id))
            .collect();
        for session_id in expired_resumable {
            self.resumable.remove(&session_id);
            actions.push(TunnelAction::SessionRecoveryExpired { session_id });
        }
        let bucket_retention = self.config.handshake_rate_refill_interval.saturating_mul(
            u32::try_from(self.config.handshake_rate_limit_burst).unwrap_or(u32::MAX),
        );
        self.handshake_rate_buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_refill_at) < bucket_retention
        });
        actions
    }

    fn allow_handshake_attempt(&mut self, peer_id: PeerId, now: Instant) -> bool {
        let burst = self.config.handshake_rate_limit_burst;
        let refill_interval = self.config.handshake_rate_refill_interval;
        if !self.handshake_rate_buckets.contains_key(&peer_id)
            && self.handshake_rate_buckets.len() >= self.config.max_pending_handshakes
        {
            return false;
        }
        let bucket = self
            .handshake_rate_buckets
            .entry(peer_id)
            .or_insert(HandshakeRateBucket {
                tokens: burst,
                last_refill_at: now,
            });
        let elapsed = now.saturating_duration_since(bucket.last_refill_at);
        let refill_count = elapsed.as_nanos() / refill_interval.as_nanos();
        if refill_count != 0 {
            bucket.tokens = bucket
                .tokens
                .saturating_add(usize::try_from(refill_count).unwrap_or(usize::MAX))
                .min(burst);
            bucket.last_refill_at = now;
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        true
    }

    fn now_ms(&mut self, now: Instant) -> u64 {
        let origin = self.clock_origin.get_or_insert(now);
        u64::try_from(now.saturating_duration_since(*origin).as_millis()).unwrap_or(u64::MAX)
    }
}
