use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::{ConversationId, EngineConfig, EngineError, FrameType, Role, SessionId, WireFrame};

/// Inputs accepted by the synchronous engine.
#[derive(Debug)]
pub enum TunnelEvent {
    ClientDatagram {
        local_peer: SocketAddr,
        payload: Vec<u8>,
    },
    ServerDatagram {
        session_id: SessionId,
        conversation_id: ConversationId,
        payload: Vec<u8>,
    },
    TunnelFrame(Vec<u8>),
    TimeAdvanced(Instant),
    CloseConversation(ConversationId),
}

/// Side effects the host must execute.
#[derive(Debug, Eq, PartialEq)]
pub enum TunnelAction {
    SendTunnelFrame(Vec<u8>),
    DeliverToClient {
        local_peer: SocketAddr,
        payload: Vec<u8>,
    },
    DeliverToUpstream {
        session_id: SessionId,
        conversation_id: ConversationId,
        payload: Vec<u8>,
    },
    ConversationOpened(ConversationId),
    ConversationClosed(ConversationId),
    ScheduleTimer(Duration),
}

#[derive(Debug)]
struct ClientConversation {
    id: ConversationId,
    last_activity: Instant,
}

/// Minimal client-side event engine.
///
/// Frames emitted here are not secure until the handshake/record layer lands.
pub struct ClientEngine {
    config: EngineConfig,
    session_id: SessionId,
    next_packet_number: u64,
    by_peer: HashMap<SocketAddr, ClientConversation>,
    by_id: HashMap<ConversationId, SocketAddr>,
}

impl ClientEngine {
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        config.validate()?;
        if config.role != Role::Client {
            return Err(EngineError::InvalidRole);
        }
        Ok(Self {
            config,
            session_id: SessionId::generate()?,
            next_packet_number: 0,
            by_peer: HashMap::new(),
            by_id: HashMap::new(),
        })
    }

    pub fn handle(
        &mut self,
        event: TunnelEvent,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        match event {
            TunnelEvent::ClientDatagram {
                local_peer,
                payload,
            } => self.handle_local(local_peer, payload, now),
            TunnelEvent::TunnelFrame(bytes) => self.handle_tunnel(bytes, now),
            TunnelEvent::TimeAdvanced(at) => Ok(self.expire(at)),
            TunnelEvent::CloseConversation(id) => Ok(self.close(id).into_iter().collect()),
            TunnelEvent::ServerDatagram { .. } => Err(EngineError::InvalidRole),
        }
    }

    fn handle_local(
        &mut self,
        local_peer: SocketAddr,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
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
            actions.push(TunnelAction::ConversationOpened(id));
            id
        };
        let frame = self.data_frame(conversation_id, payload)?;
        actions.push(TunnelAction::SendTunnelFrame(frame.encode()?));
        Ok(actions)
    }

    fn handle_tunnel(
        &mut self,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<TunnelAction>, EngineError> {
        let frame = WireFrame::decode(&bytes)?;
        if frame.session_id != self.session_id || frame.frame_type != FrameType::Data {
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
            payload: frame.payload,
        }])
    }

    fn data_frame(
        &mut self,
        conversation_id: ConversationId,
        payload: Vec<u8>,
    ) -> Result<WireFrame, EngineError> {
        let packet_number = self.next_packet_number;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(EngineError::PacketNumberExhausted)?;
        Ok(WireFrame {
            session_id: self.session_id,
            packet_number,
            epoch: 0,
            frame_type: FrameType::Data,
            conversation_id: Some(conversation_id),
            payload,
        })
    }

    fn expire(&mut self, now: Instant) -> Vec<TunnelAction> {
        let timeout = self.config.conversation_idle_timeout;
        let expired: Vec<_> = self
            .by_peer
            .iter()
            .filter_map(|(peer, conversation)| {
                (now.saturating_duration_since(conversation.last_activity) >= timeout)
                    .then_some((*peer, conversation.id))
            })
            .collect();
        expired
            .into_iter()
            .map(|(peer, id)| {
                self.by_peer.remove(&peer);
                self.by_id.remove(&id);
                TunnelAction::ConversationClosed(id)
            })
            .collect()
    }

    fn close(&mut self, id: ConversationId) -> Option<TunnelAction> {
        let peer = self.by_id.remove(&id)?;
        self.by_peer.remove(&peer);
        Some(TunnelAction::ConversationClosed(id))
    }
}

/// Minimal server engine that demonstrates `(session, conversation)` isolation.
pub struct ServerEngine {
    config: EngineConfig,
    conversations: HashSet<(SessionId, ConversationId)>,
    next_packet_number: HashMap<SessionId, u64>,
}

impl ServerEngine {
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        config.validate()?;
        if config.role != Role::Server {
            return Err(EngineError::InvalidRole);
        }
        Ok(Self {
            config,
            conversations: HashSet::new(),
            next_packet_number: HashMap::new(),
        })
    }

    pub fn handle(&mut self, event: TunnelEvent) -> Result<Vec<TunnelAction>, EngineError> {
        match event {
            TunnelEvent::TunnelFrame(bytes) => {
                let frame = WireFrame::decode(&bytes)?;
                if frame.frame_type != FrameType::Data {
                    return Ok(Vec::new());
                }
                let id = frame
                    .conversation_id
                    .ok_or(EngineError::UnknownConversation)?;
                let key = (frame.session_id, id);
                let mut actions = Vec::with_capacity(2);
                if !self.conversations.contains(&key) {
                    let session_count = self
                        .conversations
                        .iter()
                        .filter(|(session, _)| *session == frame.session_id)
                        .count();
                    if session_count >= self.config.max_conversations {
                        return Err(EngineError::ConversationCapacity);
                    }
                    self.conversations.insert(key);
                    actions.push(TunnelAction::ConversationOpened(id));
                }
                actions.push(TunnelAction::DeliverToUpstream {
                    session_id: frame.session_id,
                    conversation_id: id,
                    payload: frame.payload,
                });
                Ok(actions)
            }
            TunnelEvent::ServerDatagram {
                session_id,
                conversation_id,
                payload,
            } => {
                if payload.len() > self.config.max_frame_payload {
                    return Err(EngineError::PayloadTooLarge);
                }
                if !self.conversations.contains(&(session_id, conversation_id)) {
                    return Err(EngineError::UnknownConversation);
                }
                let packet_number = self.next_packet_number.entry(session_id).or_default();
                let current = *packet_number;
                *packet_number = packet_number
                    .checked_add(1)
                    .ok_or(EngineError::PacketNumberExhausted)?;
                let frame = WireFrame {
                    session_id,
                    packet_number: current,
                    epoch: 0,
                    frame_type: FrameType::Data,
                    conversation_id: Some(conversation_id),
                    payload,
                };
                Ok(vec![TunnelAction::SendTunnelFrame(frame.encode()?)])
            }
            TunnelEvent::CloseConversation(id) => {
                self.conversations.retain(|(_, existing)| *existing != id);
                Ok(vec![TunnelAction::ConversationClosed(id)])
            }
            TunnelEvent::TimeAdvanced(_) => Ok(Vec::new()),
            TunnelEvent::ClientDatagram { .. } => Err(EngineError::InvalidRole),
        }
    }
}
