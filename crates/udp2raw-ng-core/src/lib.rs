//! Platform-independent, synchronous protocol building blocks for `udp2raw-ng`.
//!
//! This crate intentionally performs no network I/O. It provides a PSK-
//! authenticated handshake and protected record layer that can be driven by an
//! embedding host or a pure in-memory transport.

mod config;
mod crypto;
mod engine;
mod error;
mod handshake;
mod id;
mod protocol;
mod record;
mod replay;
mod secret;

pub use config::{CipherSuite, EngineConfig, Role};
pub use engine::{ClientEngine, ServerEngine, SessionState, TunnelAction, TunnelEvent};
pub use error::{
    ConfigError, CryptoError, EngineError, FrameError, HandshakeError, RecordError, ReplayError,
};
pub use id::{ConversationId, PeerId, SessionId};
pub use protocol::{FrameType, MAX_FRAME_PAYLOAD, PROTOCOL_VERSION, WireFrame};
pub use replay::ReplayWindow;
pub use secret::Psk;
