//! Platform-independent, synchronous protocol building blocks for `udp2raw-ng`.
//!
//! This crate intentionally performs no network I/O. The current milestone is a
//! scaffold: wire frames are versioned and bounded, but are **not yet encrypted
//! or authenticated** and must not be used on an untrusted network.

mod config;
mod engine;
mod error;
mod id;
mod protocol;
mod replay;
mod secret;

pub use config::{CipherSuite, EngineConfig, Role};
pub use engine::{ClientEngine, ServerEngine, TunnelAction, TunnelEvent};
pub use error::{ConfigError, EngineError, FrameError, ReplayError};
pub use id::{ConversationId, SessionId};
pub use protocol::{FrameType, MAX_FRAME_PAYLOAD, PROTOCOL_VERSION, WireFrame};
pub use replay::ReplayWindow;
pub use secret::Psk;
