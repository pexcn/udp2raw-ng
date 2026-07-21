use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("replay window size must be greater than zero")]
    ZeroReplayWindow,
    #[error("conversation limit must be greater than zero")]
    ZeroConversationLimit,
    #[error("conversation idle timeout must be greater than zero")]
    ZeroConversationIdleTimeout,
    #[error("frame payload limit {value} is outside 1..={maximum}")]
    InvalidFramePayloadLimit { value: usize, maximum: usize },
    #[error("unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(String),
    #[error("PSK must contain at least {minimum} bytes; got {actual}")]
    PskTooShort { minimum: usize, actual: usize },
    #[error("PSK exceeds the {maximum}-byte limit")]
    PskTooLong { maximum: usize },
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    #[error("frame is truncated")]
    Truncated,
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("unknown frame type {0}")]
    UnknownFrameType(u8),
    #[error("reserved frame flags are non-zero")]
    ReservedFlags,
    #[error("declared payload length is invalid")]
    InvalidPayloadLength,
    #[error("payload exceeds the configured protocol limit")]
    PayloadTooLarge,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReplayError {
    #[error("packet number has already been accepted")]
    Duplicate,
    #[error("packet number is older than the replay window")]
    TooOld,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("this event is not valid for the engine role")]
    InvalidRole,
    #[error("conversation capacity has been reached")]
    ConversationCapacity,
    #[error("unknown conversation")]
    UnknownConversation,
    #[error("local payload exceeds the configured maximum")]
    PayloadTooLarge,
    #[error("packet number space exhausted; a new session is required")]
    PacketNumberExhausted,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}
