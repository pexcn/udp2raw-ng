use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("replay window size must be greater than zero")]
    ZeroReplayWindow,
    #[error("conversation limit must be greater than zero")]
    ZeroConversationLimit,
    #[error("conversation idle timeout must be greater than zero")]
    ZeroConversationIdleTimeout,
    #[error("heartbeat interval must be greater than zero")]
    ZeroHeartbeatInterval,
    #[error("session timeout must be greater than zero")]
    ZeroSessionTimeout,
    #[error("heartbeat interval must be shorter than the session timeout")]
    HeartbeatNotBelowSessionTimeout,
    #[error("server session idle timeout must be greater than zero")]
    ZeroSessionIdleTimeout,
    #[error("handshake timeout must be greater than zero")]
    ZeroHandshakeTimeout,
    #[error("handshake retry interval must be greater than zero")]
    ZeroHandshakeRetryInterval,
    #[error("handshake retry interval must not exceed the handshake timeout")]
    HandshakeRetryExceedsTimeout,
    #[error("handshake attempt limit must be greater than zero")]
    ZeroHandshakeAttemptLimit,
    #[error("reconnect queue capacity must be greater than zero")]
    ZeroReconnectQueueCapacity,
    #[error("reconnect queue timeout must be greater than zero")]
    ZeroReconnectQueueTimeout,
    #[error("handshake rate-limit burst must be greater than zero")]
    ZeroHandshakeRateLimitBurst,
    #[error("handshake rate-limit refill interval must be greater than zero")]
    ZeroHandshakeRateRefillInterval,
    #[error("handshake cookie lifetime must be greater than zero")]
    ZeroHandshakeCookieLifetime,
    #[error("session resumption lifetime must be greater than zero")]
    ZeroResumptionLifetime,
    #[error("pending handshake limit must be greater than zero")]
    ZeroPendingHandshakeLimit,
    #[error("per-peer pending handshake limit must be greater than zero")]
    ZeroPerPeerPendingHandshakeLimit,
    #[error("session limit must be greater than zero")]
    ZeroSessionLimit,
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
    #[error("frame fields are invalid for its type")]
    InvalidFrameFields,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReplayError {
    #[error("packet number has already been accepted")]
    Duplicate,
    #[error("packet number is older than the replay window")]
    TooOld,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("message authentication failed")]
    AuthenticationFailed,
    #[error("key derivation failed")]
    KeyDerivationFailed,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum HandshakeError {
    #[error("unexpected handshake message")]
    UnexpectedMessage,
    #[error("malformed handshake message")]
    Malformed,
    #[error("handshake identifier does not match")]
    HandshakeIdMismatch,
    #[error("handshake selected a different cipher suite")]
    CipherSuiteMismatch,
    #[error("handshake transcript authentication failed")]
    AuthenticationFailed,
    #[error("handshake cookie is invalid or expired")]
    InvalidCookie,
    #[error("session resumption credential is invalid or expired")]
    InvalidResumptionCredential,
    #[error("no matching pending handshake")]
    UnknownPendingHandshake,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RecordError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error("record belongs to another session")]
    SessionMismatch,
    #[error("record epoch is unsupported")]
    UnsupportedEpoch,
    #[error("record type is not protected application data")]
    InvalidRecordType,
    #[error("record authentication tag is truncated")]
    TruncatedTag,
    #[error("packet number space exhausted; a new session is required")]
    PacketNumberExhausted,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("this event is not valid for the engine role")]
    InvalidRole,
    #[error("conversation capacity has been reached")]
    ConversationCapacity,
    #[error("pending handshake capacity has been reached")]
    PendingHandshakeCapacity,
    #[error("per-peer pending handshake capacity has been reached")]
    PerPeerPendingHandshakeCapacity,
    #[error("unauthenticated handshake rate limit has been reached for this peer")]
    HandshakeRateLimited,
    #[error("authenticated session capacity has been reached")]
    SessionCapacity,
    #[error("unknown conversation")]
    UnknownConversation,
    #[error("local payload exceeds the configured maximum")]
    PayloadTooLarge,
    #[error("packet number space exhausted; a new session is required")]
    PacketNumberExhausted,
    #[error("session is not ready for application data")]
    SessionNotReady,
    #[error("unknown authenticated session")]
    UnknownSession,
    #[error("frame arrived from an unexpected transport peer")]
    UnexpectedPeer,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}
