use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use crate::ConfigError;

/// Protocol endpoint role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

/// Configured cryptographic suite.
///
/// Implementations are scheduled for the next milestone. `NoneAuthenticated`
/// means plaintext plus a strong MAC; it never means unauthenticated traffic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CipherSuite {
    #[default]
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
    NoneAuthenticated,
}

impl CipherSuite {
    pub(crate) const fn wire_id(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 1,
            Self::XChaCha20Poly1305 => 2,
            Self::Aes128Gcm => 3,
            Self::Aes256Gcm => 4,
            Self::NoneAuthenticated => 5,
        }
    }

    pub(crate) fn from_wire_id(value: u8) -> Result<Self, ConfigError> {
        match value {
            1 => Ok(Self::ChaCha20Poly1305),
            2 => Ok(Self::XChaCha20Poly1305),
            3 => Ok(Self::Aes128Gcm),
            4 => Ok(Self::Aes256Gcm),
            5 => Ok(Self::NoneAuthenticated),
            _ => Err(ConfigError::UnsupportedCipherSuite(format!(
                "wire id {value}"
            ))),
        }
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ChaCha20Poly1305 => "chacha20poly1305",
            Self::XChaCha20Poly1305 => "xchacha20poly1305",
            Self::Aes128Gcm => "aes128gcm",
            Self::Aes256Gcm => "aes256gcm",
            Self::NoneAuthenticated => "none",
        })
    }
}

impl FromStr for CipherSuite {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "chacha20poly1305" => Ok(Self::ChaCha20Poly1305),
            "xchacha20poly1305" => Ok(Self::XChaCha20Poly1305),
            "aes128gcm" => Ok(Self::Aes128Gcm),
            "aes256gcm" => Ok(Self::Aes256Gcm),
            "none" => Ok(Self::NoneAuthenticated),
            _ => Err(ConfigError::UnsupportedCipherSuite(value.to_owned())),
        }
    }
}

/// Resource and timer limits for a protocol engine.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub role: Role,
    pub cipher_suite: CipherSuite,
    pub replay_window_size: usize,
    pub max_conversations: usize,
    pub max_frame_payload: usize,
    pub conversation_idle_timeout: Duration,
    pub handshake_retry_interval: Duration,
    pub handshake_timeout: Duration,
    pub handshake_max_attempts: usize,
    pub require_handshake_cookie: bool,
    pub handshake_cookie_lifetime: Duration,
    pub max_pending_handshakes: usize,
    pub max_pending_handshakes_per_peer: usize,
    pub max_sessions: usize,
}

impl EngineConfig {
    pub fn client() -> Self {
        Self {
            role: Role::Client,
            ..Self::default()
        }
    }

    pub fn server() -> Self {
        Self {
            role: Role::Server,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.replay_window_size == 0 {
            return Err(ConfigError::ZeroReplayWindow);
        }
        if self.max_conversations == 0 {
            return Err(ConfigError::ZeroConversationLimit);
        }
        if !(1..=crate::MAX_FRAME_PAYLOAD).contains(&self.max_frame_payload) {
            return Err(ConfigError::InvalidFramePayloadLimit {
                value: self.max_frame_payload,
                maximum: crate::MAX_FRAME_PAYLOAD,
            });
        }
        if self.conversation_idle_timeout.is_zero() {
            return Err(ConfigError::ZeroConversationIdleTimeout);
        }
        if self.handshake_retry_interval.is_zero() {
            return Err(ConfigError::ZeroHandshakeRetryInterval);
        }
        if self.handshake_timeout.is_zero() {
            return Err(ConfigError::ZeroHandshakeTimeout);
        }
        if self.handshake_retry_interval > self.handshake_timeout {
            return Err(ConfigError::HandshakeRetryExceedsTimeout);
        }
        if self.handshake_max_attempts == 0 {
            return Err(ConfigError::ZeroHandshakeAttemptLimit);
        }
        if self.handshake_cookie_lifetime.is_zero() {
            return Err(ConfigError::ZeroHandshakeCookieLifetime);
        }
        if self.max_pending_handshakes == 0 {
            return Err(ConfigError::ZeroPendingHandshakeLimit);
        }
        if self.max_pending_handshakes_per_peer == 0 {
            return Err(ConfigError::ZeroPerPeerPendingHandshakeLimit);
        }
        if self.max_sessions == 0 {
            return Err(ConfigError::ZeroSessionLimit);
        }
        Ok(())
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            role: Role::Client,
            cipher_suite: CipherSuite::default(),
            replay_window_size: 4096,
            max_conversations: 1024,
            max_frame_payload: crate::MAX_FRAME_PAYLOAD,
            conversation_idle_timeout: Duration::from_secs(180),
            handshake_retry_interval: Duration::from_millis(500),
            handshake_timeout: Duration::from_secs(10),
            handshake_max_attempts: 8,
            require_handshake_cookie: true,
            handshake_cookie_lifetime: Duration::from_secs(30),
            max_pending_handshakes: 1024,
            max_pending_handshakes_per_peer: 64,
            max_sessions: 4096,
        }
    }
}
