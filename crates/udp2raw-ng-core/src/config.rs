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
        }
    }
}
