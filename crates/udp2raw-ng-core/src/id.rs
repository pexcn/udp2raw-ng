use std::fmt;
use std::num::NonZeroU64;

use crate::EngineError;

/// Host-assigned transport route identifier. It is routing metadata, not an
/// authenticated identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId(u64);

impl PeerId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Random identifier scoped to an authenticated session.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConversationId(NonZeroU64);

impl ConversationId {
    pub fn generate() -> Result<Self, EngineError> {
        loop {
            let mut bytes = [0_u8; 8];
            getrandom::getrandom(&mut bytes).map_err(|_| EngineError::RandomnessUnavailable)?;
            if let Some(value) = NonZeroU64::new(u64::from_be_bytes(bytes)) {
                return Ok(Self(value));
            }
        }
    }

    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConversationId({:#018x})", self.get())
    }
}

/// Random logical session identifier. It is routing metadata, not a secret.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(u128);

impl SessionId {
    pub fn generate() -> Result<Self, EngineError> {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| EngineError::RandomnessUnavailable)?;
        Ok(Self(u128::from_be_bytes(bytes)))
    }

    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    pub const fn as_u128(self) -> u128 {
        self.0
    }

    pub const fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({:#034x})", self.0)
    }
}
