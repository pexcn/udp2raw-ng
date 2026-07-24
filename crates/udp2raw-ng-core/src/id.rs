use std::fmt;
use std::num::NonZeroU32;

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

/// Random stable logical conversation identifier exposed to embedding hosts.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConversationId(NonZeroU32);

impl ConversationId {
    pub fn generate() -> Result<Self, EngineError> {
        loop {
            let mut bytes = [0_u8; 4];
            getrandom::getrandom(&mut bytes).map_err(|_| EngineError::RandomnessUnavailable)?;
            if let Some(value) = NonZeroU32::new(u32::from_be_bytes(bytes)) {
                return Ok(Self(value));
            }
        }
    }

    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Debug for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConversationId({:#010x})", self.get())
    }
}

/// Non-zero conversation routing handle scoped to one authenticated session.
///
/// This value is the only conversation identifier written to a v4 envelope.
/// It must never be exposed as a stable host-facing conversation identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConversationHandle(NonZeroU32);

impl ConversationHandle {
    pub const fn new(value: NonZeroU32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Random logical session identifier. It is routing metadata, not a secret.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(u64);

impl SessionId {
    pub fn generate() -> Result<Self, EngineError> {
        let mut bytes = [0_u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|_| EngineError::RandomnessUnavailable)?;
        Ok(Self(u64::from_be_bytes(bytes)))
    }

    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({:#018x})", self.0)
    }
}
