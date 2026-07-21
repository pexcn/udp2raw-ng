use std::fmt;

use zeroize::Zeroizing;

use crate::ConfigError;

const MIN_PSK_LENGTH: usize = 32;
const MAX_PSK_LENGTH: usize = 1024;

/// Owned pre-shared key material that is zeroized when dropped.
pub struct Psk(Zeroizing<Vec<u8>>);

impl Psk {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ConfigError> {
        let bytes = bytes.into();
        if bytes.len() < MIN_PSK_LENGTH {
            return Err(ConfigError::PskTooShort {
                minimum: MIN_PSK_LENGTH,
                actual: bytes.len(),
            });
        }
        if bytes.len() > MAX_PSK_LENGTH {
            return Err(ConfigError::PskTooLong {
                maximum: MAX_PSK_LENGTH,
            });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exposes key bytes only within this crate when deriving protocol keys.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Psk")
            .field("length", &self.len())
            .field("material", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Psk;

    #[test]
    fn debug_output_redacts_secret() {
        let psk = Psk::new(vec![b'x'; 32]).expect("valid key");
        let output = format!("{psk:?}");
        assert!(output.contains("REDACTED"));
        assert!(!output.contains("xxxxxxxx"));
        assert_eq!(psk.as_bytes().len(), 32);
    }
}
