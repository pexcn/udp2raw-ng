use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{CipherSuite, CryptoError, Psk, SessionId};

const PROTOCOL_DOMAIN: &[u8] = b"udp2raw-ng/v4";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    pub(crate) const fn label(self) -> &'static [u8] {
        match self {
            Self::ClientToServer => b"client-to-server",
            Self::ServerToClient => b"server-to-client",
        }
    }

    pub(crate) const fn wire_id(self) -> u8 {
        match self {
            Self::ClientToServer => 1,
            Self::ServerToClient => 2,
        }
    }
}

pub(crate) struct DirectionKeys {
    pub(crate) record_key: Zeroizing<Vec<u8>>,
    pub(crate) nonce_prefix: Zeroizing<Vec<u8>>,
}

pub(crate) struct SessionKeys {
    pub(crate) client_to_server: DirectionKeys,
    pub(crate) server_to_client: DirectionKeys,
}

pub(crate) fn handshake_tag(
    psk: &Psk,
    handshake_id: &[u8; 16],
    client_nonce: &[u8; 32],
    transcript: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let key = handshake_key(psk, handshake_id, client_nonce)?;
    hmac_tag(key.as_ref(), transcript)
}

fn handshake_key(
    psk: &Psk,
    handshake_id: &[u8; 16],
    client_nonce: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(client_nonce), psk.as_bytes());
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut info = Vec::with_capacity(PROTOCOL_DOMAIN.len() + 32);
    info.extend_from_slice(PROTOCOL_DOMAIN);
    info.extend_from_slice(b"/handshake-auth/");
    info.extend_from_slice(handshake_id);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

pub(crate) fn verify_handshake_tag(
    psk: &Psk,
    handshake_id: &[u8; 16],
    client_nonce: &[u8; 32],
    transcript: &[u8],
    tag: &[u8; 32],
) -> Result<(), CryptoError> {
    let key = handshake_key(psk, handshake_id, client_nonce)?;
    let mut mac =
        HmacSha256::new_from_slice(key.as_ref()).map_err(|_| CryptoError::KeyDerivationFailed)?;
    mac.update(transcript);
    mac.verify_slice(tag)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub(crate) fn derive_session_keys(
    psk: &Psk,
    suite: CipherSuite,
    session_id: SessionId,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    session_salt: &[u8; 32],
    transcript: &[u8],
) -> Result<SessionKeys, CryptoError> {
    let transcript_hash = Sha256::digest(transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(session_salt), psk.as_bytes());
    let derive = |direction: Direction| -> Result<DirectionKeys, CryptoError> {
        let key_len = match suite {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::ChaCha20Poly1305
            | CipherSuite::XChaCha20Poly1305
            | CipherSuite::Aes256Gcm
            | CipherSuite::NoneAuthenticated => 32,
        };
        let nonce_len = match suite {
            CipherSuite::XChaCha20Poly1305 => 16,
            CipherSuite::NoneAuthenticated => 0,
            _ => 4,
        };
        let mut common = Vec::with_capacity(160);
        common.extend_from_slice(PROTOCOL_DOMAIN);
        common.extend_from_slice(b"/session/");
        common.extend_from_slice(&session_id.to_be_bytes());
        common.push(suite.wire_id());
        common.extend_from_slice(client_nonce);
        common.extend_from_slice(server_nonce);
        common.extend_from_slice(transcript_hash.as_slice());
        common.push(b'/');
        common.extend_from_slice(direction.label());

        let mut record_key = Zeroizing::new(vec![0_u8; key_len]);
        let mut key_info = common.clone();
        key_info.extend_from_slice(b"/record-key");
        hkdf.expand(&key_info, record_key.as_mut_slice())
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let mut nonce_prefix = Zeroizing::new(vec![0_u8; nonce_len]);
        if nonce_len != 0 {
            let mut nonce_info = common;
            nonce_info.extend_from_slice(b"/nonce-prefix");
            hkdf.expand(&nonce_info, nonce_prefix.as_mut_slice())
                .map_err(|_| CryptoError::KeyDerivationFailed)?;
        }
        Ok(DirectionKeys {
            record_key,
            nonce_prefix,
        })
    };

    Ok(SessionKeys {
        client_to_server: derive(Direction::ClientToServer)?,
        server_to_client: derive(Direction::ServerToClient)?,
    })
}

pub(crate) fn hmac_tag(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn verify_hmac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    mac.update(data);
    mac.verify_slice(tag)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::{Direction, derive_session_keys};
    use crate::{CipherSuite, Psk, SessionId};

    #[test]
    fn direction_and_purpose_keys_are_separated() {
        let psk = Psk::new(vec![7; 32]).expect("psk");
        let keys = derive_session_keys(
            &psk,
            CipherSuite::ChaCha20Poly1305,
            SessionId::from_u64(9),
            &[1; 32],
            &[2; 32],
            &[3; 32],
            b"transcript",
        )
        .expect("derive");
        assert_ne!(
            keys.client_to_server.record_key.as_slice(),
            keys.server_to_client.record_key.as_slice()
        );
        assert_ne!(
            keys.client_to_server.record_key.as_slice(),
            keys.client_to_server.nonce_prefix.as_slice()
        );
        assert_ne!(
            Direction::ClientToServer.wire_id(),
            Direction::ServerToClient.wire_id()
        );
    }
}
