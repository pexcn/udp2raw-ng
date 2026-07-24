use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::crypto::{Direction, DirectionKeys, hmac_tag, verify_hmac};
use crate::{
    CipherSuite, ConversationHandle, CryptoError, FrameType, RecordError, ReplayWindow, SessionId,
    WireFrame,
};

const AEAD_TAG_LENGTH: usize = 16;
const HMAC_TAG_LENGTH: usize = 32;

pub(crate) struct AuthenticatedFrame {
    pub(crate) frame_type: FrameType,
    pub(crate) conversation_handle: Option<ConversationHandle>,
    pub(crate) plaintext: Vec<u8>,
}

pub(crate) struct RecordSealer {
    suite: CipherSuite,
    direction: Direction,
    session_id: SessionId,
    next_packet_number: u64,
    keys: DirectionKeys,
}

pub(crate) struct RecordOpener {
    suite: CipherSuite,
    direction: Direction,
    session_id: SessionId,
    keys: DirectionKeys,
    replay: ReplayWindow,
}

impl RecordSealer {
    pub(crate) fn new(
        suite: CipherSuite,
        direction: Direction,
        session_id: SessionId,
        keys: DirectionKeys,
    ) -> Self {
        Self {
            suite,
            direction,
            session_id,
            next_packet_number: 0,
            keys,
        }
    }

    pub(crate) fn seal(
        &mut self,
        frame_type: FrameType,
        conversation_handle: Option<ConversationHandle>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        if !frame_type.is_protected() {
            return Err(RecordError::InvalidRecordType);
        }
        let packet_number = self.next_packet_number;
        let next = packet_number
            .checked_add(1)
            .ok_or(RecordError::PacketNumberExhausted)?;
        let tag_length = self.tag_length();
        let mut frame = WireFrame {
            session_id: self.session_id,
            packet_number,
            epoch: 0,
            frame_type,
            conversation_handle,
            payload: Vec::new(),
        };
        plaintext
            .len()
            .checked_add(tag_length)
            .ok_or(crate::FrameError::PayloadTooLarge)?;
        let aad = self.aad(&frame)?;
        let mut body = plaintext.to_vec();
        match self.suite {
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = self.nonce_12(packet_number)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut body)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                body.extend_from_slice(&tag);
            }
            CipherSuite::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = self.nonce_24(packet_number)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut body)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                body.extend_from_slice(&tag);
            }
            CipherSuite::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = self.nonce_12(packet_number)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut body)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                body.extend_from_slice(&tag);
            }
            CipherSuite::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = self.nonce_12(packet_number)?;
                let tag = cipher
                    .encrypt_in_place_detached((&nonce).into(), &aad, &mut body)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                body.extend_from_slice(&tag);
            }
            CipherSuite::NoneAuthenticated => {
                let mut authenticated = aad;
                authenticated.extend_from_slice(&body);
                body.extend_from_slice(&hmac_tag(&self.keys.record_key, &authenticated)?);
            }
        }
        frame.payload = body;
        let encoded = frame.encode()?;
        self.next_packet_number = next;
        Ok(encoded)
    }

    fn tag_length(&self) -> usize {
        match self.suite {
            CipherSuite::NoneAuthenticated => HMAC_TAG_LENGTH,
            _ => AEAD_TAG_LENGTH,
        }
    }

    fn aad(&self, frame: &WireFrame) -> Result<Vec<u8>, crate::FrameError> {
        let mut aad = Vec::with_capacity(crate::protocol::HEADER_LENGTH + 2);
        aad.extend_from_slice(&frame.encoded_header()?);
        aad.push(self.direction.wire_id());
        aad.push(self.suite.wire_id());
        Ok(aad)
    }

    fn nonce_12(&self, packet_number: u64) -> Result<[u8; 12], CryptoError> {
        if self.keys.nonce_prefix.len() != 4 {
            return Err(CryptoError::KeyDerivationFailed);
        }
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&self.keys.nonce_prefix);
        nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
        Ok(nonce)
    }

    fn nonce_24(&self, packet_number: u64) -> Result<[u8; 24], CryptoError> {
        if self.keys.nonce_prefix.len() != 16 {
            return Err(CryptoError::KeyDerivationFailed);
        }
        let mut nonce = [0_u8; 24];
        nonce[..16].copy_from_slice(&self.keys.nonce_prefix);
        nonce[16..].copy_from_slice(&packet_number.to_be_bytes());
        Ok(nonce)
    }
}

impl RecordOpener {
    pub(crate) fn new(
        suite: CipherSuite,
        direction: Direction,
        session_id: SessionId,
        keys: DirectionKeys,
        replay_window_size: usize,
    ) -> Self {
        Self {
            suite,
            direction,
            session_id,
            keys,
            replay: ReplayWindow::new(replay_window_size),
        }
    }

    pub(crate) fn open(&mut self, bytes: &[u8]) -> Result<AuthenticatedFrame, RecordError> {
        let frame = WireFrame::decode(bytes)?;
        if frame.session_id != self.session_id {
            return Err(RecordError::SessionMismatch);
        }
        if frame.epoch != 0 {
            return Err(RecordError::UnsupportedEpoch);
        }
        if !frame.frame_type.is_protected() {
            return Err(RecordError::InvalidRecordType);
        }
        let tag_length = match self.suite {
            CipherSuite::NoneAuthenticated => HMAC_TAG_LENGTH,
            _ => AEAD_TAG_LENGTH,
        };
        if frame.payload.len() < tag_length {
            return Err(RecordError::TruncatedTag);
        }
        let mut aad = Vec::with_capacity(crate::protocol::HEADER_LENGTH + 2);
        aad.extend_from_slice(&frame.encoded_header()?);
        aad.push(self.direction.wire_id());
        aad.push(self.suite.wire_id());

        let split = frame.payload.len() - tag_length;
        let mut plaintext = frame.payload[..split].to_vec();
        let tag = &frame.payload[split..];
        match self.suite {
            CipherSuite::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = nonce_12(&self.keys, frame.packet_number)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), &aad, &mut plaintext, tag.into())
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
            }
            CipherSuite::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = nonce_24(&self.keys, frame.packet_number)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), &aad, &mut plaintext, tag.into())
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
            }
            CipherSuite::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = nonce_12(&self.keys, frame.packet_number)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), &aad, &mut plaintext, tag.into())
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
            }
            CipherSuite::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.keys.record_key)
                    .map_err(|_| CryptoError::KeyDerivationFailed)?;
                let nonce = nonce_12(&self.keys, frame.packet_number)?;
                cipher
                    .decrypt_in_place_detached((&nonce).into(), &aad, &mut plaintext, tag.into())
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
            }
            CipherSuite::NoneAuthenticated => {
                let mut authenticated = aad;
                authenticated.extend_from_slice(&plaintext);
                verify_hmac(&self.keys.record_key, &authenticated, tag)?;
            }
        }

        if plaintext.len() > crate::MAX_FRAME_PAYLOAD {
            return Err(crate::FrameError::PayloadTooLarge.into());
        }

        // Authentication always precedes replay mutation and plaintext delivery.
        self.replay.accept(frame.packet_number)?;
        Ok(AuthenticatedFrame {
            frame_type: frame.frame_type,
            conversation_handle: frame.conversation_handle,
            plaintext,
        })
    }
}

fn nonce_12(keys: &DirectionKeys, packet_number: u64) -> Result<[u8; 12], CryptoError> {
    if keys.nonce_prefix.len() != 4 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&keys.nonce_prefix);
    nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
    Ok(nonce)
}

fn nonce_24(keys: &DirectionKeys, packet_number: u64) -> Result<[u8; 24], CryptoError> {
    if keys.nonce_prefix.len() != 16 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(&keys.nonce_prefix);
    nonce[16..].copy_from_slice(&packet_number.to_be_bytes());
    Ok(nonce)
}
