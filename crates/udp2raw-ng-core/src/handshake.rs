use crate::crypto::{
    SessionKeys, derive_session_keys, handshake_tag, hmac_tag, verify_handshake_tag, verify_hmac,
};
use std::time::Duration;

use crate::{
    CipherSuite, CryptoError, FrameType, HandshakeError, PeerId, Psk, SessionId, WireFrame,
};

const CLIENT_HELLO_BASE_LENGTH: usize = 50;
const CLIENT_HELLO_COOKIE_LENGTH: usize = CLIENT_HELLO_BASE_LENGTH + 40;
const HELLO_RETRY_UNSIGNED_LENGTH: usize = 89;
const HELLO_RETRY_LENGTH: usize = HELLO_RETRY_UNSIGNED_LENGTH + 32;
const SERVER_HELLO_UNSIGNED_LENGTH: usize = 113;
const SERVER_HELLO_LENGTH: usize = SERVER_HELLO_UNSIGNED_LENGTH + 32;
const CLIENT_FINISH_LENGTH: usize = 48;

#[derive(Clone)]
pub(crate) struct ClientHello {
    pub(crate) handshake_id: [u8; 16],
    pub(crate) client_nonce: [u8; 32],
    pub(crate) suite: CipherSuite,
    pub(crate) cookie: Option<HandshakeCookie>,
}

#[derive(Clone, Copy)]
pub(crate) struct HandshakeCookie {
    issued_at_ms: u64,
    tag: [u8; 32],
}

pub(crate) struct HelloRetry {
    handshake_id: [u8; 16],
    client_nonce: [u8; 32],
    suite: CipherSuite,
    cookie: HandshakeCookie,
    auth_tag: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct ServerHello {
    pub(crate) handshake_id: [u8; 16],
    pub(crate) client_nonce: [u8; 32],
    pub(crate) server_nonce: [u8; 32],
    pub(crate) session_salt: [u8; 32],
    pub(crate) suite: CipherSuite,
    pub(crate) auth_tag: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct ClientFinish {
    pub(crate) handshake_id: [u8; 16],
    pub(crate) auth_tag: [u8; 32],
}

impl ClientHello {
    pub(crate) fn generate(suite: CipherSuite) -> Result<Self, crate::EngineError> {
        let mut handshake_id = [0_u8; 16];
        let mut client_nonce = [0_u8; 32];
        getrandom::getrandom(&mut handshake_id)
            .map_err(|_| crate::EngineError::RandomnessUnavailable)?;
        getrandom::getrandom(&mut client_nonce)
            .map_err(|_| crate::EngineError::RandomnessUnavailable)?;
        Ok(Self {
            handshake_id,
            client_nonce,
            suite,
            cookie: None,
        })
    }

    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(if self.cookie.is_some() {
            CLIENT_HELLO_COOKIE_LENGTH
        } else {
            CLIENT_HELLO_BASE_LENGTH
        });
        payload.extend_from_slice(&self.handshake_id);
        payload.extend_from_slice(&self.client_nonce);
        payload.push(self.suite.wire_id());
        if let Some(cookie) = self.cookie {
            payload.push(1);
            payload.extend_from_slice(&cookie.issued_at_ms.to_be_bytes());
            payload.extend_from_slice(&cookie.tag);
        } else {
            payload.push(0);
        }
        payload
    }

    pub(crate) fn decode(frame: &WireFrame) -> Result<Self, HandshakeError> {
        if frame.frame_type != FrameType::ClientHello
            || frame.session_id != SessionId::from_u128(0)
            || frame.packet_number != 0
            || frame.epoch != 0
            || !matches!(
                frame.payload.len(),
                CLIENT_HELLO_BASE_LENGTH | CLIENT_HELLO_COOKIE_LENGTH
            )
        {
            return Err(HandshakeError::Malformed);
        }
        let suite =
            CipherSuite::from_wire_id(frame.payload[48]).map_err(|_| HandshakeError::Malformed)?;
        let cookie = match frame.payload[49] {
            0 if frame.payload.len() == CLIENT_HELLO_BASE_LENGTH => None,
            1 if frame.payload.len() == CLIENT_HELLO_COOKIE_LENGTH => Some(HandshakeCookie {
                issued_at_ms: u64::from_be_bytes(
                    frame.payload[50..58].try_into().expect("fixed slice"),
                ),
                tag: frame.payload[58..90].try_into().expect("fixed slice"),
            }),
            _ => return Err(HandshakeError::Malformed),
        };
        Ok(Self {
            handshake_id: frame.payload[..16].try_into().expect("fixed slice"),
            client_nonce: frame.payload[16..48].try_into().expect("fixed slice"),
            suite,
            cookie,
        })
    }

    pub(crate) fn frame(&self) -> WireFrame {
        WireFrame {
            session_id: SessionId::from_u128(0),
            packet_number: 0,
            epoch: 0,
            frame_type: FrameType::ClientHello,
            conversation_id: None,
            payload: self.encode_payload(),
        }
    }
}

impl HelloRetry {
    pub(crate) fn create(
        psk: &Psk,
        cookie_secret: &[u8],
        client_hello: &ClientHello,
        peer_id: PeerId,
        issued_at_ms: u64,
    ) -> Result<Self, CryptoError> {
        let cookie = HandshakeCookie {
            issued_at_ms,
            tag: cookie_tag(cookie_secret, client_hello, peer_id, issued_at_ms)?,
        };
        let mut retry = Self {
            handshake_id: client_hello.handshake_id,
            client_nonce: client_hello.client_nonce,
            suite: client_hello.suite,
            cookie,
            auth_tag: [0; 32],
        };
        retry.auth_tag = handshake_tag(
            psk,
            &retry.handshake_id,
            &retry.client_nonce,
            &retry_auth_transcript(&retry),
        )?;
        Ok(retry)
    }

    pub(crate) fn decode(frame: &WireFrame) -> Result<Self, HandshakeError> {
        if frame.frame_type != FrameType::HelloRetry
            || frame.session_id != SessionId::from_u128(0)
            || frame.packet_number != 0
            || frame.epoch != 0
            || frame.payload.len() != HELLO_RETRY_LENGTH
        {
            return Err(HandshakeError::Malformed);
        }
        let suite =
            CipherSuite::from_wire_id(frame.payload[48]).map_err(|_| HandshakeError::Malformed)?;
        Ok(Self {
            handshake_id: frame.payload[..16].try_into().expect("fixed slice"),
            client_nonce: frame.payload[16..48].try_into().expect("fixed slice"),
            suite,
            cookie: HandshakeCookie {
                issued_at_ms: u64::from_be_bytes(
                    frame.payload[49..57].try_into().expect("fixed slice"),
                ),
                tag: frame.payload[57..89].try_into().expect("fixed slice"),
            },
            auth_tag: frame.payload[89..121].try_into().expect("fixed slice"),
        })
    }

    pub(crate) fn verify_and_apply(
        &self,
        psk: &Psk,
        client_hello: &ClientHello,
    ) -> Result<ClientHello, HandshakeError> {
        if self.handshake_id != client_hello.handshake_id
            || self.client_nonce != client_hello.client_nonce
        {
            return Err(HandshakeError::HandshakeIdMismatch);
        }
        if self.suite != client_hello.suite {
            return Err(HandshakeError::CipherSuiteMismatch);
        }
        verify_handshake_tag(
            psk,
            &self.handshake_id,
            &self.client_nonce,
            &retry_auth_transcript(self),
            &self.auth_tag,
        )
        .map_err(|_| HandshakeError::AuthenticationFailed)?;
        let mut hello = client_hello.clone();
        hello.cookie = Some(self.cookie);
        Ok(hello)
    }

    pub(crate) fn frame(&self) -> WireFrame {
        let mut payload = self.encode_unsigned_payload();
        payload.extend_from_slice(&self.auth_tag);
        WireFrame {
            session_id: SessionId::from_u128(0),
            packet_number: 0,
            epoch: 0,
            frame_type: FrameType::HelloRetry,
            conversation_id: None,
            payload,
        }
    }

    fn encode_unsigned_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(HELLO_RETRY_UNSIGNED_LENGTH);
        payload.extend_from_slice(&self.handshake_id);
        payload.extend_from_slice(&self.client_nonce);
        payload.push(self.suite.wire_id());
        payload.extend_from_slice(&self.cookie.issued_at_ms.to_be_bytes());
        payload.extend_from_slice(&self.cookie.tag);
        payload
    }
}

pub(crate) fn verify_cookie(
    cookie_secret: &[u8],
    client_hello: &ClientHello,
    peer_id: PeerId,
    now_ms: u64,
    lifetime: Duration,
) -> Result<(), HandshakeError> {
    let cookie = client_hello.cookie.ok_or(HandshakeError::InvalidCookie)?;
    let lifetime_ms = u64::try_from(lifetime.as_millis()).unwrap_or(u64::MAX);
    if cookie.issued_at_ms > now_ms || now_ms.saturating_sub(cookie.issued_at_ms) > lifetime_ms {
        return Err(HandshakeError::InvalidCookie);
    }
    let transcript = cookie_transcript(client_hello, peer_id, cookie.issued_at_ms);
    verify_hmac(cookie_secret, &transcript, &cookie.tag).map_err(|_| HandshakeError::InvalidCookie)
}

impl ServerHello {
    pub(crate) fn create(
        psk: &Psk,
        client_hello: &ClientHello,
        session_id: SessionId,
    ) -> Result<Self, crate::EngineError> {
        let mut server_nonce = [0_u8; 32];
        let mut session_salt = [0_u8; 32];
        getrandom::getrandom(&mut server_nonce)
            .map_err(|_| crate::EngineError::RandomnessUnavailable)?;
        getrandom::getrandom(&mut session_salt)
            .map_err(|_| crate::EngineError::RandomnessUnavailable)?;
        let mut hello = Self {
            handshake_id: client_hello.handshake_id,
            client_nonce: client_hello.client_nonce,
            server_nonce,
            session_salt,
            suite: client_hello.suite,
            auth_tag: [0; 32],
        };
        let transcript = server_auth_transcript(client_hello, session_id, &hello);
        hello.auth_tag = handshake_tag(psk, &hello.handshake_id, &hello.client_nonce, &transcript)?;
        Ok(hello)
    }

    pub(crate) fn verify(
        &self,
        psk: &Psk,
        client_hello: &ClientHello,
        session_id: SessionId,
    ) -> Result<(), HandshakeError> {
        if self.handshake_id != client_hello.handshake_id {
            return Err(HandshakeError::HandshakeIdMismatch);
        }
        if self.client_nonce != client_hello.client_nonce {
            return Err(HandshakeError::AuthenticationFailed);
        }
        if self.suite != client_hello.suite {
            return Err(HandshakeError::CipherSuiteMismatch);
        }
        let transcript = server_auth_transcript(client_hello, session_id, self);
        verify_handshake_tag(
            psk,
            &self.handshake_id,
            &self.client_nonce,
            &transcript,
            &self.auth_tag,
        )
        .map_err(|_| HandshakeError::AuthenticationFailed)
    }

    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        let mut payload = self.encode_unsigned_payload();
        payload.extend_from_slice(&self.auth_tag);
        payload
    }

    fn encode_unsigned_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(SERVER_HELLO_UNSIGNED_LENGTH);
        payload.extend_from_slice(&self.handshake_id);
        payload.extend_from_slice(&self.client_nonce);
        payload.extend_from_slice(&self.server_nonce);
        payload.extend_from_slice(&self.session_salt);
        payload.push(self.suite.wire_id());
        payload
    }

    pub(crate) fn decode(frame: &WireFrame) -> Result<Self, HandshakeError> {
        if frame.frame_type != FrameType::ServerHello
            || frame.session_id == SessionId::from_u128(0)
            || frame.packet_number != 0
            || frame.epoch != 0
            || frame.payload.len() != SERVER_HELLO_LENGTH
        {
            return Err(HandshakeError::Malformed);
        }
        let suite =
            CipherSuite::from_wire_id(frame.payload[112]).map_err(|_| HandshakeError::Malformed)?;
        Ok(Self {
            handshake_id: frame.payload[..16].try_into().expect("fixed slice"),
            client_nonce: frame.payload[16..48].try_into().expect("fixed slice"),
            server_nonce: frame.payload[48..80].try_into().expect("fixed slice"),
            session_salt: frame.payload[80..112].try_into().expect("fixed slice"),
            suite,
            auth_tag: frame.payload[113..145].try_into().expect("fixed slice"),
        })
    }

    pub(crate) fn frame(&self, session_id: SessionId) -> WireFrame {
        WireFrame {
            session_id,
            packet_number: 0,
            epoch: 0,
            frame_type: FrameType::ServerHello,
            conversation_id: None,
            payload: self.encode_payload(),
        }
    }
}

impl ClientFinish {
    pub(crate) fn create(
        psk: &Psk,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        session_id: SessionId,
    ) -> Result<Self, CryptoError> {
        let transcript = full_transcript(client_hello, session_id, server_hello);
        let auth_tag = handshake_tag(
            psk,
            &client_hello.handshake_id,
            &client_hello.client_nonce,
            &transcript,
        )?;
        Ok(Self {
            handshake_id: client_hello.handshake_id,
            auth_tag,
        })
    }

    pub(crate) fn verify(
        &self,
        psk: &Psk,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        session_id: SessionId,
    ) -> Result<(), HandshakeError> {
        if self.handshake_id != client_hello.handshake_id {
            return Err(HandshakeError::HandshakeIdMismatch);
        }
        let transcript = full_transcript(client_hello, session_id, server_hello);
        verify_handshake_tag(
            psk,
            &self.handshake_id,
            &client_hello.client_nonce,
            &transcript,
            &self.auth_tag,
        )
        .map_err(|_| HandshakeError::AuthenticationFailed)
    }

    pub(crate) fn decode(frame: &WireFrame) -> Result<Self, HandshakeError> {
        if frame.frame_type != FrameType::ClientFinish
            || frame.session_id == SessionId::from_u128(0)
            || frame.packet_number != 0
            || frame.epoch != 0
            || frame.payload.len() != CLIENT_FINISH_LENGTH
        {
            return Err(HandshakeError::Malformed);
        }
        Ok(Self {
            handshake_id: frame.payload[..16].try_into().expect("fixed slice"),
            auth_tag: frame.payload[16..48].try_into().expect("fixed slice"),
        })
    }

    pub(crate) fn frame(&self, session_id: SessionId) -> WireFrame {
        let mut payload = Vec::with_capacity(CLIENT_FINISH_LENGTH);
        payload.extend_from_slice(&self.handshake_id);
        payload.extend_from_slice(&self.auth_tag);
        WireFrame {
            session_id,
            packet_number: 0,
            epoch: 0,
            frame_type: FrameType::ClientFinish,
            conversation_id: None,
            payload,
        }
    }
}

pub(crate) fn session_keys(
    psk: &Psk,
    client_hello: &ClientHello,
    server_hello: &ServerHello,
    session_id: SessionId,
) -> Result<SessionKeys, CryptoError> {
    derive_session_keys(
        psk,
        client_hello.suite,
        session_id,
        &client_hello.client_nonce,
        &server_hello.server_nonce,
        &server_hello.session_salt,
        &full_transcript(client_hello, session_id, server_hello),
    )
}

fn server_auth_transcript(
    client_hello: &ClientHello,
    session_id: SessionId,
    server_hello: &ServerHello,
) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(16 + CLIENT_HELLO_COOKIE_LENGTH + 16 + SERVER_HELLO_LENGTH);
    transcript.extend_from_slice(b"udp2raw-ng/v3/server-auth");
    transcript.extend_from_slice(&client_hello.encode_payload());
    transcript.extend_from_slice(&session_id.to_be_bytes());
    transcript.extend_from_slice(&server_hello.encode_unsigned_payload());
    transcript
}

fn full_transcript(
    client_hello: &ClientHello,
    session_id: SessionId,
    server_hello: &ServerHello,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(CLIENT_HELLO_COOKIE_LENGTH + SERVER_HELLO_LENGTH + 64);
    transcript.extend_from_slice(b"udp2raw-ng/v3/full-transcript");
    transcript.extend_from_slice(&client_hello.encode_payload());
    transcript.extend_from_slice(&session_id.to_be_bytes());
    transcript.extend_from_slice(&server_hello.encode_payload());
    transcript
}

fn retry_auth_transcript(retry: &HelloRetry) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(32 + HELLO_RETRY_UNSIGNED_LENGTH);
    transcript.extend_from_slice(b"udp2raw-ng/v3/hello-retry-auth");
    transcript.extend_from_slice(&retry.encode_unsigned_payload());
    transcript
}

fn cookie_tag(
    cookie_secret: &[u8],
    client_hello: &ClientHello,
    peer_id: PeerId,
    issued_at_ms: u64,
) -> Result<[u8; 32], CryptoError> {
    hmac_tag(
        cookie_secret,
        &cookie_transcript(client_hello, peer_id, issued_at_ms),
    )
}

fn cookie_transcript(client_hello: &ClientHello, peer_id: PeerId, issued_at_ms: u64) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(b"udp2raw-ng/v3/handshake-cookie");
    transcript.extend_from_slice(&peer_id.get().to_be_bytes());
    transcript.extend_from_slice(&issued_at_ms.to_be_bytes());
    transcript.extend_from_slice(&client_hello.handshake_id);
    transcript.extend_from_slice(&client_hello.client_nonce);
    transcript.push(client_hello.suite.wire_id());
    transcript
}
