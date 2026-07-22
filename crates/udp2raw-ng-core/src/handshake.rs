use crate::crypto::{SessionKeys, derive_session_keys, handshake_tag, verify_handshake_tag};
use crate::{CipherSuite, CryptoError, FrameType, HandshakeError, Psk, SessionId, WireFrame};

const CLIENT_HELLO_LENGTH: usize = 49;
const SERVER_HELLO_UNSIGNED_LENGTH: usize = 113;
const SERVER_HELLO_LENGTH: usize = SERVER_HELLO_UNSIGNED_LENGTH + 32;
const CLIENT_FINISH_LENGTH: usize = 48;

#[derive(Clone)]
pub(crate) struct ClientHello {
    pub(crate) handshake_id: [u8; 16],
    pub(crate) client_nonce: [u8; 32],
    pub(crate) suite: CipherSuite,
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
        })
    }

    pub(crate) fn encode_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(CLIENT_HELLO_LENGTH);
        payload.extend_from_slice(&self.handshake_id);
        payload.extend_from_slice(&self.client_nonce);
        payload.push(self.suite.wire_id());
        payload
    }

    pub(crate) fn decode(frame: &WireFrame) -> Result<Self, HandshakeError> {
        if frame.frame_type != FrameType::ClientHello
            || frame.session_id != SessionId::from_u128(0)
            || frame.packet_number != 0
            || frame.epoch != 0
            || frame.payload.len() != CLIENT_HELLO_LENGTH
        {
            return Err(HandshakeError::Malformed);
        }
        let suite =
            CipherSuite::from_wire_id(frame.payload[48]).map_err(|_| HandshakeError::Malformed)?;
        Ok(Self {
            handshake_id: frame.payload[..16].try_into().expect("fixed slice"),
            client_nonce: frame.payload[16..48].try_into().expect("fixed slice"),
            suite,
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
    let mut transcript = Vec::with_capacity(16 + CLIENT_HELLO_LENGTH + 16 + SERVER_HELLO_LENGTH);
    transcript.extend_from_slice(b"udp2raw-ng/v2/server-auth");
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
    let mut transcript = Vec::with_capacity(CLIENT_HELLO_LENGTH + SERVER_HELLO_LENGTH + 64);
    transcript.extend_from_slice(b"udp2raw-ng/v2/full-transcript");
    transcript.extend_from_slice(&client_hello.encode_payload());
    transcript.extend_from_slice(&session_id.to_be_bytes());
    transcript.extend_from_slice(&server_hello.encode_payload());
    transcript
}
