use crate::{ConversationId, FrameError, SessionId};

pub const PROTOCOL_VERSION: u16 = 3;
pub const MAX_FRAME_PAYLOAD: usize = 65_507;
pub(crate) const MAX_FRAME_BODY: usize = MAX_FRAME_PAYLOAD + 32;
pub(crate) const HEADER_LENGTH: usize = 48;
const MAGIC: [u8; 4] = *b"U2NG";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 1,
    ServerHello = 2,
    ClientFinish = 3,
    HelloRetry = 4,
    Data = 16,
    Heartbeat = 17,
    Close = 18,
    HandshakeAck = 19,
    ResumptionCredential = 20,
    MtuProbe = 32,
    MtuAck = 33,
}

impl FrameType {
    pub(crate) const fn is_handshake(self) -> bool {
        matches!(
            self,
            Self::ClientHello | Self::ServerHello | Self::ClientFinish | Self::HelloRetry
        )
    }

    pub(crate) const fn is_protected(self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::Heartbeat
                | Self::Close
                | Self::HandshakeAck
                | Self::ResumptionCredential
        )
    }
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::ClientFinish),
            4 => Ok(Self::HelloRetry),
            16 => Ok(Self::Data),
            17 => Ok(Self::Heartbeat),
            18 => Ok(Self::Close),
            19 => Ok(Self::HandshakeAck),
            20 => Ok(Self::ResumptionCredential),
            32 => Ok(Self::MtuProbe),
            33 => Ok(Self::MtuAck),
            _ => Err(FrameError::UnknownFrameType(value)),
        }
    }
}

/// Versioned wire envelope. For protected frames `payload` contains ciphertext
/// and its authentication tag, not application plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFrame {
    pub session_id: SessionId,
    pub packet_number: u64,
    pub epoch: u32,
    pub frame_type: FrameType,
    pub conversation_id: Option<ConversationId>,
    pub payload: Vec<u8>,
}

impl WireFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.validate_fields()?;
        if self.payload.len() > MAX_FRAME_BODY {
            return Err(FrameError::PayloadTooLarge);
        }
        let header = self.encoded_header(self.payload.len())?;
        let mut output = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        if input.len() < HEADER_LENGTH {
            return Err(FrameError::Truncated);
        }
        if input[..4] != MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        let version = u16::from_be_bytes([input[4], input[5]]);
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }
        let frame_type = FrameType::try_from(input[6])?;
        if input[7] != 0 {
            return Err(FrameError::ReservedFlags);
        }
        let payload_length = usize::try_from(u32::from_be_bytes(
            input[44..48].try_into().expect("fixed slice"),
        ))
        .map_err(|_| FrameError::InvalidPayloadLength)?;
        if payload_length > MAX_FRAME_BODY {
            return Err(FrameError::PayloadTooLarge);
        }
        if input.len() != HEADER_LENGTH + payload_length {
            return Err(FrameError::InvalidPayloadLength);
        }
        let raw_conversation = u64::from_be_bytes(input[36..44].try_into().expect("fixed slice"));
        let conversation_id = std::num::NonZeroU64::new(raw_conversation).map(ConversationId::new);
        let frame = Self {
            session_id: SessionId::from_u128(u128::from_be_bytes(
                input[12..28].try_into().expect("fixed slice"),
            )),
            packet_number: u64::from_be_bytes(input[28..36].try_into().expect("fixed slice")),
            epoch: u32::from_be_bytes(input[8..12].try_into().expect("fixed slice")),
            frame_type,
            conversation_id,
            payload: input[HEADER_LENGTH..].to_vec(),
        };
        frame.validate_fields()?;
        Ok(frame)
    }

    pub(crate) fn encoded_header(
        &self,
        body_length: usize,
    ) -> Result<[u8; HEADER_LENGTH], FrameError> {
        let body_length = u32::try_from(body_length).map_err(|_| FrameError::PayloadTooLarge)?;
        let mut output = [0_u8; HEADER_LENGTH];
        output[..4].copy_from_slice(&MAGIC);
        output[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        output[6] = self.frame_type as u8;
        output[7] = 0;
        output[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        output[12..28].copy_from_slice(&self.session_id.to_be_bytes());
        output[28..36].copy_from_slice(&self.packet_number.to_be_bytes());
        output[36..44].copy_from_slice(
            &self
                .conversation_id
                .map_or(0, ConversationId::get)
                .to_be_bytes(),
        );
        output[44..48].copy_from_slice(&body_length.to_be_bytes());
        Ok(output)
    }

    fn validate_fields(&self) -> Result<(), FrameError> {
        if self.frame_type == FrameType::Data && self.conversation_id.is_none() {
            return Err(FrameError::InvalidFrameFields);
        }
        if self.frame_type.is_handshake() && self.conversation_id.is_some() {
            return Err(FrameError::InvalidFrameFields);
        }
        Ok(())
    }
}
