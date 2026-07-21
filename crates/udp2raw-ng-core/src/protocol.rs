use crate::{ConversationId, FrameError, SessionId};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_PAYLOAD: usize = 65_507;
const MAGIC: [u8; 4] = *b"U2NG";
const HEADER_LENGTH: usize = 48;

/// Extensible inner frame kind. Encryption and transcript formats are not yet
/// implemented, so data frames produced in this milestone are test-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 1,
    ServerHello = 2,
    ClientFinish = 3,
    Data = 16,
    Heartbeat = 17,
    Close = 18,
    MtuProbe = 32,
    MtuAck = 33,
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::ClientFinish),
            16 => Ok(Self::Data),
            17 => Ok(Self::Heartbeat),
            18 => Ok(Self::Close),
            32 => Ok(Self::MtuProbe),
            33 => Ok(Self::MtuAck),
            _ => Err(FrameError::UnknownFrameType(value)),
        }
    }
}

/// A bounded, versioned wire envelope.
///
/// This representation deliberately reserves an epoch and flags field for
/// authenticated key rotation and protocol evolution.
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
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge);
        }
        let payload_length =
            u32::try_from(self.payload.len()).map_err(|_| FrameError::PayloadTooLarge)?;
        let mut output = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        output.extend_from_slice(&MAGIC);
        output.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        output.push(self.frame_type as u8);
        output.push(0); // Reserved flags; authenticated in the future.
        output.extend_from_slice(&self.epoch.to_be_bytes());
        output.extend_from_slice(&self.session_id.to_be_bytes());
        output.extend_from_slice(&self.packet_number.to_be_bytes());
        output.extend_from_slice(
            &self
                .conversation_id
                .map_or(0, ConversationId::get)
                .to_be_bytes(),
        );
        output.extend_from_slice(&payload_length.to_be_bytes());
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
        FrameType::try_from(input[6])?;
        if input[7] != 0 {
            return Err(FrameError::ReservedFlags);
        }
        let payload_length = usize::try_from(u32::from_be_bytes(
            input[44..48].try_into().expect("fixed slice"),
        ))
        .map_err(|_| FrameError::InvalidPayloadLength)?;
        if payload_length > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge);
        }
        if input.len() != HEADER_LENGTH + payload_length {
            return Err(FrameError::InvalidPayloadLength);
        }
        let raw_conversation = u64::from_be_bytes(input[36..44].try_into().expect("fixed slice"));
        let conversation_id = std::num::NonZeroU64::new(raw_conversation).map(ConversationId::new);
        Ok(Self {
            session_id: SessionId::from_u128(u128::from_be_bytes(
                input[12..28].try_into().expect("fixed slice"),
            )),
            packet_number: u64::from_be_bytes(input[28..36].try_into().expect("fixed slice")),
            epoch: u32::from_be_bytes(input[8..12].try_into().expect("fixed slice")),
            frame_type: FrameType::try_from(input[6])?,
            conversation_id,
            payload: input[HEADER_LENGTH..].to_vec(),
        })
    }
}
