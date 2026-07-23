use crate::{ConversationId, FrameError, SessionId};

pub const PROTOCOL_VERSION: u16 = 4;
/// Conservative v4 UDP payload ceiling before future per-path PMTU probing.
/// It avoids handing oversized datagrams to the future FakeTCP/IP transport.
pub const MAX_FRAME_PAYLOAD: usize = 1_150;
pub(crate) const MAX_FRAME_BODY: usize = MAX_FRAME_PAYLOAD + 32;
pub(crate) const HEADER_LENGTH: usize = 24;
const V4_DISCRIMINATOR: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 1,
    ServerHello = 2,
    ClientFinish = 3,
    HelloRetry = 4,
    Data = 16,
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
            Self::Data | Self::Close | Self::HandshakeAck | Self::ResumptionCredential
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
            17 => Err(FrameError::UnknownFrameType(value)),
            18 => Ok(Self::Close),
            19 => Ok(Self::HandshakeAck),
            20 => Ok(Self::ResumptionCredential),
            32 => Ok(Self::MtuProbe),
            33 => Ok(Self::MtuAck),
            _ => Err(FrameError::UnknownFrameType(value)),
        }
    }
}

/// Compact v4 datagram envelope. The datagram boundary supplies the body
/// length; for protected frames `payload` contains ciphertext and its tag.
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
        let header = self.encoded_header()?;
        let mut output = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        output.extend_from_slice(&header);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, FrameError> {
        if input.len() < HEADER_LENGTH {
            return Err(FrameError::Truncated);
        }
        if input[0] != V4_DISCRIMINATOR {
            return Err(FrameError::InvalidMagic);
        }
        let frame_type = FrameType::try_from(input[1])?;
        if input[3] != 0 {
            return Err(FrameError::ReservedFlags);
        }
        let payload_length = input.len() - HEADER_LENGTH;
        if payload_length > MAX_FRAME_BODY {
            return Err(FrameError::PayloadTooLarge);
        }
        let raw_conversation = u32::from_be_bytes(input[20..24].try_into().expect("fixed slice"));
        let conversation_id = std::num::NonZeroU32::new(raw_conversation).map(ConversationId::new);
        let frame = Self {
            session_id: SessionId::from_u64(u64::from_be_bytes(
                input[4..12].try_into().expect("fixed slice"),
            )),
            packet_number: u64::from_be_bytes(input[12..20].try_into().expect("fixed slice")),
            epoch: u32::from(input[2]),
            frame_type,
            conversation_id,
            payload: input[HEADER_LENGTH..].to_vec(),
        };
        frame.validate_fields()?;
        Ok(frame)
    }

    pub(crate) fn encoded_header(&self) -> Result<[u8; HEADER_LENGTH], FrameError> {
        let epoch = u8::try_from(self.epoch).map_err(|_| FrameError::InvalidFrameFields)?;
        let mut output = [0_u8; HEADER_LENGTH];
        output[0] = V4_DISCRIMINATOR;
        output[1] = self.frame_type as u8;
        output[2] = epoch;
        output[3] = 0;
        output[4..12].copy_from_slice(&self.session_id.to_be_bytes());
        output[12..20].copy_from_slice(&self.packet_number.to_be_bytes());
        output[20..24].copy_from_slice(
            &self
                .conversation_id
                .map_or(0, ConversationId::get)
                .to_be_bytes(),
        );
        Ok(output)
    }

    fn validate_fields(&self) -> Result<(), FrameError> {
        match self.frame_type {
            FrameType::Data | FrameType::ResumptionCredential if self.conversation_id.is_none() => {
                return Err(FrameError::InvalidFrameFields);
            }
            FrameType::ClientHello
            | FrameType::ServerHello
            | FrameType::ClientFinish
            | FrameType::HelloRetry
            | FrameType::HandshakeAck
                if self.conversation_id.is_some() =>
            {
                return Err(FrameError::InvalidFrameFields);
            }
            _ => {}
        }
        if self.epoch > u32::from(u8::MAX) {
            return Err(FrameError::InvalidFrameFields);
        }
        if self.frame_type.is_handshake() && self.conversation_id.is_some() {
            return Err(FrameError::InvalidFrameFields);
        }
        Ok(())
    }
}
