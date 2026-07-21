use std::num::NonZeroU64;

use udp2raw_ng_core::{ConversationId, FrameError, FrameType, SessionId, WireFrame};

fn sample_frame() -> WireFrame {
    WireFrame {
        session_id: SessionId::from_u128(42),
        packet_number: 7,
        epoch: 0,
        frame_type: FrameType::Data,
        conversation_id: Some(ConversationId::new(NonZeroU64::new(9).expect("non-zero"))),
        payload: b"hello".to_vec(),
    }
}

#[test]
fn frame_round_trip() {
    let frame = sample_frame();
    let encoded = frame.encode().expect("encode");
    assert_eq!(WireFrame::decode(&encoded).expect("decode"), frame);
}

#[test]
fn every_truncation_is_rejected_without_panicking() {
    let encoded = sample_frame().encode().expect("encode");
    for length in 0..encoded.len() {
        assert!(WireFrame::decode(&encoded[..length]).is_err());
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut encoded = sample_frame().encode().expect("encode");
    encoded.push(0);
    assert_eq!(
        WireFrame::decode(&encoded),
        Err(FrameError::InvalidPayloadLength)
    );
}
