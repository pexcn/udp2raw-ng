use std::num::NonZeroU32;

use udp2raw_ng_core::{ConversationId, FrameError, FrameType, SessionId, WireFrame};

fn sample_frame() -> WireFrame {
    WireFrame {
        session_id: SessionId::from_u64(42),
        packet_number: 7,
        epoch: 0,
        frame_type: FrameType::Data,
        conversation_id: Some(ConversationId::new(NonZeroU32::new(9).expect("non-zero"))),
        payload: b"hello".to_vec(),
    }
}

#[test]
fn frame_round_trip() {
    let frame = sample_frame();
    let encoded = frame.encode().expect("encode");
    assert_eq!(encoded.len(), 24 + frame.payload.len());
    assert_eq!(WireFrame::decode(&encoded).expect("decode"), frame);
}

#[test]
fn every_fixed_header_truncation_is_rejected_without_panicking() {
    let encoded = sample_frame().encode().expect("encode");
    for length in 0..24 {
        assert!(WireFrame::decode(&encoded[..length]).is_err());
    }
}

#[test]
fn datagram_boundary_supplies_body_length() {
    let mut encoded = sample_frame().encode().expect("encode");
    encoded.push(0);
    let decoded = WireFrame::decode(&encoded).expect("decode extended datagram");
    assert_eq!(decoded.payload, b"hello\0");
}

#[test]
fn v4_rejects_legacy_magic_reserved_heartbeat_and_nonzero_flags() {
    let encoded = sample_frame().encode().expect("encode");

    let mut legacy = encoded.clone();
    legacy[..4].copy_from_slice(b"U2NG");
    assert_eq!(WireFrame::decode(&legacy), Err(FrameError::InvalidMagic));

    let mut heartbeat = encoded.clone();
    heartbeat[1] = 17;
    assert_eq!(
        WireFrame::decode(&heartbeat),
        Err(FrameError::UnknownFrameType(17))
    );

    let mut flagged = encoded;
    flagged[3] = 1;
    assert_eq!(WireFrame::decode(&flagged), Err(FrameError::ReservedFlags));
}
