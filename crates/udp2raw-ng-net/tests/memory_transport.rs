use std::task::Context;

use udp2raw_ng_net::{
    MemoryTransportError, OutboundPacket, PacketTransport, memory_transport_pair,
};

fn context() -> Context<'static> {
    Context::from_waker(std::task::Waker::noop())
}

fn ready_packet(
    poll: std::task::Poll<Result<udp2raw_ng_net::InboundPacket, MemoryTransportError>>,
) -> udp2raw_ng_net::InboundPacket {
    match poll {
        std::task::Poll::Ready(result) => result.expect("packet"),
        std::task::Poll::Pending => panic!("packet should be ready"),
    }
}

#[test]
fn pair_is_bidirectional_fifo_and_preserves_sender_peer() {
    let (mut a, mut b) = memory_transport_pair(2).expect("pair");
    let a_peer = a.local_peer();
    let b_peer = b.local_peer();
    a.send(OutboundPacket {
        peer_id: b_peer,
        frame: vec![1],
    })
    .expect("first");
    a.send(OutboundPacket {
        peer_id: b_peer,
        frame: vec![2],
    })
    .expect("second");
    assert_eq!(
        a.send(OutboundPacket {
            peer_id: b_peer,
            frame: vec![3],
        }),
        Err(MemoryTransportError::QueueFull)
    );

    let mut cx = context();
    let first = ready_packet(b.poll_receive(&mut cx));
    let second = ready_packet(b.poll_receive(&mut cx));
    assert_eq!(first.peer_id, a_peer);
    assert_eq!(first.frame, vec![1]);
    assert_eq!(second.frame, vec![2]);

    b.send(OutboundPacket {
        peer_id: a_peer,
        frame: vec![9],
    })
    .expect("reply");
    let reply = ready_packet(a.poll_receive(&mut cx));
    assert_eq!(reply.peer_id, b_peer);
    assert_eq!(reply.frame, vec![9]);
}

#[test]
fn dropping_peer_closes_both_directions() {
    let (a, mut b) = memory_transport_pair(1).expect("pair");
    let a_peer = a.local_peer();
    drop(a);
    assert_eq!(
        b.send(OutboundPacket {
            peer_id: a_peer,
            frame: vec![1],
        }),
        Err(MemoryTransportError::PeerClosed)
    );
    let mut cx = context();
    assert_eq!(
        b.poll_receive(&mut cx),
        std::task::Poll::Ready(Err(MemoryTransportError::PeerClosed))
    );
}
