use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use thiserror::Error;
use udp2raw_ng_core::PeerId;

use crate::{InboundPacket, OutboundPacket, PacketTransport};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemoryTransportError {
    #[error("memory transport capacity must be greater than zero")]
    ZeroCapacity,
    #[error("memory transport receive queue is full")]
    QueueFull,
    #[error("memory transport peer is closed")]
    PeerClosed,
}

#[derive(Default)]
struct QueueState {
    packets: VecDeque<InboundPacket>,
    receiver_waker: Option<Waker>,
    sender_open: bool,
    receiver_open: bool,
}

struct SharedQueue {
    capacity: usize,
    state: Mutex<QueueState>,
}

pub struct MemoryTransport {
    local_peer: PeerId,
    remote_peer: PeerId,
    incoming: Arc<SharedQueue>,
    outgoing: Arc<SharedQueue>,
}

pub fn memory_transport_pair(
    capacity: usize,
) -> Result<(MemoryTransport, MemoryTransport), MemoryTransportError> {
    if capacity == 0 {
        return Err(MemoryTransportError::ZeroCapacity);
    }
    let a_peer = PeerId::new(1);
    let b_peer = PeerId::new(2);
    let a_to_b = Arc::new(SharedQueue {
        capacity,
        state: Mutex::new(QueueState {
            sender_open: true,
            receiver_open: true,
            ..QueueState::default()
        }),
    });
    let b_to_a = Arc::new(SharedQueue {
        capacity,
        state: Mutex::new(QueueState {
            sender_open: true,
            receiver_open: true,
            ..QueueState::default()
        }),
    });
    Ok((
        MemoryTransport {
            local_peer: a_peer,
            remote_peer: b_peer,
            incoming: Arc::clone(&b_to_a),
            outgoing: Arc::clone(&a_to_b),
        },
        MemoryTransport {
            local_peer: b_peer,
            remote_peer: a_peer,
            incoming: a_to_b,
            outgoing: b_to_a,
        },
    ))
}

impl MemoryTransport {
    pub const fn local_peer(&self) -> PeerId {
        self.local_peer
    }

    pub const fn remote_peer(&self) -> PeerId {
        self.remote_peer
    }
}

impl PacketTransport for MemoryTransport {
    type Error = MemoryTransportError;

    fn send(&mut self, packet: OutboundPacket) -> Result<(), Self::Error> {
        if packet.peer_id != self.remote_peer {
            return Err(MemoryTransportError::PeerClosed);
        }
        let waker = {
            let mut state = self.outgoing.state.lock().expect("memory queue poisoned");
            if !state.receiver_open {
                return Err(MemoryTransportError::PeerClosed);
            }
            if state.packets.len() >= self.outgoing.capacity {
                return Err(MemoryTransportError::QueueFull);
            }
            state.packets.push_back(InboundPacket {
                peer_id: self.local_peer,
                frame: packet.frame,
            });
            state.receiver_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<InboundPacket, Self::Error>> {
        let mut state = self.incoming.state.lock().expect("memory queue poisoned");
        if let Some(packet) = state.packets.pop_front() {
            return Poll::Ready(Ok(packet));
        }
        if !state.sender_open {
            return Poll::Ready(Err(MemoryTransportError::PeerClosed));
        }
        state.receiver_waker = Some(context.waker().clone());
        Poll::Pending
    }
}

impl Drop for MemoryTransport {
    fn drop(&mut self) {
        {
            let mut state = self.outgoing.state.lock().expect("memory queue poisoned");
            state.sender_open = false;
        }
        let waker = {
            let mut state = self.incoming.state.lock().expect("memory queue poisoned");
            state.receiver_open = false;
            state.receiver_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
