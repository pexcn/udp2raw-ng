//! Packet transport boundary with a bounded in-memory implementation for tests
//! and embedding. Raw sockets, AF_PACKET, cBPF, and Netfilter management remain
//! unimplemented; the Linux placeholder fails closed.

use std::task::{Context, Poll};

use thiserror::Error;
use udp2raw_ng_core::PeerId;

pub use udp2raw_ng_core;

mod memory;
pub use memory::{MemoryTransport, MemoryTransportError, memory_transport_pair};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundPacket {
    /// Host-assigned route for the remote endpoint.
    pub peer_id: PeerId,
    /// Authenticated tunnel frame to place in a FakeTCP payload.
    pub frame: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundPacket {
    /// Host-assigned route identifying the transport sender.
    pub peer_id: PeerId,
    /// Tunnel frame extracted from a validated outer packet.
    pub frame: Vec<u8>,
}

/// Replaceable host transport. The core crate does not depend on this trait.
pub trait PacketTransport {
    type Error;

    fn send(&mut self, packet: OutboundPacket) -> Result<(), Self::Error>;

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<InboundPacket, Self::Error>>;
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LinuxTransportError {
    #[error("Linux FakeTCP transport is not implemented in this milestone")]
    NotImplemented,
}

/// Fail-closed placeholder for the future Linux raw packet transport.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct LinuxFakeTcpTransport;

impl LinuxFakeTcpTransport {
    pub fn open() -> Result<Self, LinuxTransportError> {
        Err(LinuxTransportError::NotImplemented)
    }
}

impl PacketTransport for LinuxFakeTcpTransport {
    type Error = LinuxTransportError;

    fn send(&mut self, _packet: OutboundPacket) -> Result<(), Self::Error> {
        Err(LinuxTransportError::NotImplemented)
    }

    fn poll_receive(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<Result<InboundPacket, Self::Error>> {
        Poll::Ready(Err(LinuxTransportError::NotImplemented))
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxFakeTcpTransport, LinuxTransportError};

    #[test]
    fn placeholder_fails_closed() {
        assert_eq!(
            LinuxFakeTcpTransport::open(),
            Err(LinuxTransportError::NotImplemented)
        );
    }
}
