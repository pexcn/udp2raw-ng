//! Packet transport boundary with a bounded in-memory implementation for tests
//! and embedding, plus an IPv4 Linux FakeTCP adapter. AF_PACKET, cBPF, and
//! Netfilter management remain separate follow-up work.

use std::task::{Context, Poll};

use udp2raw_ng_core::PeerId;

pub use udp2raw_ng_core;

mod memory;
pub use memory::{MemoryTransport, MemoryTransportError, memory_transport_pair};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{FakeTcpRole, LinuxFakeTcpConfig, LinuxFakeTcpTransport, LinuxTransportError};

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
