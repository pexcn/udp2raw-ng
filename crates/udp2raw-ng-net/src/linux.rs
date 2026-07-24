//! Linux IPv4 FakeTCP transport.
//!
//! The adapter owns only the outer packet path. Inner frames remain opaque and
//! are authenticated by `udp2raw-ng-core` after delivery.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;

use getrandom::getrandom;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{
    Ipv4Flags, Ipv4Packet, MutableIpv4Packet, checksum as ipv4_header_checksum,
};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::transport::{TransportChannelType, TransportSender, ipv4_packet_iter, transport_channel};
use thiserror::Error;
use udp2raw_ng_core::PeerId;

use crate::{InboundPacket, OutboundPacket, PacketTransport};

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const MAX_INNER_FRAME: usize = 65_535 - TCP_HEADER_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeTcpRole {
    Client,
    Server,
}

/// Configuration for the IPv4-only Linux FakeTCP transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxFakeTcpConfig {
    pub role: FakeTcpRole,
    /// Client: outer source address. Server: local destination address to accept.
    pub local_addr: SocketAddr,
    /// Required only for a client.
    pub peer_addr: Option<SocketAddr>,
    /// Stable transport route assigned to the configured client peer.
    pub local_peer: PeerId,
    /// Maximum decoded inner frames waiting for the host.
    pub queue_capacity: usize,
}

impl LinuxFakeTcpConfig {
    pub fn client(local_addr: SocketAddr, peer_addr: SocketAddr, server_peer: PeerId) -> Self {
        Self {
            role: FakeTcpRole::Client,
            local_addr,
            peer_addr: Some(peer_addr),
            local_peer: server_peer,
            queue_capacity: 1024,
        }
    }

    pub fn server(local_addr: SocketAddr) -> Self {
        Self {
            role: FakeTcpRole::Server,
            local_addr,
            peer_addr: None,
            local_peer: PeerId::new(0),
            queue_capacity: 1024,
        }
    }

    fn validate(&self) -> Result<(), LinuxTransportError> {
        if self.queue_capacity == 0 {
            return Err(LinuxTransportError::ZeroQueueCapacity);
        }
        if !matches!(self.local_addr, SocketAddr::V4(_)) {
            return Err(LinuxTransportError::Ipv6Unsupported);
        }
        match (self.role, self.peer_addr) {
            (FakeTcpRole::Client, Some(SocketAddr::V4(_))) => Ok(()),
            (FakeTcpRole::Client, _) => Err(LinuxTransportError::MissingClientPeer),
            (FakeTcpRole::Server, None) => Ok(()),
            (FakeTcpRole::Server, Some(_)) => Err(LinuxTransportError::ServerPeerConfigured),
        }
    }
}

#[derive(Debug, Error)]
pub enum LinuxTransportError {
    #[error("Linux FakeTCP transport requires a non-zero receive queue capacity")]
    ZeroQueueCapacity,
    #[error("IPv6 FakeTCP transport is not implemented")]
    Ipv6Unsupported,
    #[error("a client FakeTCP transport requires an IPv4 peer")]
    MissingClientPeer,
    #[error("a server FakeTCP transport accepts peers dynamically")]
    ServerPeerConfigured,
    #[error("raw TCP socket setup failed: {0}")]
    Socket(#[source] io::Error),
    #[error("raw packet send failed: {0}")]
    Send(#[source] io::Error),
    #[error("outer FakeTCP handshake is not established for peer {0}")]
    HandshakePending(u64),
    #[error("unknown FakeTCP peer {0}")]
    UnknownPeer(u64),
    #[error("inner frame is too large for one TCP payload")]
    FrameTooLarge,
    #[error("Linux FakeTCP transport state lock was poisoned")]
    StatePoisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathPhase {
    ClientSynSent,
    ServerSynAckSent,
    Established,
}

#[derive(Clone, Debug)]
struct Path {
    peer: SocketAddrV4,
    peer_id: PeerId,
    local_ip: Ipv4Addr,
    phase: PathPhase,
    next_sequence: u32,
    expected_sequence: u32,
    pending_frames: VecDeque<Vec<u8>>,
}

struct SharedState {
    paths: HashMap<PeerId, Path>,
    peers: HashMap<SocketAddrV4, PeerId>,
    incoming: VecDeque<InboundPacket>,
    pending_packets: VecDeque<RawTcpPacket>,
    receiver_waker: Option<Waker>,
    queue_capacity: usize,
}

impl SharedState {
    fn new(queue_capacity: usize) -> Self {
        Self {
            paths: HashMap::new(),
            peers: HashMap::new(),
            incoming: VecDeque::new(),
            pending_packets: VecDeque::new(),
            receiver_waker: None,
            queue_capacity,
        }
    }
}

#[derive(Clone, Debug)]
struct RawTcpPacket {
    source: Ipv4Addr,
    destination: SocketAddrV4,
    source_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: Vec<u8>,
}

/// Linux raw IPv4/TCP transport with a minimal, datagram-oriented FakeTCP
/// handshake. It performs no TCP retransmission, flow control, or stream
/// reassembly.
pub struct LinuxFakeTcpTransport {
    local: SocketAddrV4,
    state: Arc<Mutex<SharedState>>,
    sender: TransportSender,
}

impl LinuxFakeTcpTransport {
    pub fn open(config: LinuxFakeTcpConfig) -> Result<Self, LinuxTransportError> {
        config.validate()?;
        let local = match config.local_addr {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => return Err(LinuxTransportError::Ipv6Unsupported),
        };
        let (sender, receiver) = transport_channel(
            65_536,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .map_err(LinuxTransportError::Socket)?;
        let state = Arc::new(Mutex::new(SharedState::new(config.queue_capacity)));
        let transport = Self {
            local,
            state: Arc::clone(&state),
            sender,
        };
        if let Some(peer) = config.peer_addr {
            let peer = match peer {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => return Err(LinuxTransportError::Ipv6Unsupported),
            };
            transport.install_client_path(peer, config.local_peer)?;
        }
        spawn_receiver(receiver, local, config.role, state);
        Ok(transport)
    }

    fn install_client_path(
        &self,
        peer: SocketAddrV4,
        peer_id: PeerId,
    ) -> Result<(), LinuxTransportError> {
        let sequence = random_u32()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LinuxTransportError::StatePoisoned)?;
        state.peers.insert(peer, peer_id);
        state.paths.insert(
            peer_id,
            Path {
                peer,
                peer_id,
                local_ip: *self.local.ip(),
                phase: PathPhase::ClientSynSent,
                next_sequence: sequence.wrapping_add(1),
                expected_sequence: 0,
                pending_frames: VecDeque::new(),
            },
        );
        state.pending_packets.push_back(RawTcpPacket {
            source: *self.local.ip(),
            destination: peer,
            source_port: self.local.port(),
            sequence,
            acknowledgement: 0,
            flags: TcpFlags::SYN,
            payload: Vec::new(),
        });
        Ok(())
    }

    fn flush_pending(&mut self) -> Result<(), LinuxTransportError> {
        let pending = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LinuxTransportError::StatePoisoned)?;
            state.pending_packets.drain(..).collect::<Vec<_>>()
        };
        for packet in pending {
            send_tcp_packet(&mut self.sender, packet)?;
        }
        Ok(())
    }
}

impl PacketTransport for LinuxFakeTcpTransport {
    type Error = LinuxTransportError;

    fn send(&mut self, packet: OutboundPacket) -> Result<(), Self::Error> {
        self.flush_pending()?;
        if packet.frame.len() > MAX_INNER_FRAME {
            return Err(LinuxTransportError::FrameTooLarge);
        }
        let raw = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LinuxTransportError::StatePoisoned)?;
            let queue_capacity = state.queue_capacity;
            let path = state
                .paths
                .get_mut(&packet.peer_id)
                .ok_or(LinuxTransportError::UnknownPeer(packet.peer_id.get()))?;
            if path.phase != PathPhase::Established {
                if path.pending_frames.len() >= queue_capacity {
                    return Err(LinuxTransportError::HandshakePending(packet.peer_id.get()));
                }
                path.pending_frames.push_back(packet.frame);
                return Ok(());
            }
            let sequence = path.next_sequence;
            path.next_sequence = path.next_sequence.wrapping_add(packet.frame.len() as u32);
            RawTcpPacket {
                source: path.local_ip,
                destination: path.peer,
                source_port: self.local.port(),
                sequence,
                acknowledgement: path.expected_sequence,
                flags: TcpFlags::ACK | TcpFlags::PSH,
                payload: packet.frame,
            }
        };
        send_tcp_packet(&mut self.sender, raw)
    }

    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<InboundPacket, Self::Error>> {
        self.flush_pending()?;
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(LinuxTransportError::StatePoisoned)),
        };
        if let Some(packet) = state.incoming.pop_front() {
            return Poll::Ready(Ok(packet));
        }
        state.receiver_waker = Some(context.waker().clone());
        Poll::Pending
    }
}

fn spawn_receiver(
    mut receiver: pnet::transport::TransportReceiver,
    local: SocketAddrV4,
    role: FakeTcpRole,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        let mut packets = ipv4_packet_iter(&mut receiver);
        loop {
            let Ok((packet, _)) = packets.next() else {
                return;
            };
            let Some(parsed) = parse_ipv4_tcp(packet.packet()) else {
                continue;
            };
            if parsed.destination != *local.ip() || parsed.destination_port != local.port() {
                continue;
            }
            let source = SocketAddrV4::new(parsed.source, parsed.source_port);
            let waker = match state.lock() {
                Ok(mut guard) => handle_incoming(&mut guard, local, role, source, parsed),
                Err(_) => return,
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    });
}

fn handle_incoming(
    state: &mut SharedState,
    local: SocketAddrV4,
    role: FakeTcpRole,
    source: SocketAddrV4,
    packet: ParsedTcpPacket,
) -> Option<Waker> {
    let peer_id = match state.peers.get(&source).copied() {
        Some(peer_id) => peer_id,
        None if role == FakeTcpRole::Server && packet.flags == TcpFlags::SYN => {
            let peer_id = peer_id_for(source);
            if state.paths.contains_key(&peer_id) {
                return None;
            }
            let sequence = match random_u32() {
                Ok(sequence) => sequence,
                Err(_) => return None,
            };
            state.peers.insert(source, peer_id);
            state.paths.insert(
                peer_id,
                Path {
                    peer: source,
                    peer_id,
                    local_ip: packet.destination,
                    phase: PathPhase::ServerSynAckSent,
                    next_sequence: sequence.wrapping_add(1),
                    expected_sequence: packet.sequence.wrapping_add(1),
                    pending_frames: VecDeque::new(),
                },
            );
            state.pending_packets.push_back(RawTcpPacket {
                source: packet.destination,
                destination: source,
                source_port: local.port(),
                sequence,
                acknowledgement: packet.sequence.wrapping_add(1),
                flags: TcpFlags::SYN | TcpFlags::ACK,
                payload: Vec::new(),
            });
            return state.receiver_waker.take();
        }
        None => return None,
    };
    let inbound_full = state.incoming.len() >= state.queue_capacity;
    let path = state.paths.get_mut(&peer_id)?;
    match (role, path.phase) {
        (FakeTcpRole::Client, PathPhase::ClientSynSent)
            if packet.flags == (TcpFlags::SYN | TcpFlags::ACK)
                && packet.acknowledgement == path.next_sequence =>
        {
            path.expected_sequence = packet.sequence.wrapping_add(1);
            path.phase = PathPhase::Established;
            state.pending_packets.push_back(RawTcpPacket {
                source: path.local_ip,
                destination: source,
                source_port: local.port(),
                sequence: path.next_sequence,
                acknowledgement: path.expected_sequence,
                flags: TcpFlags::ACK,
                payload: Vec::new(),
            });
            queue_pending_frames(path, local.port(), &mut state.pending_packets);
            state.receiver_waker.take()
        }
        (FakeTcpRole::Server, PathPhase::ServerSynAckSent)
            if packet.flags == TcpFlags::ACK
                && packet.sequence == path.expected_sequence
                && packet.acknowledgement == path.next_sequence =>
        {
            path.phase = PathPhase::Established;
            queue_pending_frames(path, local.port(), &mut state.pending_packets);
            None
        }
        (_, PathPhase::Established) if packet.flags & TcpFlags::RST != 0 => {
            state.peers.remove(&source);
            state.paths.remove(&peer_id);
            None
        }
        (_, PathPhase::Established)
            if !packet.payload.is_empty()
                && packet.sequence == path.expected_sequence
                && packet.acknowledgement == path.next_sequence =>
        {
            if inbound_full {
                return None;
            }
            path.expected_sequence = path
                .expected_sequence
                .wrapping_add(packet.payload.len() as u32);
            state.pending_packets.push_back(RawTcpPacket {
                source: path.local_ip,
                destination: source,
                source_port: local.port(),
                sequence: path.next_sequence,
                acknowledgement: path.expected_sequence,
                flags: TcpFlags::ACK,
                payload: Vec::new(),
            });
            state.incoming.push_back(InboundPacket {
                peer_id: path.peer_id,
                frame: packet.payload,
            });
            state.receiver_waker.take()
        }
        _ => None,
    }
}

fn queue_pending_frames(
    path: &mut Path,
    source_port: u16,
    pending_packets: &mut VecDeque<RawTcpPacket>,
) {
    while let Some(payload) = path.pending_frames.pop_front() {
        let sequence = path.next_sequence;
        path.next_sequence = path.next_sequence.wrapping_add(payload.len() as u32);
        pending_packets.push_back(RawTcpPacket {
            source: path.local_ip,
            destination: path.peer,
            source_port,
            sequence,
            acknowledgement: path.expected_sequence,
            flags: TcpFlags::ACK | TcpFlags::PSH,
            payload,
        });
    }
}

fn send_tcp_packet(
    sender: &mut TransportSender,
    raw: RawTcpPacket,
) -> Result<(), LinuxTransportError> {
    let total_length = IPV4_HEADER_LEN + TCP_HEADER_LEN + raw.payload.len();
    let total_length =
        u16::try_from(total_length).map_err(|_| LinuxTransportError::FrameTooLarge)?;
    let mut bytes = vec![0_u8; usize::from(total_length)];
    {
        let mut ip =
            MutableIpv4Packet::new(&mut bytes).expect("IPv4 buffer has fixed minimum size");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_length);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(raw.source);
        ip.set_destination(*raw.destination.ip());
    }
    {
        let mut packet = MutableTcpPacket::new(&mut bytes[IPV4_HEADER_LEN..])
            .expect("TCP buffer has fixed minimum size");
        packet.set_source(raw.source_port);
        packet.set_destination(raw.destination.port());
        packet.set_sequence(raw.sequence);
        packet.set_acknowledgement(raw.acknowledgement);
        packet.set_data_offset(5);
        packet.set_flags(raw.flags);
        packet.set_window(65_535);
        packet.set_payload(&raw.payload);
        packet.set_checksum(ipv4_checksum(
            &packet.to_immutable(),
            &raw.source,
            raw.destination.ip(),
        ));
    }
    let mut ip = MutableIpv4Packet::new(&mut bytes).expect("IPv4 buffer has fixed minimum size");
    ip.set_checksum(0);
    ip.set_checksum(ipv4_header_checksum(&ip.to_immutable()));
    sender
        .send_to(ip, IpAddr::V4(*raw.destination.ip()))
        .map(|_| ())
        .map_err(LinuxTransportError::Send)
}

struct ParsedTcpPacket {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn parse_ipv4_tcp(bytes: &[u8]) -> Option<ParsedTcpPacket> {
    let ip = Ipv4Packet::new(bytes)?;
    if ip.get_version() != 4
        || ip.get_header_length() < 5
        || ip.get_checksum() != ipv4_header_checksum(&ip)
        || ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        || ip.get_fragment_offset() != 0
        || ip.get_flags() & 0x1 != 0
    {
        return None;
    }
    let ip_header_length = usize::from(ip.get_header_length()) * 4;
    let total_length = usize::from(ip.get_total_length());
    if ip_header_length < 20 || total_length < ip_header_length || total_length > bytes.len() {
        return None;
    }
    let tcp = TcpPacket::new(&bytes[ip_header_length..total_length])?;
    let header_length = usize::from(tcp.get_data_offset()) * 4;
    if header_length < TCP_HEADER_LEN || header_length > tcp.packet().len() {
        return None;
    }
    if tcp.get_checksum() != ipv4_checksum(&tcp, &ip.get_source(), &ip.get_destination()) {
        return None;
    }
    Some(ParsedTcpPacket {
        source: ip.get_source(),
        destination: ip.get_destination(),
        source_port: tcp.get_source(),
        destination_port: tcp.get_destination(),
        sequence: tcp.get_sequence(),
        acknowledgement: tcp.get_acknowledgement(),
        flags: tcp.get_flags(),
        payload: tcp.payload().to_vec(),
    })
}

fn peer_id_for(address: SocketAddrV4) -> PeerId {
    let ip = u64::from(u32::from_be_bytes(address.ip().octets()));
    let port = u64::from(address.port());
    PeerId::new((ip << 16) | port)
}

fn random_u32() -> Result<u32, LinuxTransportError> {
    let mut bytes = [0_u8; 4];
    getrandom(&mut bytes)
        .map_err(|error| LinuxTransportError::Socket(io::Error::other(error.to_string())))?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        FakeTcpRole, LinuxFakeTcpConfig, LinuxTransportError, parse_ipv4_tcp, peer_id_for,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum};

    #[test]
    fn client_configuration_requires_ipv4_peer() {
        let config = LinuxFakeTcpConfig {
            role: FakeTcpRole::Client,
            local_addr: "127.0.0.1:3000".parse().unwrap(),
            peer_addr: None,
            local_peer: udp2raw_ng_core::PeerId::new(1),
            queue_capacity: 1,
        };
        assert!(matches!(
            config.validate(),
            Err(LinuxTransportError::MissingClientPeer)
        ));
    }

    #[test]
    fn server_peer_ids_are_stable_per_socket_address() {
        let address = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4096);
        assert_eq!(peer_id_for(address), peer_id_for(address));
        assert_ne!(
            peer_id_for(address),
            peer_id_for(SocketAddrV4::new(*address.ip(), 4097))
        );
    }

    #[test]
    fn server_configuration_has_no_fixed_peer() {
        let config = LinuxFakeTcpConfig::server(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            4096,
        )));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn parser_accepts_a_checksumming_valid_unfragmented_packet() {
        let bytes = ipv4_tcp_packet(b"inner-frame", 0, TcpFlags::ACK | TcpFlags::PSH);
        let parsed = parse_ipv4_tcp(&bytes).expect("packet must parse");
        assert_eq!(parsed.source_port, 40000);
        assert_eq!(parsed.destination_port, 4096);
        assert_eq!(parsed.payload, b"inner-frame");
    }

    #[test]
    fn parser_rejects_fragmented_or_bad_checksum_packets() {
        let mut fragmented = ipv4_tcp_packet(b"frame", 1, TcpFlags::ACK);
        assert!(parse_ipv4_tcp(&fragmented).is_none());
        let last = fragmented.len() - 1;
        fragmented[last] ^= 1;
        assert!(parse_ipv4_tcp(&fragmented).is_none());
    }

    fn ipv4_tcp_packet(payload: &[u8], fragment_offset: u16, flags: u8) -> Vec<u8> {
        let ip_header_len = 20;
        let tcp_header_len = 20;
        let mut bytes = vec![0_u8; ip_header_len + tcp_header_len + payload.len()];
        {
            let mut ip = MutableIpv4Packet::new(&mut bytes).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((ip_header_len + tcp_header_len + payload.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(Ipv4Addr::new(192, 0, 2, 1));
            ip.set_destination(Ipv4Addr::new(198, 51, 100, 2));
            ip.set_fragment_offset(fragment_offset);
        }
        {
            let source = Ipv4Addr::new(192, 0, 2, 1);
            let destination = Ipv4Addr::new(198, 51, 100, 2);
            let mut tcp = MutableTcpPacket::new(&mut bytes[ip_header_len..]).unwrap();
            tcp.set_source(40000);
            tcp.set_destination(4096);
            tcp.set_sequence(7);
            tcp.set_acknowledgement(9);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
            tcp.set_window(65_535);
            tcp.set_payload(payload);
            tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &source, &destination));
        }
        let mut ip = MutableIpv4Packet::new(&mut bytes).unwrap();
        ip.set_checksum(checksum(&ip.to_immutable()));
        bytes
    }
}
