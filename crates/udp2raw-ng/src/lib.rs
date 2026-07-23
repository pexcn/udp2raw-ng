//! Tokio managed services for embedding `udp2raw-ng`.
//!
//! The services manage ordinary UDP sockets while a caller-provided
//! [`PacketTransport`] carries authenticated inner tunnel frames. This is a
//! production-useful UDP harness, but it deliberately does **not** claim to
//! implement the future Linux FakeTCP outer transport.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, RwLock, mpsc};
use tokio::time::MissedTickBehavior;
use udp2raw_ng_core::{
    ClientEngine, ConversationId, EngineConfig, EngineError, PeerId, Psk, Role, ServerEngine,
    SessionId, TunnelAction, TunnelEvent,
};
use udp2raw_ng_net::{InboundPacket, OutboundPacket, PacketTransport};

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub engine: EngineConfig,
    /// Maximum packets waiting between the transport poller and protocol task.
    pub queue_capacity: usize,
    /// Reserved for the future session-sharded FakeTCP runtime. This UDP
    /// harness has one engine owner and therefore requires one worker.
    pub packet_workers: usize,
}

impl ServiceConfig {
    pub fn validate(&self) -> Result<(), ServiceError> {
        self.engine.validate()?;
        if self.queue_capacity == 0 {
            return Err(ServiceError::ZeroQueueCapacity);
        }
        if self.packet_workers != 1 {
            return Err(ServiceError::UnsupportedPacketWorkerCount(
                self.packet_workers,
            ));
        }
        Ok(())
    }
}

/// Explicit bounded-queue and error counters for the managed harness.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceMetrics {
    pub transport_queue_dropped: u64,
    pub client_datagrams_dropped: u64,
    pub upstream_datagrams_dropped: u64,
    pub transport_errors: u64,
    pub engine_errors: u64,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    CoreConfig(#[from] udp2raw_ng_core::ConfigError),
    #[error("queue capacity must be greater than zero")]
    ZeroQueueCapacity,
    #[error("the UDP managed-service harness supports exactly one packet worker; got {0}")]
    UnsupportedPacketWorkerCount(usize),
    #[error("service role does not match its engine configuration")]
    InvalidEngineRole,
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct ServiceBuilder<T> {
    config: ServiceConfig,
    transport: T,
}

impl<T> ServiceBuilder<T>
where
    T: PacketTransport + Send + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    pub fn new(config: ServiceConfig, transport: T) -> Self {
        Self { config, transport }
    }

    pub fn build_client(
        self,
        psk: Psk,
        server_peer: PeerId,
        listen: SocketAddr,
    ) -> Result<ClientService<T>, ServiceError> {
        self.config.validate()?;
        if self.config.engine.role != Role::Client {
            return Err(ServiceError::InvalidEngineRole);
        }
        Ok(ClientService {
            config: self.config.clone(),
            transport: self.transport,
            engine: Arc::new(Mutex::new(ClientEngine::new(
                self.config.engine,
                psk,
                server_peer,
            )?)),
            listen,
            shutdown: Arc::new(Notify::new()),
            metrics: Arc::new(Mutex::new(ServiceMetrics::default())),
        })
    }

    pub fn build_server(
        self,
        psk: Psk,
        listen: SocketAddr,
        upstream: SocketAddr,
    ) -> Result<ServerService<T>, ServiceError> {
        self.config.validate()?;
        if self.config.engine.role != Role::Server {
            return Err(ServiceError::InvalidEngineRole);
        }
        Ok(ServerService {
            config: self.config.clone(),
            transport: self.transport,
            engine: Arc::new(Mutex::new(ServerEngine::new(self.config.engine, psk)?)),
            listen,
            upstream,
            shutdown: Arc::new(Notify::new()),
            metrics: Arc::new(Mutex::new(ServiceMetrics::default())),
        })
    }
}

/// Handle used by a host to request graceful managed-service shutdown.
#[derive(Clone, Debug)]
pub struct ShutdownHandle(Arc<Notify>);

impl ShutdownHandle {
    pub fn shutdown(&self) {
        self.0.notify_waiters();
    }
}

pub struct ClientService<T> {
    config: ServiceConfig,
    transport: T,
    engine: Arc<Mutex<ClientEngine>>,
    listen: SocketAddr,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ServiceMetrics>>,
}

impl<T> ClientService<T>
where
    T: PacketTransport + Send + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(Arc::clone(&self.shutdown))
    }

    pub async fn metrics(&self) -> ServiceMetrics {
        *self.metrics.lock().await
    }

    /// Binds the local UDP listener and serves it until [`ShutdownHandle`] is
    /// signalled. Transport output and input are bounded independently.
    pub async fn run(self) -> Result<(), ServiceError> {
        let socket = Arc::new(UdpSocket::bind(self.listen).await?);
        let transport = Arc::new(StdMutex::new(self.transport));
        let (packet_tx, mut packet_rx) = mpsc::channel(self.config.queue_capacity);
        let (send_tx, send_rx) = mpsc::channel(self.config.queue_capacity);
        let shutdown = Arc::clone(&self.shutdown);
        let metrics = Arc::clone(&self.metrics);
        let poll_task = spawn_transport_poller(
            Arc::clone(&transport),
            packet_tx,
            Arc::clone(&shutdown),
            Arc::clone(&metrics),
        );
        let send_task =
            spawn_transport_sender(transport, send_rx, shutdown.clone(), metrics.clone());
        let initial = self
            .engine
            .lock()
            .await
            .handle(TunnelEvent::Start, Instant::now())?;
        execute_client_actions(&socket, &send_tx, &self.metrics, initial).await?;
        let mut timer = tokio::time::interval(Duration::from_millis(50));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut buffer = vec![0_u8; udp2raw_ng_core::MAX_FRAME_PAYLOAD + 1];
        let result = loop {
            tokio::select! {
                _ = self.shutdown.notified() => break Ok(()),
                _ = timer.tick() => {
                    let now = Instant::now();
                    let actions = self.engine.lock().await.handle(TunnelEvent::TimeAdvanced(now), now)?;
                    execute_client_actions(&socket, &send_tx, &self.metrics, actions).await?;
                }
                received = socket.recv_from(&mut buffer) => {
                    let (length, local_peer) = received?;
                    if length > udp2raw_ng_core::MAX_FRAME_PAYLOAD {
                        self.metrics.lock().await.client_datagrams_dropped += 1;
                        continue;
                    }
                    let now = Instant::now();
                    let actions = self.engine.lock().await.handle(TunnelEvent::ClientDatagram {
                        local_peer, payload: buffer[..length].to_vec(),
                    }, now)?;
                    execute_client_actions(&socket, &send_tx, &self.metrics, actions).await?;
                }
                packet = packet_rx.recv() => match packet {
                    Some(packet) => {
                        let now = Instant::now();
                        let actions = self.engine.lock().await.handle(TunnelEvent::TunnelFrame {
                            peer_id: packet.peer_id, bytes: packet.frame,
                        }, now)?;
                        execute_client_actions(&socket, &send_tx, &self.metrics, actions).await?;
                    }
                    None => break Ok(()),
                },
            }
        };
        self.shutdown.notify_waiters();
        poll_task.abort();
        send_task.abort();
        result
    }
}

pub struct ServerService<T> {
    config: ServiceConfig,
    transport: T,
    engine: Arc<Mutex<ServerEngine>>,
    listen: SocketAddr,
    upstream: SocketAddr,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ServiceMetrics>>,
}

impl<T> ServerService<T>
where
    T: PacketTransport + Send + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(Arc::clone(&self.shutdown))
    }

    pub async fn metrics(&self) -> ServiceMetrics {
        *self.metrics.lock().await
    }

    /// Runs a server-side UDP upstream harness. A connected upstream socket is
    /// retained per `(session, conversation)` through the valid recovery
    /// window, then moved atomically when `SessionResumed` is observed.
    pub async fn run(self) -> Result<(), ServiceError> {
        // Detect an invalid requested listener early. FakeTCP ownership remains
        // with the future Linux transport adapter, so this socket is not used
        // as a raw-packet listener.
        drop(UdpSocket::bind(self.listen).await?);
        let transport = Arc::new(StdMutex::new(self.transport));
        let (packet_tx, mut packet_rx) = mpsc::channel(self.config.queue_capacity);
        let (send_tx, send_rx) = mpsc::channel(self.config.queue_capacity);
        let poll_task = spawn_transport_poller(
            Arc::clone(&transport),
            packet_tx,
            Arc::clone(&self.shutdown),
            Arc::clone(&self.metrics),
        );
        let send_task = spawn_transport_sender(
            transport,
            send_rx,
            Arc::clone(&self.shutdown),
            Arc::clone(&self.metrics),
        );
        let routes = Arc::new(RwLock::new(HashMap::new()));
        let mut route_tasks = HashMap::new();
        let mut timer = tokio::time::interval(Duration::from_millis(50));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                _ = self.shutdown.notified() => break Ok(()),
                _ = timer.tick() => {
                    let now = Instant::now();
                    let actions = self.engine.lock().await.handle(TunnelEvent::TimeAdvanced(now), now)?;
                    execute_server_actions(
                        actions, &self.engine, &send_tx, &self.metrics, self.upstream,
                        &self.shutdown, &routes, &mut route_tasks,
                    ).await?;
                }
                packet = packet_rx.recv() => match packet {
                    Some(packet) => {
                        let now = Instant::now();
                        let actions = self.engine.lock().await.handle(TunnelEvent::TunnelFrame {
                            peer_id: packet.peer_id, bytes: packet.frame,
                        }, now)?;
                        execute_server_actions(
                            actions, &self.engine, &send_tx, &self.metrics, self.upstream,
                            &self.shutdown, &routes, &mut route_tasks,
                        ).await?;
                    }
                    None => break Ok(()),
                },
            }
        };
        self.shutdown.notify_waiters();
        poll_task.abort();
        send_task.abort();
        for (_, task) in route_tasks {
            task.abort();
        }
        result
    }
}

fn spawn_transport_poller<T>(
    transport: Arc<StdMutex<T>>,
    packet_tx: mpsc::Sender<InboundPacket>,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ServiceMetrics>>,
) -> tokio::task::JoinHandle<()>
where
    T: PacketTransport + Send + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.notified() => return,
                received = std::future::poll_fn(|context| transport.lock().expect("transport poisoned").poll_receive(context)) => {
                    match received {
                        Ok(packet) => match packet_tx.try_send(packet) {
                            Ok(()) => {},
                            Err(mpsc::error::TrySendError::Full(_)) => metrics.lock().await.transport_queue_dropped += 1,
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        },
                        Err(_) => { metrics.lock().await.transport_errors += 1; return; }
                    }
                }
            }
        }
    })
}

fn spawn_transport_sender<T>(
    transport: Arc<StdMutex<T>>,
    mut packets: mpsc::Receiver<OutboundPacket>,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ServiceMetrics>>,
) -> tokio::task::JoinHandle<()>
where
    T: PacketTransport + Send + 'static,
    T::Error: std::fmt::Display + Send + Sync + 'static,
{
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.notified() => return,
                packet = packets.recv() => match packet {
                    Some(packet) => if transport.lock().expect("transport poisoned").send(packet).is_err() {
                        metrics.lock().await.transport_errors += 1;
                    },
                    None => return,
                },
            }
        }
    })
}

async fn enqueue_packet(
    sender: &mpsc::Sender<OutboundPacket>,
    metrics: &Arc<Mutex<ServiceMetrics>>,
    packet: OutboundPacket,
) {
    if sender.try_send(packet).is_err() {
        metrics.lock().await.transport_queue_dropped += 1;
    }
}

async fn execute_client_actions(
    socket: &UdpSocket,
    sender: &mpsc::Sender<OutboundPacket>,
    metrics: &Arc<Mutex<ServiceMetrics>>,
    actions: Vec<TunnelAction>,
) -> Result<(), ServiceError> {
    for action in actions {
        match action {
            TunnelAction::SendTunnelFrame { peer_id, bytes } => {
                enqueue_packet(
                    sender,
                    metrics,
                    OutboundPacket {
                        peer_id,
                        frame: bytes,
                    },
                )
                .await;
            }
            TunnelAction::DeliverToClient {
                local_peer,
                payload,
            } => {
                socket.send_to(&payload, local_peer).await?;
            }
            TunnelAction::ClientDatagramDropped { .. } => {
                metrics.lock().await.client_datagrams_dropped += 1;
            }
            TunnelAction::ScheduleTimer(_)
            | TunnelAction::SessionEstablished { .. }
            | TunnelAction::SessionResumed { .. }
            | TunnelAction::SessionClosed { .. }
            | TunnelAction::SessionRecoveryExpired { .. }
            | TunnelAction::ConversationOpened { .. }
            | TunnelAction::ConversationClosed { .. }
            | TunnelAction::DeliverToUpstream { .. } => {}
        }
    }
    Ok(())
}

type RouteKey = (SessionId, ConversationId);
type Routes = Arc<RwLock<HashMap<RouteKey, Arc<UdpSocket>>>>;

#[allow(clippy::too_many_arguments)]
async fn execute_server_actions(
    actions: Vec<TunnelAction>,
    engine: &Arc<Mutex<ServerEngine>>,
    sender: &mpsc::Sender<OutboundPacket>,
    metrics: &Arc<Mutex<ServiceMetrics>>,
    upstream: SocketAddr,
    shutdown: &Arc<Notify>,
    routes: &Routes,
    route_tasks: &mut HashMap<RouteKey, tokio::task::JoinHandle<()>>,
) -> Result<(), ServiceError> {
    for action in actions {
        match action {
            TunnelAction::SendTunnelFrame { peer_id, bytes } => {
                enqueue_packet(
                    sender,
                    metrics,
                    OutboundPacket {
                        peer_id,
                        frame: bytes,
                    },
                )
                .await;
            }
            TunnelAction::DeliverToUpstream {
                session_id,
                conversation_id,
                payload,
            } => {
                let key = (session_id, conversation_id);
                ensure_upstream_route(
                    key,
                    engine,
                    sender,
                    metrics,
                    upstream,
                    shutdown,
                    routes,
                    route_tasks,
                )
                .await?;
                let socket = routes.read().await.get(&key).cloned();
                if let Some(socket) = socket {
                    socket.send(&payload).await?;
                } else {
                    metrics.lock().await.upstream_datagrams_dropped += 1;
                }
            }
            TunnelAction::SessionResumed {
                old_session_id,
                new_session_id,
                ..
            } => {
                migrate_session_routes(
                    old_session_id,
                    new_session_id,
                    engine,
                    sender,
                    metrics,
                    shutdown,
                    routes,
                    route_tasks,
                )
                .await?;
            }
            TunnelAction::SessionRecoveryExpired { session_id } => {
                remove_session_routes(session_id, routes, route_tasks).await;
            }
            TunnelAction::ConversationClosed {
                session_id: Some(session_id),
                conversation_id,
            } => {
                remove_route((session_id, conversation_id), routes, route_tasks).await;
            }
            TunnelAction::ScheduleTimer(_)
            | TunnelAction::SessionEstablished { .. }
            | TunnelAction::SessionClosed { .. }
            | TunnelAction::ConversationOpened { .. }
            | TunnelAction::ClientDatagramDropped { .. }
            | TunnelAction::DeliverToClient { .. }
            | TunnelAction::ConversationClosed {
                session_id: None, ..
            } => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ensure_upstream_route(
    key: RouteKey,
    engine: &Arc<Mutex<ServerEngine>>,
    sender: &mpsc::Sender<OutboundPacket>,
    metrics: &Arc<Mutex<ServiceMetrics>>,
    upstream: SocketAddr,
    shutdown: &Arc<Notify>,
    routes: &Routes,
    route_tasks: &mut HashMap<RouteKey, tokio::task::JoinHandle<()>>,
) -> Result<(), ServiceError> {
    if routes.read().await.contains_key(&key) {
        return Ok(());
    }
    let bind_address = match upstream.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = Arc::new(UdpSocket::bind(bind_address).await?);
    socket.connect(upstream).await?;
    routes.write().await.insert(key, Arc::clone(&socket));
    let task = spawn_upstream_receiver(
        key,
        socket,
        Arc::clone(engine),
        sender.clone(),
        Arc::clone(metrics),
        Arc::clone(shutdown),
        Arc::clone(routes),
    );
    route_tasks.insert(key, task);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_upstream_receiver(
    key: RouteKey,
    socket: Arc<UdpSocket>,
    engine: Arc<Mutex<ServerEngine>>,
    sender: mpsc::Sender<OutboundPacket>,
    metrics: Arc<Mutex<ServiceMetrics>>,
    shutdown: Arc<Notify>,
    routes: Routes,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; udp2raw_ng_core::MAX_FRAME_PAYLOAD + 1];
        loop {
            tokio::select! {
                _ = shutdown.notified() => return,
                received = socket.recv(&mut buffer) => match received {
                    Ok(length) => {
                        if !routes.read().await.contains_key(&key) { return; }
                        if length > udp2raw_ng_core::MAX_FRAME_PAYLOAD {
                            metrics.lock().await.upstream_datagrams_dropped += 1;
                            continue;
                        }
                        let now = Instant::now();
                        match engine.lock().await.handle(TunnelEvent::ServerDatagram {
                            session_id: key.0, conversation_id: key.1, payload: buffer[..length].to_vec(),
                        }, now) {
                            Ok(actions) => for action in actions {
                                if let TunnelAction::SendTunnelFrame { peer_id, bytes } = action {
                                    enqueue_packet(&sender, &metrics, OutboundPacket { peer_id, frame: bytes }).await;
                                }
                            },
                            Err(_) => { metrics.lock().await.engine_errors += 1; return; }
                        }
                    }
                    Err(_) => { metrics.lock().await.upstream_datagrams_dropped += 1; return; }
                },
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn migrate_session_routes(
    old_session_id: SessionId,
    new_session_id: SessionId,
    engine: &Arc<Mutex<ServerEngine>>,
    sender: &mpsc::Sender<OutboundPacket>,
    metrics: &Arc<Mutex<ServiceMetrics>>,
    shutdown: &Arc<Notify>,
    routes: &Routes,
    route_tasks: &mut HashMap<RouteKey, tokio::task::JoinHandle<()>>,
) -> Result<(), ServiceError> {
    let moved = {
        let mut route_map = routes.write().await;
        let moved: Vec<_> = route_map
            .iter()
            .filter_map(|((session_id, conversation_id), socket)| {
                (*session_id == old_session_id).then_some((*conversation_id, Arc::clone(socket)))
            })
            .collect();
        for (conversation_id, socket) in &moved {
            route_map.remove(&(old_session_id, *conversation_id));
            route_map.insert((new_session_id, *conversation_id), Arc::clone(socket));
        }
        moved
    };
    for (conversation_id, socket) in moved {
        let old_key = (old_session_id, conversation_id);
        let new_key = (new_session_id, conversation_id);
        if let Some(task) = route_tasks.remove(&old_key) {
            task.abort();
        }
        let task = spawn_upstream_receiver(
            new_key,
            socket,
            Arc::clone(engine),
            sender.clone(),
            Arc::clone(metrics),
            Arc::clone(shutdown),
            Arc::clone(routes),
        );
        route_tasks.insert(new_key, task);
    }
    Ok(())
}

async fn remove_session_routes(
    session_id: SessionId,
    routes: &Routes,
    route_tasks: &mut HashMap<RouteKey, tokio::task::JoinHandle<()>>,
) {
    let keys: Vec<_> = routes
        .read()
        .await
        .keys()
        .copied()
        .filter(|(candidate, _)| *candidate == session_id)
        .collect();
    for key in keys {
        remove_route(key, routes, route_tasks).await;
    }
}

async fn remove_route(
    key: RouteKey,
    routes: &Routes,
    route_tasks: &mut HashMap<RouteKey, tokio::task::JoinHandle<()>>,
) {
    routes.write().await.remove(&key);
    if let Some(task) = route_tasks.remove(&key) {
        task.abort();
    }
}
