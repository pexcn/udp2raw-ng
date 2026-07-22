//! Tokio managed-service scaffolding for embedding `udp2raw-ng`.
//!
//! The service lifecycle is defined, but production packet I/O remains disabled
//! until the Linux FakeTCP adapter and worker runtime are implemented. The core
//! authenticated record layer can already be driven by custom transports.

use std::marker::PhantomData;

use thiserror::Error;
use udp2raw_ng_core::EngineConfig;
use udp2raw_ng_net::PacketTransport;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub engine: EngineConfig,
    pub queue_capacity: usize,
    pub packet_workers: usize,
}

impl ServiceConfig {
    pub fn validate(&self) -> Result<(), ServiceError> {
        self.engine.validate()?;
        if self.queue_capacity == 0 {
            return Err(ServiceError::ZeroQueueCapacity);
        }
        if self.packet_workers == 0 {
            return Err(ServiceError::ZeroPacketWorkers);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    CoreConfig(#[from] udp2raw_ng_core::ConfigError),
    #[error("queue capacity must be greater than zero")]
    ZeroQueueCapacity,
    #[error("packet worker count must be greater than zero")]
    ZeroPacketWorkers,
    #[error("managed FakeTCP services are not implemented in this milestone")]
    NotImplemented,
}

pub struct ServiceBuilder<T> {
    config: ServiceConfig,
    transport: T,
}

impl<T> ServiceBuilder<T>
where
    T: PacketTransport + Send + 'static,
    T::Error: Send + Sync + 'static,
{
    pub fn new(config: ServiceConfig, transport: T) -> Self {
        Self { config, transport }
    }

    pub fn build_client(self) -> Result<ClientService<T>, ServiceError> {
        self.config.validate()?;
        Ok(ClientService {
            config: self.config,
            transport: self.transport,
            _not_sync: PhantomData,
        })
    }

    pub fn build_server(self) -> Result<ServerService<T>, ServiceError> {
        self.config.validate()?;
        Ok(ServerService {
            config: self.config,
            transport: self.transport,
            _not_sync: PhantomData,
        })
    }
}

pub struct ClientService<T> {
    config: ServiceConfig,
    transport: T,
    _not_sync: PhantomData<*mut ()>,
}

impl<T> ClientService<T>
where
    T: PacketTransport,
{
    pub async fn run(self) -> Result<(), ServiceError> {
        let Self {
            config,
            transport,
            _not_sync: _,
        } = self;
        let _ = (config, transport);
        Err(ServiceError::NotImplemented)
    }
}

pub struct ServerService<T> {
    config: ServiceConfig,
    transport: T,
    _not_sync: PhantomData<*mut ()>,
}

impl<T> ServerService<T>
where
    T: PacketTransport,
{
    pub async fn run(self) -> Result<(), ServiceError> {
        let Self {
            config,
            transport,
            _not_sync: _,
        } = self;
        let _ = (config, transport);
        Err(ServiceError::NotImplemented)
    }
}
