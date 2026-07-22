use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use udp2raw_ng_core::{CipherSuite, Psk};

#[derive(Debug, Parser)]
#[command(name = "udp2raw-ng", version, about)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Listen for local UDP datagrams and tunnel them to a server.
    Client(ClientArgs),
    /// Receive tunnel frames and forward datagrams to a UDP upstream.
    Server(ServerArgs),
}

#[derive(Debug, Args)]
struct ClientArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// Remote FakeTCP endpoint.
    #[arg(long)]
    peer: SocketAddr,

    /// Force the outer source IP instead of route selection.
    #[arg(long)]
    source_ip: Option<IpAddr>,

    /// Force the outer source port. Reduces path recovery flexibility.
    #[arg(long)]
    source_port: Option<NonZeroU16>,

    #[arg(long, default_value_t = 750)]
    heartbeat_ms: u64,

    #[arg(long, default_value_t = 10)]
    session_timeout_secs: u64,

    #[arg(long)]
    reconnect: bool,
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[command(flatten)]
    common: CommonArgs,

    /// Fixed UDP upstream endpoint.
    #[arg(long)]
    upstream: SocketAddr,

    #[arg(long, default_value_t = 64)]
    handshake_limit_per_ip: usize,

    #[arg(long, default_value_t = 300)]
    session_idle_secs: u64,
}

#[derive(Debug, Args)]
struct CommonArgs {
    #[arg(long)]
    listen: SocketAddr,

    #[arg(long, value_name = "PATH")]
    secret_file: Option<PathBuf>,

    #[arg(long, value_name = "VARIABLE")]
    secret_env: Option<String>,

    #[arg(long)]
    secret_stdin: bool,

    /// Unsafe for production because process listings and shell history may expose it.
    #[arg(long, value_name = "VALUE")]
    secret: Option<String>,

    #[arg(long, value_enum, default_value_t = CryptoArg::ChaCha20Poly1305)]
    crypto: CryptoArg,

    #[arg(long)]
    bind_interface: Option<String>,

    #[arg(long, default_value_t = default_workers())]
    workers: usize,

    #[arg(long, default_value_t = default_workers())]
    packet_workers: usize,

    #[arg(long, default_value_t = 1)]
    io_threads: usize,

    #[arg(long, default_value_t = 1024)]
    queue_capacity: usize,

    #[arg(long, default_value_t = 4096)]
    socket_buffer_kib: usize,

    #[arg(long, value_enum, default_value_t = MtuProbeArg::Auto)]
    mtu_probe: MtuProbeArg,

    #[arg(long, default_value_t = 4096)]
    max_sessions: usize,

    #[arg(long, default_value_t = 1024)]
    max_pending_handshakes: usize,

    #[arg(long, default_value_t = 1024)]
    max_conversations: usize,

    #[arg(long, default_value_t = 180)]
    conversation_idle_secs: u64,

    #[arg(long, default_value_t = 64)]
    ttl: u8,

    #[arg(long, default_value_t = 64)]
    hop_limit: u8,

    #[arg(long, value_enum, default_value_t = LogLevelArg::Info)]
    log_level: LogLevelArg,

    #[arg(long, value_enum, default_value_t = RstGuardArg::Auto)]
    rst_guard: RstGuardArg,

    #[arg(long, value_enum, default_value_t = RstLifecycleArg::Managed)]
    rst_guard_lifecycle: RstLifecycleArg,

    #[arg(long)]
    check_environment: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CryptoArg {
    #[value(name = "chacha20poly1305")]
    ChaCha20Poly1305,
    #[value(name = "xchacha20poly1305")]
    XChaCha20Poly1305,
    #[value(name = "aes128gcm")]
    Aes128Gcm,
    #[value(name = "aes256gcm")]
    Aes256Gcm,
    None,
}

impl From<CryptoArg> for CipherSuite {
    fn from(value: CryptoArg) -> Self {
        match value {
            CryptoArg::ChaCha20Poly1305 => Self::ChaCha20Poly1305,
            CryptoArg::XChaCha20Poly1305 => Self::XChaCha20Poly1305,
            CryptoArg::Aes128Gcm => Self::Aes128Gcm,
            CryptoArg::Aes256Gcm => Self::Aes256Gcm,
            CryptoArg::None => Self::NoneAuthenticated,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MtuProbeArg {
    Auto,
    Off,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogLevelArg {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevelArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RstGuardArg {
    Auto,
    Nftables,
    Iptables,
    Manual,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RstLifecycleArg {
    Managed,
    Manual,
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1)
        .min(32)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let common = match &cli.command {
        Command::Client(args) => &args.common,
        Command::Server(args) => &args.common,
    };
    init_tracing(common.log_level);

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error!(error = %message, "startup failed");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let common = match &cli.command {
        Command::Client(args) => &args.common,
        Command::Server(args) => &args.common,
    };
    validate_common(common)?;
    let psk = read_psk(common)?;
    let suite = CipherSuite::from(common.crypto);

    if suite == CipherSuite::NoneAuthenticated {
        warn!("crypto=none exposes UDP payload contents; authentication remains mandatory");
    }
    if common.rst_guard == RstGuardArg::Manual {
        warn!("manual RST guard requires an independently verified administrator-managed rule");
    }

    if common.check_environment {
        print_environment_scaffold(common, suite, psk.len());
        return Ok(());
    }

    info!(
        cipher_suite = %suite,
        workers = common.workers,
        packet_workers = common.packet_workers,
        "configuration accepted"
    );
    Err("production execution is intentionally disabled: FakeTCP, AF_PACKET, Netfilter, managed runtime services, and complete source rate limiting are not implemented yet".to_owned())
}

fn validate_common(common: &CommonArgs) -> Result<(), String> {
    let secret_sources = usize::from(common.secret_file.is_some())
        + usize::from(common.secret_env.is_some())
        + usize::from(common.secret_stdin)
        + usize::from(common.secret.is_some());
    if secret_sources != 1 {
        return Err(
            "exactly one of --secret-file, --secret-env, --secret-stdin, or --secret is required"
                .to_owned(),
        );
    }
    if common.workers == 0
        || common.packet_workers == 0
        || common.io_threads == 0
        || common.queue_capacity == 0
    {
        return Err("worker counts and queue capacity must be greater than zero".to_owned());
    }
    if common.ttl == 0 || common.hop_limit == 0 {
        return Err("--ttl and --hop-limit must be in 1..=255".to_owned());
    }
    Ok(())
}

fn read_psk(common: &CommonArgs) -> Result<Psk, String> {
    let bytes = if let Some(path) = &common.secret_file {
        warn_if_secret_file_is_broad(path);
        fs::read(path).map_err(|error| format!("failed to read secret file: {error}"))?
    } else if let Some(variable) = &common.secret_env {
        std::env::var_os(variable)
            .ok_or_else(|| format!("secret environment variable {variable} is not set"))?
            .as_encoded_bytes()
            .to_vec()
    } else if common.secret_stdin {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read secret from stdin: {error}"))?;
        bytes
    } else if let Some(value) = &common.secret {
        warn!("--secret may expose the PSK through process listings or shell history");
        value.as_bytes().to_vec()
    } else {
        return Err("no secret source configured".to_owned());
    };
    let bytes = trim_line_ending(bytes);
    Psk::new(bytes).map_err(|error| error.to_string())
}

fn trim_line_ending(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

#[cfg(unix)]
fn warn_if_secret_file_is_broad(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    match fs::metadata(path) {
        Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
            warn!(path = %path.display(), "secret file is accessible by group or other users");
        }
        Ok(_) => {}
        Err(error) => {
            warn!(path = %path.display(), %error, "could not inspect secret file permissions")
        }
    }
}

#[cfg(not(unix))]
fn warn_if_secret_file_is_broad(_path: &PathBuf) {}

fn init_tracing(level: LogLevelArg) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn print_environment_scaffold(common: &CommonArgs, suite: CipherSuite, psk_length: usize) {
    info!(os = std::env::consts::OS, "environment check");
    info!(listen = %common.listen, cipher_suite = %suite, psk_length, "validated basic configuration");
    info!(mtu_probe = ?common.mtu_probe, rst_guard = ?common.rst_guard, "requested adapters");
    warn!(
        "raw socket, AF_PACKET, route MTU, capability, and Netfilter checks are pending implementation"
    );
}
