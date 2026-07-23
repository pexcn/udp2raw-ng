# udp2raw-ng

一个以可复用 Rust 库为核心、面向 Linux FakeTCP UDP 数据报隧道的全新项目。

> **当前状态：阶段 5 的轻量协议与托管 UDP 服务切片，不可用于生产或直接部署到不可信公网。** 核心已实现 v4 24 字节固定 envelope、无 heartbeat 的空闲会话、无状态 Cookie、丢包重试和受保护最终确认的 PSK 认证握手、五种受保护 record suite、防重放、握手期/重连期有界数据报队列、按路径 `PeerId` 的基础令牌桶握手限速，以及短期恢复凭据驱动的进程内 conversation 状态迁移；官方库提供基于可替换 transport 的 Tokio UDP client/server harness，并会在恢复时迁移 connected upstream UDP socket 路由。CLI 仍会安全拒绝启动真实隧道。按业务触发重连、独立 conversation handle 映射、Raw socket、AF_PACKET、FakeTCP、worker shard、PMTU 探测、来源 IP 归一化与完整抗洪泛指标、Netfilter RST 抑制尚未实现。

完整需求见 [udp2raw-ng-spec.md](docs/udp2raw-ng-spec.md)，当前实现边界见 [docs/implementation-status.md](docs/implementation-status.md)。

轻量协议计划及剩余的按业务触发重连、独立 conversation handle 映射工作见
[docs/next-stage-plan.md](docs/next-stage-plan.md)。当前实现已迁移到 v4，不会发送 heartbeat。

## Workspace

- `udp2raw-ng-core`：不依赖 Tokio/Linux I/O 的同步安全协议核心。
- `udp2raw-ng-net`：可替换 packet transport、纯内存实现及安全失败的 Linux 占位实现。
- `udp2raw-ng`：官方 CLI 与 Tokio 托管 UDP 服务 API。
- `fuzz`：帧解码 fuzz target。

## 当前可用能力

- 有界、版本化的 v3 帧编码/解码；
- `SessionId` / `ConversationId` 强类型；
- PSK/HMAC-SHA256 transcript 认证握手；
- 来源绑定、短时有效、服务端进程随机密钥保护的无状态握手 Cookie；
- `ClientHello` / `ClientFinish` 定时重试、幂等 server 响应和受保护 `HandshakeAck`；
- HKDF-SHA256 方向密钥和 nonce prefix 派生；
- ChaCha20-Poly1305、XChaCha20-Poly1305、AES-128-GCM、AES-256-GCM；
- `none` 明文加 HMAC-SHA256 的强制认证模式；
- PSK 最小长度检查、日志脱敏与 drop 时清零；
- 4096 位可配置防重放滑动窗口；
- 同步 `ClientEngine` / `ServerEngine` 会话状态机；
- 带过期时间的认证恢复凭据、新 session 密钥建立和跨 session conversation 元数据迁移；
- `SessionResumed` 宿主 action，用于后续 runtime 原子迁移 connected upstream socket 路由键；
- 可嵌入 Tokio UDP client/server harness：有界 transport 收发队列、显式 overload 指标、关闭控制，以及恢复期内保留并在恢复成功时迁移的 connected upstream UDP socket；
- client 握手期/重连期的严格有界、短时 FIFO 数据报队列，以及队满、超时和关闭的显式丢弃 action；
- server 在 Cookie 校验前按 `PeerId` 执行的有界令牌桶握手限速；
- conversation 容量、反向映射、空闲回收和 `(session, conversation)` 隔离基础；
- `PacketTransport`、有界纯内存双端 transport 和托管服务 API 边界；
- `client` / `server` CLI 参数骨架，无配置文件入口。

## 构建与测试

需要 Rust 1.85 或更高版本：

    cargo fmt --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

查看参数：

    cargo run -p udp2raw-ng -- client --help
    cargo run -p udp2raw-ng -- server --help

即使参数有效，非环境检查模式也会以错误退出，因为 Linux FakeTCP 数据面、完整按来源速率限制和 CLI 到托管 UDP 服务的装配尚未实现。

## Fuzz

安装 `cargo-fuzz` 后执行：

    cargo fuzz run decode-wire-frame

## 法律与政策

仅在获得授权的网络和设备上部署。使用者必须遵守所在地法律、网络服务协议、云服务商政策和组织安全政策。本项目不承诺绕过任何网络限制。
