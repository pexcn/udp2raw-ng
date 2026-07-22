# udp2raw-ng

一个以可复用 Rust 库为核心、面向 Linux FakeTCP UDP 数据报隧道的全新项目。

> **当前状态：阶段 2 安全核心，不可用于生产或直接部署到不可信公网。** 平台无关核心已实现 PSK 认证握手、五种受保护 record suite 和防重放；CLI 仍会安全拒绝启动真实隧道。Raw socket、AF_PACKET、FakeTCP、握手丢包恢复、PMTU 探测和 Netfilter RST 抑制尚未实现。

完整需求见 [udp2raw-ng-spec.md](docs/udp2raw-ng-spec.md)，当前实现边界见 [docs/implementation-status.md](docs/implementation-status.md)。

## Workspace

- `udp2raw-ng-core`：不依赖 Tokio/Linux I/O 的同步安全协议核心。
- `udp2raw-ng-net`：可替换 packet transport、纯内存实现及安全失败的 Linux 占位实现。
- `udp2raw-ng`：官方 CLI 与 Tokio 托管服务 API 骨架。
- `fuzz`：帧解码 fuzz target。

## 当前可用能力

- 有界、版本化的 v2 帧编码/解码；
- `SessionId` / `ConversationId` 强类型；
- 三段式 PSK/HMAC-SHA256 transcript 认证握手；
- HKDF-SHA256 方向密钥和 nonce prefix 派生；
- ChaCha20-Poly1305、XChaCha20-Poly1305、AES-128-GCM、AES-256-GCM；
- `none` 明文加 HMAC-SHA256 的强制认证模式；
- PSK 最小长度检查、日志脱敏与 drop 时清零；
- 4096 位可配置防重放滑动窗口；
- 同步 `ClientEngine` / `ServerEngine` 会话状态机；
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

即使参数有效，非环境检查模式也会以错误退出，因为 Linux FakeTCP 数据面和公网握手抗洪泛/丢包恢复尚未实现。

## Fuzz

安装 `cargo-fuzz` 后执行：

    cargo fuzz run decode-wire-frame

## 法律与政策

仅在获得授权的网络和设备上部署。使用者必须遵守所在地法律、网络服务协议、云服务商政策和组织安全政策。本项目不承诺绕过任何网络限制。
