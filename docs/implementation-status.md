# 当前实施状态

## 本轮目标

本轮将平台无关核心从“仅有结构校验的明文帧脚手架”推进到可由纯内存或自定义可信 transport 驱动的认证会话：固化三段式 PSK 握手、方向密钥派生、受保护 record layer、防重放入口和有界内存 transport。真实 Linux FakeTCP 数据面仍不在本轮范围内。

## 已实现

### 工程与 API

- Cargo workspace 和三个 crate 的单向依赖关系；
- 平台无关、同步、事件驱动的 `ClientEngine` / `ServerEngine`；
- `PeerId` transport 路由标识，以及带目标/来源 peer 的 tunnel action/event；
- `Idle`、`Handshaking`、`Ready`、`Closed` 会话状态模型；
- conversation 容量、空闲回收、反向映射和 `(session, conversation)` 隔离；
- PSK 长度限制、调试输出脱敏和 drop 时清零；
- 协议版本提升到 v2，旧的 v1 未认证帧不会被接受。

### 握手与密钥派生

- `ClientHello -> ServerHello -> ClientFinish` 三段式 PSK 认证握手；
- server hello 和 client finish 的 HMAC-SHA256 transcript 认证；
- cipher suite、session ID、client/server nonce、session salt 和握手 transcript 的绑定；
- HKDF-SHA256 方向密钥与 nonce prefix 派生；
- client-to-server / server-to-client 方向隔离，以及 record key / nonce prefix 用途隔离；
- cipher suite 不一致时明确拒绝，不做隐式降级；
- 全局有界 pending handshake、握手超时回收和已认证 session 容量限制；
- server 只有在验证有效 `ClientFinish` 后才创建已认证 session。

### Record layer

- ChaCha20-Poly1305；
- XChaCha20-Poly1305；
- AES-128-GCM；
- AES-256-GCM；
- `none` 认证明文模式：payload 不加密，但使用完整 HMAC-SHA256 tag；
- 每方向独立 packet number 和 nonce prefix；
- header、协议版本、session、epoch、packet number、frame type、conversation、方向、cipher suite 和长度均绑定到认证上下文；
- 非零 epoch、错误 session、错误方向、截断 tag、非法 record 类型和畸形长度均拒绝；
- packet number 溢出时安全失败并要求新 session；
- 防重放滑动窗口已接入唯一 record 打开入口，顺序固定为“先认证、再更新 replay window、最后返回明文”；
- 认证失败不会推进 replay window，也不会创建 conversation 或投递明文。

### Transport 与测试

- `PacketTransport` 的有界纯内存双端实现；
- FIFO 双向传输、`PeerId` 保留、队列满错误、peer drop/关闭行为和 waker 唤醒；
- 五种 cipher suite 的完整内存握手与双向数据 round-trip；
- 错 PSK、suite 不一致、密文/tag 篡改、重复 record、认证失败后合法同 packet number 仍可接受的测试；
- 非 `Ready` 状态业务数据拒绝；
- 基础帧所有截断位置和 trailing bytes 拒绝测试；
- 帧解码 fuzz target；
- `cargo fmt --check`、严格 Clippy 和 workspace 测试作为验收项。

## 明确未实现

- 第四段 server 握手确认、握手重试、丢包恢复和无状态 cookie；
- 面向公网握手洪泛的完整防护、按来源限速和 per-peer pending 限制；
- session 恢复凭据、stable client identity 和密钥轮换/非零 epoch；
- heartbeat、session 超时、自动重连和恢复；
- AES 硬件加速实际启用/软件回退的可观测指标；
- PMTU 探测、可信 ICMP 关联和 MTU 事件；
- worker shard、有界 Tokio 运行时队列和真实 UDP upstream；
- FakeTCP 状态机和 IP/TCP 报文编解码；
- Raw socket、AF_PACKET、cBPF、route/neighbor Netlink；
- nftables Netlink 和 legacy iptables 后端；
- IPv6 Linux transport。

## 当前安全边界

平台无关的 v2 内层协议已经提供 PSK 身份证明、完整性、防重放，以及除 `none` 外的机密性；`none` 只暴露 payload 内容，不会关闭握手认证、record 认证或防重放。未经认证的网络帧不能创建已认证 session、创建 conversation 或投递应用明文。

但当前实现还不能宣称适合直接部署到不可信公网：三段式握手中 client 发出 `ClientFinish` 后即进入本地 `Ready`，尚无 server 最终确认或丢包重试；server 对 `ClientHello` 会分配有界短期状态并执行密码运算，尚无无状态 cookie 和来源速率限制。`PeerId` 由宿主分配，仅用于路由，不是安全身份。

真实 Linux tunnel 仍不可用。CLI 的正常运行路径继续安全拒绝启动，`LinuxFakeTcpTransport` 的所有操作继续返回 `NotImplemented`，不会将安全核心静默降级为裸网络传输。

## 下一阶段建议

1. 增加握手重试、server 最终确认/首个受保护 record 隐式确认、超时和无状态 cookie；
2. 实现 heartbeat、session 生命周期、重连和恢复凭据，并为 epoch/key rotation 固化状态机；
3. 实现 Tokio worker shard、有界队列和纯 UDP upstream harness；
4. 开始 Linux FakeTCP 报文编解码、校验和、AF_PACKET/raw socket 与 cBPF；
5. 最后接入 route/neighbor Netlink、PMTU 和 Netfilter RST guard。

当前阶段不需要 root、`CAP_NET_RAW`、network namespace 或 Netfilter 权限。真实 Linux 网络层阶段才需要这些条件。
