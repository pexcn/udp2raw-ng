# 当前实施状态

## 本轮目标

本轮将平台无关核心推进到基础 session 生命周期：在可靠、非乐观的 v3 认证握手之上增加认证 heartbeat、client session 超时、自动/手动重连状态和 server 空闲 session 回收。恢复凭据和 stable identity 尚未实现，因此重连会建立新的安全 session，但 client 会保留本地 conversation 映射。真实 Linux FakeTCP 数据面仍不在本轮范围内。

## 已实现

### 工程与 API

- Cargo workspace 和三个 crate 的单向依赖关系；
- 平台无关、同步、事件驱动的 `ClientEngine` / `ServerEngine`；
- `PeerId` transport 路由标识，以及带目标/来源 peer 的 tunnel action/event；
- `Idle`、`Handshaking`、`Ready`、`Reconnecting`、`Closed` 会话状态模型；
- client 在 `Ready` 下按配置间隔发送受保护 heartbeat，server 认证后回送受保护 heartbeat；
- client 仅以成功认证的 server record 刷新接收活性，超时后关闭旧 session 并自动进入 `Reconnecting`；
- 支持显式 `Reconnect` 事件，重连期间拒绝业务数据，握手成功后回到 `Ready`；
- 重连建立新的随机 session 和方向密钥，同时保留 client 本地 peer 到 conversation ID 的映射；
- server 跟踪认证入站 record 和 upstream 回包活动，并仅在无活跃 conversation 时回收空闲 session；
- session 建立、heartbeat/data 活动和重连均返回宿主可执行的单调时钟定时 action；
- conversation 容量、空闲回收、反向映射和 `(session, conversation)` 隔离；
- PSK 长度限制、调试输出脱敏和 drop 时清零；
- 协议版本提升到 v3，旧版本帧不会被接受。

### 握手与密钥派生

- `ClientHello -> HelloRetry(cookie) -> ClientHello(cookie) -> ServerHello -> ClientFinish -> HandshakeAck` PSK 认证握手；
- `HelloRetry` 本身由 PSK 派生握手密钥认证，客户端不会接受伪造 cookie challenge；
- Cookie 绑定 `PeerId`、handshake ID、client nonce、suite 和签发时间，并使用服务端进程随机独立密钥认证；
- 无 Cookie 或 Cookie 无效/过期时服务端不创建 pending handshake；
- Cookie 验证使用常量时间 MAC 校验，默认有效期 30 秒；
- `ClientHello` 和 `ClientFinish` 按配置间隔重试，受总超时和最大尝试次数约束；
- 重复 cookie hello 返回同一 `ServerHello`，重复有效 finish 返回同一受保护 `HandshakeAck`；
- client 只有成功打开 `HandshakeAck` 后才进入 `Ready` 并报告 `SessionEstablished`；
- server hello 和 client finish 的 HMAC-SHA256 transcript 认证；
- cipher suite、session ID、client/server nonce、session salt 和握手 transcript 的绑定；
- HKDF-SHA256 方向密钥与 nonce prefix 派生；
- client-to-server / server-to-client 方向隔离，以及 record key / nonce prefix 用途隔离；
- cipher suite 不一致时明确拒绝，不做隐式降级；
- 全局及按 `PeerId` 有界 pending handshake、握手超时回收和已认证 session 容量限制；
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
- 握手 challenge、server hello、finish 和 ack 丢失后的重试/幂等测试；
- Cookie 来源绑定、过期和 per-peer pending 限制测试；
- 错 PSK、suite 不一致、密文/tag 篡改、重复 record、认证失败后合法同 packet number 仍可接受的测试；
- 非 `Ready` 状态业务数据拒绝；
- 认证 heartbeat 往返和持续保活测试；
- client 超时自动重连、显式重连、重连握手超时关闭测试；
- 重连后沿用 conversation ID 并在新 session 下继续投递测试；
- server 在 conversation 存活期间不回收 session、conversation 过期后回收 session 测试；
- 基础帧所有截断位置和 trailing bytes 拒绝测试；
- 帧解码 fuzz target；
- `cargo fmt --check`、严格 Clippy 和 workspace 测试作为验收项。

## 明确未实现

- 面向公网握手洪泛的完整防护和时间窗 token-bucket 来源速率限制；
- Cookie 密钥轮换、跨进程平滑轮换和可观测拒绝指标；
- session 恢复凭据、stable client identity、server 端跨 session conversation/upstream 迁移，以及密钥轮换/非零 epoch；
- 非 `Ready` 本地 UDP 严格有界暂存队列、重连退避/抖动和宿主网络路径切换；
- AES 硬件加速实际启用/软件回退的可观测指标；
- PMTU 探测、可信 ICMP 关联和 MTU 事件；
- worker shard、有界 Tokio 运行时队列和真实 UDP upstream；
- FakeTCP 状态机和 IP/TCP 报文编解码；
- Raw socket、AF_PACKET、cBPF、route/neighbor Netlink；
- nftables Netlink 和 legacy iptables 后端；
- IPv6 Linux transport。

## 当前安全边界

平台无关的 v3 内层协议已经提供 PSK 身份证明、完整性、防重放，以及除 `none` 外的机密性；`none` 只暴露 payload 内容，不会关闭握手认证、record 认证或防重放。未经认证的网络帧不能创建已认证 session、创建 conversation 或投递应用明文。

client 不再在发出 `ClientFinish` 后乐观进入 `Ready`；只有受保护 server ack 通过 record 认证和防重放后才建立会话。`Ready` 状态下的 heartbeat 与数据共享同一 record 认证、防重放和方向密钥边界；未认证输入不能刷新 session 活性。client 超时会放弃旧 record 状态并发起全新握手，server 只依据已认证活动延长空闲期限，且不会在仍有活跃 conversation 时回收 session。

当前“重连”不是协议级恢复：没有 stable identity 或恢复凭据，server 不会把旧 session 的 conversation/upstream socket 自动迁移到新 session。client 保留 conversation ID 只能保证本地映射连续，并为未来恢复协议固定状态机接口。当前实现仍不能宣称适合直接部署到不可信公网：尚无 token-bucket 来源速率限制、分布式攻击缓解、Cookie 密钥轮换和对应指标。`PeerId` 由宿主分配，是 Cookie 的路径绑定输入和路由元数据，不是稳定安全身份；宿主必须保证同一路径在握手期间映射稳定且攻击者不能任意冒用。

真实 Linux tunnel 仍不可用。CLI 的正常运行路径继续安全拒绝启动，`LinuxFakeTcpTransport` 的所有操作继续返回 `NotImplemented`，不会将安全核心静默降级为裸网络传输。

## 下一阶段建议

1. 实现 stable client identity / 恢复凭据、server 端 conversation/upstream 迁移、有界重连数据队列，并为 epoch/key rotation 固化状态机；
2. 增加来源 token-bucket、Cookie 密钥轮换和握手拒绝/重试指标；
3. 实现 Tokio worker shard、有界队列和纯 UDP upstream harness；
4. 开始 Linux FakeTCP 报文编解码、校验和、AF_PACKET/raw socket 与 cBPF；
5. 最后接入 route/neighbor Netlink、PMTU 和 Netfilter RST guard。

当前阶段不需要 root、`CAP_NET_RAW`、network namespace 或 Netfilter 权限。真实 Linux 网络层阶段才需要这些条件。
