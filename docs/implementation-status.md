# 当前实施状态

## 本轮目标

本轮将平台无关核心推进到安全 session 恢复：在可靠、非乐观的 v3 认证握手与基础重连生命周期之上，增加短期、服务端认证的恢复凭据，以及新安全 session 建立后的 conversation/upstream 状态迁移。恢复仍是进程内、短期且单服务器的，不是跨进程 stable identity。真实 Linux FakeTCP 数据面仍不在本轮范围内。

## 已实现

### 工程与 API

- Cargo workspace 和三个 crate 的单向依赖关系；
- 平台无关、同步、事件驱动的 `ClientEngine` / `ServerEngine`；
- `PeerId` transport 路由标识，以及带目标/来源 peer 的 tunnel action/event；
- `Idle`、`Handshaking`、`Ready`、`Reconnecting`、`Closed` 会话状态模型；
- client 在 `Ready` 下按配置间隔发送受保护 heartbeat，server 认证后回送受保护 heartbeat；
- client 仅以成功认证的 server record 刷新接收活性，超时后关闭旧 session 并自动进入 `Reconnecting`；
- 支持显式 `Reconnect` 事件，重连期间拒绝业务数据，握手成功后回到 `Ready`；
- 重连始终建立新的随机 session、方向密钥、packet number 与 replay window，绝不复用旧 record 状态；
- server 通过受 HMAC-SHA256 保护、带签发/过期时间、旧 session ID、conversation 锚点和随机值的短期凭据识别可恢复逻辑 session；
- 恢复凭据只通过已认证 record 下发，并绑定到后续 `ClientHello`、Cookie 和完整握手 transcript；
- server 在新 `ClientFinish` 成功认证后才原子迁移旧 conversation 集合，并发出 `SessionResumed { old_session_id, new_session_id }` 供宿主迁移 connected upstream socket 的 session 路由键；
- client 只有在认证 `HandshakeAck` 确认 `resumed=true` 后保留 conversation 映射；凭据无效/过期或 server 状态缺失时安全回退到新 session 并关闭旧本地映射；
- server 跟踪认证入站 record 和 upstream 回包活动，空闲 session 关闭后可在配置的短期恢复窗口内保留 conversation/upstream 元数据；
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
- server 只有在验证有效 `ClientFinish` 后才创建已认证 session 或迁移恢复状态；
- server hello 的 `resumed` 结果受 transcript 认证，攻击者不能把普通握手篡改成恢复握手或反向降级而不被检测。

### Record layer

- ChaCha20-Poly1305；
- XChaCha20-Poly1305；
- AES-128-GCM；
- AES-256-GCM；
- `none` 认证明文模式：payload 不加密，但使用完整 HMAC-SHA256 tag；
- 受保护 `ResumptionCredential` record 类型，和 data/heartbeat 共享方向密钥、防重放及认证边界；
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
- 有效恢复凭据下跨 session 沿用 conversation、双向继续投递、旧 session 失效和 `SessionResumed` action 测试；
- 恢复凭据过期时不迁移 server 状态、client 清理旧映射并创建新 conversation 的安全回退测试；
- server 空闲 session 转为短期可恢复状态且不立即关闭 upstream conversation 的测试；
- 基础帧所有截断位置和 trailing bytes 拒绝测试；
- 帧解码 fuzz target；
- `cargo fmt --check`、严格 Clippy 和 workspace 测试作为验收项。

## 明确未实现

- 面向公网握手洪泛的完整防护和时间窗 token-bucket 来源速率限制；
- Cookie 密钥轮换、跨进程平滑轮换和可观测拒绝指标；
- 跨进程/多节点 stable client identity、持久化或可轮换恢复凭据密钥、恢复状态复制，以及密钥轮换/非零 epoch；
- 宿主对 `SessionResumed` action 的真实 connected UDP upstream socket 路由迁移（核心已提供原子迁移信号，真实 upstream runtime 尚未实现）；
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

client 不再在发出 `ClientFinish` 后乐观进入 `Ready`；只有受保护 server ack 通过 record 认证和防重放后才建立会话。`Ready` 状态下的 heartbeat、数据和恢复凭据共享同一 record 认证、防重放和方向密钥边界；未认证输入不能刷新 session 活性。client 超时会放弃旧 record 状态并发起全新握手；即使恢复成功，新 session 也使用全新密钥、nonce prefix、packet number 和 replay window。

当前恢复凭据由服务端进程随机秘密签发，默认短期有效并仅引用服务端仍保留的内存状态；服务重启、状态过期、凭据篡改或状态缺失都会安全回退为非恢复握手。恢复成功只在新握手完成后发生，旧 session 随即失效；旧路径迟到 record 不会被新 session 接受。核心迁移 conversation 元数据并返回宿主 action，但真实 connected upstream socket 的路由迁移要由后续 runtime 执行。当前实现仍不能宣称适合直接部署到不可信公网：尚无 token-bucket 来源速率限制、分布式攻击缓解、Cookie/恢复密钥轮换和对应指标。`PeerId` 由宿主分配，是 Cookie 的路径绑定输入和路由元数据，不是稳定安全身份；宿主必须保证同一路径在握手期间映射稳定且攻击者不能任意冒用。

真实 Linux tunnel 仍不可用。CLI 的正常运行路径继续安全拒绝启动，`LinuxFakeTcpTransport` 的所有操作继续返回 `NotImplemented`，不会将安全核心静默降级为裸网络传输。

## 下一阶段建议

1. 实现宿主 `SessionResumed` upstream socket 路由迁移、有界重连数据队列，并为 epoch/key rotation 固化状态机；
2. 增加来源 token-bucket、Cookie 密钥轮换和握手拒绝/重试指标；
3. 实现 Tokio worker shard、有界队列和纯 UDP upstream harness；
4. 开始 Linux FakeTCP 报文编解码、校验和、AF_PACKET/raw socket 与 cBPF；
5. 最后接入 route/neighbor Netlink、PMTU 和 Netfilter RST guard。

当前阶段不需要 root、`CAP_NET_RAW`、network namespace 或 Netfilter 权限。真实 Linux 网络层阶段才需要这些条件。
