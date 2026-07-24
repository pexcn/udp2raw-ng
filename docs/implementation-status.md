# 当前实施状态

## 本轮目标

本轮完成轻量协议的首个可运行切片：内层协议升级为 v4，采用 24 字节固定 datagram envelope、64 位 session ID 与 32 位 conversation ID，并移除 heartbeat frame 与周期性保活路径。会话已切换为无心跳、按业务触发的重连模型：空闲会话不再发送任何 tunnel frame，也不会因超时自行重连；只有本地业务数据在认证回程活性过期时到达，才触发一次新握手并把首包放入既有有界队列。v4 仍保持 PSK 握手、方向密钥、完整认证和防重放；Linux FakeTCP 数据面仍在后续范围内。

## 已实现

### 工程与 API

- Cargo workspace 和三个 crate 的单向依赖关系；
- 平台无关、同步、事件驱动的 `ClientEngine` / `ServerEngine`；
- `PeerId` transport 路由标识，以及带目标/来源 peer 的 tunnel action/event；
- `Idle`、`Handshaking`、`Ready`、`Reconnecting`、`Closed` 会话状态模型；
- v4 已建立会话在空闲时不发送 tunnel frame；已移除 client/server heartbeat 发送、回应和 `EngineConfig::heartbeat_interval`；
- client 仅以成功认证的 server record 刷新接收活性；空闲会话保持 `Ready` 且不自动重连，`session_timeout` 仅作为“本地业务到达前判断旧会话是否仍可用”的活性阈值；
- 本地业务数据到达时，若认证回程活性已超过 `session_timeout`，先关闭旧 record 状态并发起新握手，同时把触发数据报放入有界重连队列，绝不在可能失效的旧 session 上发送；
- 支持显式 `Reconnect` 事件，重连期间业务数据进入有界队列，握手成功后回到 `Ready`；
- client 在 `Handshaking` 或 `Reconnecting` 时将合规本地 UDP 数据报放入严格有界 FIFO；队列已满、等待超时或握手失败关闭时，以可观测 action 丢弃，认证 `HandshakeAck` 后按 FIFO 顺序投递未过期数据；
- 暂存队列按数据报数限制，且每个元素受 `max_frame_payload` 限制；暂存明文以 `Zeroizing` 保存，丢弃或投递后清零；
- 重连始终建立新的随机 session、方向密钥、packet number 与 replay window，绝不复用旧 record 状态；
- server 通过受 HMAC-SHA256 保护、带签发/过期时间、旧 session ID、conversation 锚点和随机值的短期凭据识别可恢复逻辑 session；
- 恢复凭据只通过已认证 record 下发，并绑定到后续 `ClientHello`、Cookie 和完整握手 transcript；
- server 在新 `ClientFinish` 成功认证后才原子迁移旧 conversation 集合，并发出 `SessionResumed { old_session_id, new_session_id }` 供宿主迁移 connected upstream socket 的 session 路由键；
- server 在短期恢复状态最终过期时发出 `SessionRecoveryExpired`，使宿主可精确释放仅为恢复保留的资源；
- 官方 `udp2raw-ng` crate 提供可嵌入的 Tokio `ClientService` / `ServerService`：普通 UDP listener/upstream、可替换 `PacketTransport`、显式关闭 handle、定期核心定时器推进与有界 transport 收发 channel；
- server 按 `(SessionId, ConversationId)` 维护 connected upstream UDP socket；session 关闭后在恢复窗口内保留该 socket，收到 `SessionResumed` 后移动到新 session 路由键，收到 `SessionRecoveryExpired` 后释放；
- 托管服务暴露 transport queue、client 暂存队列、upstream 和内部 engine 错误的基础丢弃/错误计数；
- client 只有在认证 `HandshakeAck` 确认 `resumed=true` 后保留 conversation 映射；凭据无效/过期或 server 状态缺失时安全回退到新 session 并关闭旧本地映射；
- server 跟踪认证入站 record 和 upstream 回包活动，空闲 session 关闭后可在配置的短期恢复窗口内保留 conversation/upstream 元数据；
- session 建立、认证 data/恢复活动和重连均返回宿主可执行的单调时钟定时 action；
- conversation 容量、空闲回收、反向映射和 `(session, conversation)` 隔离；
- PSK 长度限制、调试输出脱敏和 drop 时清零；
- 协议版本提升到 v4，v3 `U2NG` envelope、保留 heartbeat type、非零 flags、未知 epoch 和非法 conversation 字段均在认证前显式拒绝；
- v4 使用固定 24 字节 envelope：版本 discriminator、frame type、8 位 epoch、flags、64 位 session ID、64 位 packet number 和 session 作用域 32 位 `ConversationHandle`；body 长度从 datagram 边界推导并进入认证上下文；
- `ConversationHandle` 只在单个已认证 session 内有效，继续由 AEAD/HMAC associated data 认证；宿主 API、`TunnelAction`、server upstream route 和恢复状态则使用独立稳定的逻辑 `ConversationId`；
- client/server 维护每 session 的 `ConversationHandle <-> ConversationId` 双向映射；关闭或回收后旧 handle 不会在同一 session 内重新分配，未知 handle 仅能在认证且通过防重放后创建新的稳定逻辑 conversation；
- 恢复 session 不复制旧 session 的 wire handle。认证 `HandshakeAck` 后，client 为每个已恢复 conversation 发送受保护的 `ResumeConversation` 绑定帧；server 验证其逐 conversation 恢复凭据后，把新 handle 绑定至已迁移的稳定逻辑 conversation；
- 每个逻辑 conversation 签发独立恢复凭据，因此多 conversation 的恢复可分别重新绑定；托管服务的 `(SessionId, ConversationId)` connected upstream route 迁移不感知 wire handle；
- 默认业务 payload 上限暂降至保守的 1150 字节，避免未来 FakeTCP/IP transport 发生外层分片；后续 PMTU 实现将按路径调整该值；

### 握手与密钥派生

- `ClientHello -> HelloRetry(cookie) -> ClientHello(cookie) -> ServerHello -> ClientFinish -> HandshakeAck` PSK 认证握手；
- `HelloRetry` 本身由 PSK 派生握手密钥认证，客户端不会接受伪造 cookie challenge；
- Cookie 绑定 `PeerId`、handshake ID、client nonce、suite 和签发时间，并使用服务端进程随机独立密钥认证；
- 无 Cookie 或 Cookie 无效/过期时服务端不创建 pending handshake；
- Cookie 验证使用常量时间 MAC 校验，默认有效期 30 秒；
- server 对每个 `PeerId` 在 Cookie 验证及 pending handshake 分配之前应用有界令牌桶；默认突发上限为 32，每 100 ms 恢复一个 token，bucket 数量受既有未认证握手全局上限约束；
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
- 紧凑 envelope、协议版本、session、epoch、packet number、frame type、conversation、方向、cipher suite 和由 datagram 推导的 body 长度均绑定到认证上下文；
- 非零 epoch、错误 session、错误方向、截断 tag、非法 record 类型和畸形长度均拒绝；
- packet number 溢出时安全失败并要求新 session；
- 防重放滑动窗口已接入唯一 record 打开入口，顺序固定为“先认证、再更新 replay window、最后返回明文”；
- 认证失败不会推进 replay window，也不会创建 conversation 或投递明文。

### Transport 与测试

- `PacketTransport` 的有界纯内存双端实现；
- FIFO 双向传输、`PeerId` 保留、队列满错误、peer drop/关闭行为和 waker 唤醒；
- 五种 cipher suite 的完整内存握手与双向数据 round-trip；
- 握手 challenge、server hello、finish 和 ack 丢失后的重试/幂等测试；
- Cookie 来源绑定、过期、per-peer pending 限制和按 `PeerId` 令牌桶限速/恢复测试；
- 错 PSK、suite 不一致、密文/tag 篡改、重复 record、认证失败后合法同 packet number 仍可接受的测试；
- 非 `Ready` 状态业务数据拒绝；
- 空闲 `Ready` 会话不产生 tunnel frame 的测试；
- 空闲的过期会话不自行重连、本地业务到达时才按需重连（首包不走旧 session）的测试；
- 显式重连、重连握手超时关闭测试；
- 重连队列容量、超时丢弃和认证建立后 FIFO 投递测试；
- 有效恢复凭据下跨 session 沿用 conversation、双向继续投递、旧 session 失效和 `SessionResumed` action 测试；
- 恢复凭据过期时不迁移 server 状态、client 清理旧映射并创建新 conversation 的安全回退测试；
- server 空闲 session 转为短期可恢复状态且不立即关闭 upstream conversation 的测试；
- 内存 transport 上的 Tokio client/service/server/upstream UDP 往返和关闭控制集成测试；
- v4 固定头截断、datagram body 长度推导、legacy magic、保留 heartbeat type 与非零 flags 拒绝测试；
- 帧解码 fuzz target；
- `cargo fmt --check`、严格 Clippy 和 workspace 测试作为验收项。

## 明确未实现

- 面向大规模分布式公网握手洪泛的完整防护、来源真实 IP 归一化和限流/拒绝指标聚合；当前按宿主 `PeerId` 的令牌桶只是核心层的基础保护；
- Cookie 密钥轮换、跨进程平滑轮换和可观测拒绝指标；
- 跨进程/多节点 stable client identity、持久化或可轮换恢复凭据密钥、恢复状态复制，以及密钥轮换/非零 epoch；
- 重连退避/抖动和宿主网络路径切换；
- AES 硬件加速实际启用/软件回退的可观测指标；
- PMTU 探测、可信 ICMP 关联和 MTU 事件；当前 1150 字节保守上限尚未按路径动态调整；
- 多 worker shard 的 session 稳定哈希、跨 shard dispatch 和每 shard 有界 runtime 队列；当前托管 UDP harness 为保证 engine 单所有者而明确限制为一个 packet worker；
- FakeTCP 状态机和 IP/TCP 报文编解码；
- Raw socket、AF_PACKET、cBPF、route/neighbor Netlink；
- nftables Netlink 和 legacy iptables 后端；
- IPv6 Linux transport。

## 当前安全边界

平台无关的 v4 内层协议已经提供 PSK 身份证明、完整性、防重放，以及除 `none` 外的机密性；`none` 只暴露 payload 内容，不会关闭握手认证、record 认证或防重放。未经认证的网络帧不能创建已认证 session、创建 conversation 或投递应用明文。v4 是 datagram-only codec：body 边界由 transport datagram 提供，不支持 stream 拼接；应用层压缩不由 tunnel 自动执行。

client 不再在发出 `ClientFinish` 后乐观进入 `Ready`；只有受保护 server ack 通过 record 认证和防重放后才建立会话。`Ready` 状态下的数据和恢复凭据共享同一 record 认证、防重放和方向密钥边界；未认证输入不能刷新 session 活性。当前空闲会话不会发送心跳；client 超时仍会放弃旧 record 状态并发起全新握手。即使恢复成功，新 session 也使用全新密钥、nonce prefix、packet number 和 replay window。

当前恢复凭据由服务端进程随机秘密签发，默认短期有效并仅引用服务端仍保留的内存状态；服务重启、状态过期、凭据篡改或状态缺失都会安全回退为非恢复握手。恢复成功只在新握手完成后发生，旧 session 随即失效；旧路径迟到 record 不会被新 session 接受。托管 server 会在 session idle close 后保留 connected upstream socket 路由到恢复窗口结束；恢复成功时随 `SessionResumed` 移至新 session，最终过期时才释放。client 仅在握手或重连状态暂存合规数据报，严格按容量和时限丢弃；不会在 `Closed` 状态继续积压明文。server 的 Cookie 前令牌桶限制单个宿主 `PeerId` 的 handshake 尝试，但该标识由宿主提供，不是来源 IP 身份，尚不足以抵御分布式攻击。当前实现仍不能宣称适合直接部署到不可信公网：尚无来源 IP 归一化、分布式攻击缓解、Cookie/恢复密钥轮换和对应指标。`PeerId` 由宿主分配，是 Cookie 的路径绑定输入和路由元数据，不是稳定安全身份；宿主必须保证同一路径在握手期间映射稳定且攻击者不能任意冒用。

真实 Linux tunnel 仍不可用。CLI 的正常运行路径继续安全拒绝启动，`LinuxFakeTcpTransport` 的所有操作继续返回 `NotImplemented`，不会将安全核心静默降级为裸网络传输。

## 下一阶段建议

1. 完成按业务触发的 client 重连：在本地业务到达时检查认证 server 活性，超时则先握手/恢复并将数据报放入既有有界队列；
2. 为 session 作用域 conversation handle 增加容量耗尽、篡改绑定、跨 session 同 handle 和多 conversation 恢复的 property/fuzz 测试；
3. 为托管服务增加全面的队列/拒绝指标、观测 API 与 shutdown drain 策略，并重新按 v4 开销计算 MTU；
4. 实现 Tokio worker shard、稳定 session 哈希和跨 shard 有界 dispatch；
5. 增加 Cookie 密钥轮换、来源真实 IP 归一化和握手拒绝/重试指标，并为 epoch/key rotation 固化状态机；
6. 开始 Linux FakeTCP 报文编解码、校验和、AF_PACKET/raw socket 与 cBPF，最后接入 route/neighbor Netlink、PMTU 和 Netfilter RST guard。

当前阶段不需要 root、`CAP_NET_RAW`、network namespace 或 Netfilter 权限。真实 Linux 网络层阶段才需要这些条件。
