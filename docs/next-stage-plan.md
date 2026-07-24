# 下一阶段实施计划：无心跳、轻量协议与低损耗会话

> **状态：核心实现已完成。** 已实现 v4 的 24 字节固定 envelope、64 位 session ID、32 位 session 作用域 wire `ConversationHandle`、由 datagram 边界推导并认证的 body length、保留 heartbeat type 拒绝、保守 1150 字节 payload 上限，以及移除 heartbeat 的核心路径。按业务触发重连、稳定逻辑 `ConversationId` 与 wire handle 的独立映射、恢复时受保护 handle 重新绑定均已完成；性能基准、完整观测和 worker shard 仍未完成。

## 目标与取舍

下一阶段优先将内层会话调整为**业务流量驱动（on-demand）**，并将 v4 的常驻数据面编码改为紧凑的固定头：在会话空闲时不发送任何隧道控制包，不以周期探测维持 NAT 或检测路径存活；业务数据不再携带为数据报 transport 重复提供的 framing 字段。目标是在不降低现有 PSK 认证、完整性、机密性（非 `none` 套件）、防重放、Cookie 限流和恢复安全边界的前提下，降低空闲网络包、每包 wire 开销、CPU 唤醒、加密/MAC 运算和状态更新开销，并尽可能避免重连期间由隧道自身造成的可避免数据报丢弃。

**明确决定：不设计、不保留可启用的心跳模式。** 不新增 `--heartbeat-ms`、`--no-heartbeat` 或等价兼容开关；下一协议版本也不再发送或回应 `Heartbeat` record。握手重试不是心跳，仍然保留，因为它只在建立/恢复会话期间用于应对握手包丢失。

这是一项有意识的 UDP 语义取舍：没有周期探测时，静默期间的断连无法被即时发现；网络重新可用或失效后的首个业务数据报可能触发重连等待，且 UDP 本身不承诺该数据报必达。项目不以数据重传伪造可靠传输，也不把普通 UDP 丢包误判为断连。

## v4 紧凑协议设计

### 数据面 envelope

v3 的统一 wire header 为 48 字节，其中包含 4 字节 magic、2 字节版本、4 字节 payload length、16 字节 session ID、8 字节 conversation ID 和 4 字节 epoch。对本项目的**分组** transport 而言，payload 边界已经由收到的数据报给出；在高频小 UDP 数据报场景中，这些重复字段是主要的固定开销。v4 将所有 handshake 和受保护 record 统一编码为严格固定的 **24 字节 envelope**：

```text
0                   1                   2                   3
+-------------------+-------------------+-------------------+-------------------+
| v4 discriminator  | frame type        | key epoch         | flags (= 0)       |
+-------------------+-------------------+-------------------+-------------------+
|                         session id (u64)                    |
+--------------------------------------------------------------+
|                       packet number (u64)                    |
+--------------------------------------------------------------+
|                  conversation handle (non-zero u32 / 0)      |
+--------------------------------------------------------------+
|                     frame body (remaining datagram bytes)   |
+--------------------------------------------------------------+
```

- `v4 discriminator` 固定为版本值 `4`。v4 解码器只接受该值；v3 的 `U2NG` 开头数据和所有其他值均在认证前被拒绝。它替代 magic 加版本字段，确保旧、新格式不会被静默混用。
- `frame type` 保留显式类型区分。v4 不定义 `Heartbeat`；其旧 wire value `17` 为保留且显式拒绝值。`flags` 必须为零，未知 `key epoch`、保留 type、非零 flags、非法 conversation handle 及不符合类型字段约束的包均拒绝。
- `session id` 改为密码学随机的 64 位路由标识。它不是认证凭据；握手 transcript、方向密钥、随机 nonce 和 record 认证仍由 PSK 派生。创建时必须在 active、pending 与 recovery-window session 集合中查重，冲突即重新生成，绝不覆盖已有 session。
- `packet number` 继续使用每方向 64 位单调序号；不得为了缩头改为 32 位。`key epoch` 使用 8 位字段预留后续受认证的 key rotation；在该机制落地前只允许 epoch 0，packet number 耗尽时仍安全失败并重新握手。
- `conversation handle` 是 session 作用域内的非零 `u32`，0 表示无 conversation 的握手/控制 record。core 为每个 session 分配、验证并维护该 handle 到既有逻辑 `ConversationId` 的映射；宿主公开 API 和恢复语义不因 wire 压缩而把 32 位 handle 当成跨 session 的身份。达到可配置容量或 handle 空间耗尽时拒绝新 conversation，绝不复用仍可能被迟到包引用的 handle。
- payload length 不再上 wire：解码器以收到的数据报总长减去 24 字节计算 body length，在任何分配、解密或 MAC 前检查最小 tag 长度和 `MAX_FRAME_BODY`。计算出的长度必须纳入 AEAD associated data 或 `none` 的 HMAC 输入，因而截断、拼接和长度篡改仍无法被接受。

该改变将常驻 envelope 从 48 降至 24 字节；以当前 16 字节 AEAD tag 计算，空 payload 的受保护 record 从至少 64 降至至少 40 字节，普通小数据报同样减少 24 字节。实际外层 TCP/IP/FakeTCP 开销不在此数字内，基准必须报告端到端长度而不是只报告 header。

### 轻量化边界与安全约束

- v4 仅面向保留数据报边界的 `PacketTransport` / UDP / FakeTCP packet transport；core 不把多个 v4 envelope 拼接进一个 datagram，也不依赖 stream read 边界。未来如需 stream 适配，长度 framing 必须由适配层提供，不能重新塞回 v4 record header。
- 不实现“自动压缩”或按包压缩。加密后的数据不可有效压缩；压缩明文会增加 CPU、内存与延迟，并可能引入跨请求长度侧信道。若应用明确需要压缩，应在隧道外、由了解自身敏感字段边界的上层协议选择。
- 不以缩头为由缩短 AEAD tag、HMAC tag、PSK、nonce prefix、握手 transcript、Cookie、replay window 或认证上下文。`none` 仍使用完整 HMAC-SHA256 tag，且同样绑定由数据报长度计算出的 body length。
- v4 的解析顺序固定为：只做固定头/长度上限的无状态检查，按 session ID 查找候选 session，验证 AEAD/MAC 与方向和长度绑定，再原子更新 replay window，最后解释 frame type、conversation handle 或投递明文。未认证的 header 绝不能创建 session、conversation 映射或刷新活性。
- v3 与 v4 不协商同一会话，也不做“尝试按两种格式解码”的降级回退。部署升级必须令 client/server 同时使用 v4；版本、envelope discriminator 和所选格式进入完整握手 transcript 与受保护 record 的认证上下文。

## 会话行为

### 空闲与活性

- 握手成功后，客户端和服务端都**不**安排周期性 heartbeat 定时器，也不发送空 payload 的保活 record。
- 仅成功认证并通过防重放校验的业务 record、恢复相关受保护 record 和握手完成事件可刷新相应的活动时间；未认证输入绝不能刷新活性。
- server 继续按认证入站活动和既有 `session_idle_timeout` 回收空闲 session；需要恢复的 conversation/upstream 路由仍只保留到受限恢复窗口结束。
- client 空闲时允许保持 `Ready` 而不探测对端。它只在收到本地业务数据、显式 `Reconnect`、可信的本地 transport 错误或宿主报告的路径变化时评估/触发恢复。

### 按需重连

当本地业务数据到达时：

1. 若会话仍处于 `Ready`，且最近一次**认证的 server 方向**活动未超过 `session_timeout`，按现有 UDP 语义直接封装并发送该数据报。
2. 若从未收到认证的 server 方向活动，或该活动已经超过 `session_timeout`，不得先向可能失效的旧 session 发送该数据报；应关闭旧 record 状态、发起全新认证握手/恢复握手，并将该数据报放入严格有界、短时 FIFO 恢复队列。
3. 只有在受保护 `HandshakeAck` 验证成功后，才按 FIFO 顺序发送仍未过期的排队数据报；恢复失败、超时、队满或服务关闭时以可观测原因丢弃。
4. 显式重连、可信 transport 错误或宿主路径变化可以立即进入同一恢复流程。重连总是创建新的 session 密钥、nonce prefix、packet number 和 replay window；恢复凭据只迁移授权的 conversation 元数据，绝不复用旧 record 状态。

`session_timeout` 在此模式中是“按需发送前的认证回程活性阈值”，**不是**发送周期包的间隔。它不可能证明单向 UDP 路径存活；在阈值内发生的突发路径失效，少量业务数据仍可能按 UDP 语义丢失。上层若需要可靠交付，必须自行实现确认、重试或选用合适协议。

## 协议与 API 变更

1. 升级内层协议版本（预期 v4），采用上述 24 字节固定 envelope，使新旧会话行为和编码清晰隔离；v4 不接受、产生或回应 `Heartbeat` frame type。保留的 wire value 如继续占位，必须被显式拒绝而非静默忽略。
2. 从 core 的 `EngineConfig` 删除 `heartbeat_interval`，并删除“heartbeat interval 必须小于 session timeout”的验证错误和相关定时 action。
3. 从 CLI 删除 `--heartbeat-ms`；`--session-timeout-secs` 保留并更新帮助文本，说明它仅用于本地业务到达时的按需重连判定。
4. 用 session 作用域 `u32` conversation handle 替换数据面上的逻辑 conversation ID，并在 core 内维护与公开稳定逻辑 `ConversationId` 的映射；恢复时不复制旧 handle，而是在认证 `HandshakeAck` 后通过受保护的 `ResumeConversation` record 和逐 conversation 恢复凭据重新绑定新 handle。server route key 继续只使用稳定逻辑 ID。
5. 删除 client/server heartbeat 发送与回复分支、相关指标和测试；不得以其他周期性空包替代。
6. 保持并完善握手重试、认证恢复凭据、重连队列、Cookie、限流、防重放和 server recovery-window 路由迁移；这些机制不是常驻保活流量。
7. 更新 library API、CLI `--help`、README、协议规范、架构图与实施状态，明确“无心跳、紧凑 24 字节 envelope、按业务触发重连”的语义、兼容性断点和 UDP 的丢包边界。

## 低损耗与资源控制要求

- 恢复队列必须继续限制数据报数量、单包大小、驻留时长和总内存；所有超限、过期、握手失败和关闭丢弃均产生明确 action/指标，暂存明文保持 `Zeroizing` 生命周期。
- 不重传已经交给 transport 的普通业务数据，也不对普通 UDP 丢包进行自动重连；这既维持 UDP 数据报语义，也避免重复投递。
- 紧凑编码必须保持单次、固定偏移解析和尽早长度上限检查；不得为节省数个字节改用无界变长整数、模糊的可选字段或需要猜测 frame 边界的格式。
- 所有 MTU 和 payload 上限计算都必须切换到 v4 的实际 envelope、套件 tag 和外层 transport 开销；不得沿用 v3 的 48 字节 header 常量，也不得因头部变短而超过 UDP、路径 MTU 或 FakeTCP 的有效 payload 上限。
- 将“避免可避免损耗”限定为：在判定旧会话过期后，先握手再投递；在握手期间尽力保留有界队列中的新数据；恢复成功时原子迁移 conversation/upstream 路由，避免因 session ID 更换造成串流或不必要的 upstream socket 重建。
- 不得因为移除 heartbeat 放宽认证、防重放、会话容量、握手限速、恢复期限或空闲资源回收。

## 实施顺序

1. **协议编码迁移**：先实现独立 v4 codec、24 字节 envelope、64 位 session ID、session 作用域 `u32` conversation handle、由数据报长度推导并认证的 body length，以及全部非法字段/截断/跨版本拒绝测试；此步骤完成前不删除 v3 codec 或开始 worker shard 改造。
2. **协议/状态机迁移**：为 v4 定义无 heartbeat frame 集和按需重连状态转换，更新 `EngineConfig`、错误类型、动作/事件、恢复映射和单调时钟调度；删除 heartbeat 配置验证与定时 action。
3. **核心与托管服务实现**：删除周期 heartbeat 路径；在 client 本地业务入口和可信路径事件入口实现按需重连；确保 Tokio service 不再因保活周期唤醒或发送控制包，并以 v4 实际开销重新计算 payload/MTU 限制。
4. **恢复与低损耗验证**：覆盖断连后首次业务、恢复队列 FIFO、队满/过期、恢复凭据有效/失效、session handle 映射、server route 迁移/过期释放和迟到旧 session record 拒绝。
5. **性能与可观测性**：增加 v3/v4 header 开销、idle、持续小包/大包业务和断连恢复基准；指标改为认证业务活动、按需重连、队列原因、恢复耗时、v4 格式/长度拒绝和 session ID 冲突重试。空闲已建立会话在观测窗口内的隧道发送包数必须为零（不计外部网络栈行为）。
6. **后续原有路线**：在无心跳的紧凑会话通过验收后，继续实现 Tokio worker shard/稳定 session 哈希/有界 dispatch、全面观测与 shutdown drain、Cookie 密钥轮换和来源 IP 归一化；之后进入 Linux FakeTCP、PMTU、route/neighbor Netlink 与 RST guard。

## 验收标准

- v4 client/server 在内存 transport 和托管 UDP harness 上完成双向业务数据与恢复测试，且不存在任何 heartbeat 收发。
- v4 的全部有效 handshake 与 record envelope 均恰为 24 字节固定头；相同 payload、suite 和 tag 下，v4 wire 长度比 v3 少 24 字节。测试须覆盖固定偏移编码、总长推导、最大长度、最小 tag 长度、截断、trailing bytes、非零 flags、保留 type/heartbeat value、未知 epoch 和 v3/v4 交叉输入的显式拒绝。
- 64 位 session ID 在 active、pending 和可恢复状态中的碰撞会被检测并重新生成；`u32` conversation handle 只在本 session 唯一，绝不会因恢复、关闭或迟到包与不同逻辑 conversation 串流。认证前输入不能分配或刷新这些映射。
- 已建立但无业务的 client/server 在超过至少两个旧 heartbeat 周期的测试窗口内不发送 tunnel frame；定时器不产生仅为保活而存在的网络动作。
- 静默后本地首个数据报到达时：认证 server 活性未过期则直接发送；已过期则先发起握手并将数据报有界排队，绝不先使用旧 session 发送。
- 握手/恢复成功后未过期数据报 FIFO 投递；队满、超时、失败和关闭均有可测的显式丢弃原因；不会重复发送已成功交给 transport 的业务数据。
- 未认证、篡改、重放或旧 session 输入不能刷新活动时间、阻止按需重连、创建 conversation 或投递明文。
- 基准报告每方向的 envelope、认证 tag、外层开销和总 wire 字节；在小 payload 代表性负载下验证紧凑格式的确定性节省，且编码/解码吞吐、分配次数与峰值内存不得因格式迁移回退。不得出现隐式压缩或未受认证的长度/可选字段解析路径。
- `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` 以及相关 fuzz/property 测试均通过。
