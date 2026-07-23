# 下一阶段实施计划：无心跳的轻量、低损耗会话

> **状态：计划，尚未实现。** 当前 v3 实现仍会周期性发送并回应受保护的 heartbeat。本计划确定下一阶段将其移除；在实现完成前，不能把当前实现描述为“无心跳”。

## 目标与取舍

下一阶段优先将内层会话调整为**业务流量驱动（on-demand）**：在会话空闲时不发送任何隧道控制包，不以周期探测维持 NAT 或检测路径存活。目标是在不降低现有 PSK 认证、完整性、机密性（非 `none` 套件）、防重放、Cookie 限流和恢复安全边界的前提下，降低空闲网络包、CPU 唤醒、加密/MAC 运算和状态更新开销，并尽可能避免重连期间由隧道自身造成的可避免数据报丢弃。

**明确决定：不设计、不保留可启用的心跳模式。** 不新增 `--heartbeat-ms`、`--no-heartbeat` 或等价兼容开关；下一协议版本也不再发送或回应 `Heartbeat` record。握手重试不是心跳，仍然保留，因为它只在建立/恢复会话期间用于应对握手包丢失。

这是一项有意识的 UDP 语义取舍：没有周期探测时，静默期间的断连无法被即时发现；网络重新可用或失效后的首个业务数据报可能触发重连等待，且 UDP 本身不承诺该数据报必达。项目不以数据重传伪造可靠传输，也不把普通 UDP 丢包误判为断连。

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

1. 升级内层协议版本（预期 v4），使新旧会话行为清晰隔离；v4 不接受、产生或回应 `Heartbeat` frame type。保留的 wire value 如继续占位，必须被显式拒绝而非静默忽略。
2. 从 core 的 `EngineConfig` 删除 `heartbeat_interval`，并删除“heartbeat interval 必须小于 session timeout”的验证错误和相关定时 action。
3. 从 CLI 删除 `--heartbeat-ms`；`--session-timeout-secs` 保留并更新帮助文本，说明它仅用于本地业务到达时的按需重连判定。
4. 删除 client/server heartbeat 发送与回复分支、相关指标和测试；不得以其他周期性空包替代。
5. 保持并完善握手重试、认证恢复凭据、重连队列、Cookie、限流、防重放和 server recovery-window 路由迁移；这些机制不是常驻保活流量。
6. 更新 library API、CLI `--help`、README、协议规范、架构图与实施状态，明确“无心跳、按业务触发重连”的语义和 UDP 的丢包边界。

## 低损耗与资源控制要求

- 恢复队列必须继续限制数据报数量、单包大小、驻留时长和总内存；所有超限、过期、握手失败和关闭丢弃均产生明确 action/指标，暂存明文保持 `Zeroizing` 生命周期。
- 不重传已经交给 transport 的普通业务数据，也不对普通 UDP 丢包进行自动重连；这既维持 UDP 数据报语义，也避免重复投递。
- 将“避免可避免损耗”限定为：在判定旧会话过期后，先握手再投递；在握手期间尽力保留有界队列中的新数据；恢复成功时原子迁移 conversation/upstream 路由，避免因 session ID 更换造成串流或不必要的 upstream socket 重建。
- 不得因为移除 heartbeat 放宽认证、防重放、会话容量、握手限速、恢复期限或空闲资源回收。

## 实施顺序

1. **协议/状态机迁移**：先为 v4 定义无 heartbeat frame 集和按需重连状态转换，更新 `EngineConfig`、错误类型、动作/事件和单调时钟调度；此步骤完成前不开始 worker shard 改造。
2. **核心与托管服务实现**：删除周期 heartbeat 路径；在 client 本地业务入口和可信路径事件入口实现按需重连；确保 Tokio service 不再因保活周期唤醒或发送控制包。
3. **恢复与低损耗验证**：覆盖断连后首次业务、恢复队列 FIFO、队满/过期、恢复凭据有效/失效、server route 迁移/过期释放和迟到旧 session record 拒绝。
4. **性能与可观测性**：增加 idle、持续业务和断连恢复基准；指标改为认证业务活动、按需重连、队列原因和恢复耗时。空闲已建立会话在观测窗口内的隧道发送包数必须为零（不计外部网络栈行为）。
5. **后续原有路线**：在无心跳会话通过验收后，继续实现 Tokio worker shard/稳定 session 哈希/有界 dispatch、全面观测与 shutdown drain、Cookie 密钥轮换和来源 IP 归一化；之后进入 Linux FakeTCP、PMTU、route/neighbor Netlink 与 RST guard。

## 验收标准

- v4 client/server 在内存 transport 和托管 UDP harness 上完成双向业务数据与恢复测试，且不存在任何 heartbeat 收发。
- 已建立但无业务的 client/server 在超过至少两个旧 heartbeat 周期的测试窗口内不发送 tunnel frame；定时器不产生仅为保活而存在的网络动作。
- 静默后本地首个数据报到达时：认证 server 活性未过期则直接发送；已过期则先发起握手并将数据报有界排队，绝不先使用旧 session 发送。
- 握手/恢复成功后未过期数据报 FIFO 投递；队满、超时、失败和关闭均有可测的显式丢弃原因；不会重复发送已成功交给 transport 的业务数据。
- 未认证、篡改、重放或旧 session 输入不能刷新活动时间、阻止按需重连、创建 conversation 或投递明文。
- `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` 以及相关 fuzz/property 测试均通过。
