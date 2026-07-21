# `udp2raw-ng`：以可复用库为核心的 Rust FakeTCP UDP 隧道

你是一名精通 Rust、Linux 网络编程、Raw Socket、AF_PACKET、多线程架构、TCP 报文构造与现代密码协议的高级系统工程师。

请从零实现一个名为 `udp2raw-ng` 的 Linux 网络工具与 Rust 库生态。

它是一个高性能、安全、可维护的 UDP 数据报隧道：默认将 UDP payload 加密、认证后封装进伪造的 TCP 风格原始 IP 报文（FakeTCP），通过公网发送到对端；对端解封装后转发给指定的 UDP upstream。为低 CPU 场景，允许显式选择 AES 硬件加速套件，或选择“明文但仍认证”的无加密模式。

**高性能、低 CPU 占用、低内存占用**是本项目的核心目标。在相同机器配置、网络条件、报文大小、并发度和安全套件下，本项目应以相较同类型程序实现更高速度与吞吐量、更低 CPU 占用和更低内存占用为优化方向，并通过公平、可重复的基准测试验证；性能优化不得削弱安全性和协议正确性。

这是一个全新设计。不要复用、模仿、兼容或参考任何已有实现的代码、网络协议、握手格式、TCP 指纹、密码构造、命令行格式或内部架构。

项目必须采用 **library-first** 设计：

- 核心协议、会话管理、加密、防重放和 conversation 多路复用应以 Rust library 的形式实现；
- 官方 CLI 程序只是该库的一个完整、开箱即用的宿主；
- 其他 Rust 程序可以嵌入该库，复用隧道协议和会话能力；
- 不应要求嵌入方直接理解或操作内部协议状态；
- raw socket 与 Linux 权限相关能力必须是可选的 Linux 适配层，而不是核心协议库的强制依赖。

---

## 1. 核心语义与边界

`udp2raw-ng` 不是 TCP 代理，不建立真实 TCP 字节流。

FakeTCP 仅是外层伪装和会话外观。它模拟 TCP 三次握手、序列号、确认号、窗口和可选 TCP options，但实际承载的内容始终是独立的数据报。

系统语义：

- UDP 风格实时传输；
- 不保证可靠传输；
- 不保证有序到达；
- 不实现重传；
- 不实现拥塞控制；
- 不实现 TCP 流控；
- 不实现 TCP 字节流拼接或拆分；
- 数据可能丢失、重复或乱序；
- 上层应用自行决定是否处理可靠性或顺序；
- 隧道层负责可选加密、强制认证、防重放、会话保活、自动重连和恢复。

外层 transport 仅支持 FakeTCP。

---

## 2. 项目组成与 crate 工作区

实现为 Cargo workspace，至少包括以下 crate：

```text
udp2raw-ng/
├── Cargo.toml
├── crates/
│   ├── udp2raw-ng-core/
│   ├── udp2raw-ng-net/
│   └── udp2raw-ng/
├── tests/
├── fuzz/
└── docs/
```

### 2.1 `udp2raw-ng-core`

这是平台无关、可嵌入、可测试的核心库。

职责：

- 协议版本与帧编码/解码；
- 安全握手；
- PSK 密钥派生；
- AEAD 加密与认证；
- 防重放滑动窗口；
- session 状态机；
- 心跳、超时和重连决策；
- stable client identity 或 session 恢复凭据；
- UDP conversation 多路复用；
- 会话恢复；
- 限流、容量控制和状态事件；
- 不依赖 Tokio；
- 不依赖 raw socket；
- 不依赖 Linux syscall；
- 不依赖 CLI；
- 不要求 root 或任何 Linux capability。

核心库必须能被纯内存 transport 和测试 harness 驱动。

### 2.2 `udp2raw-ng-net`

这是运行于用户态的 Linux 网络适配库。

职责：

- Raw IP socket；
- `AF_PACKET` 接收；
- classic BPF（cBPF）socket filter；
- IPv4、IPv6、TCP 头部构造和解析；
- Ethernet 与常见单层 VLAN 解析；
- TCP/IP 校验和；
- `SO_BINDTODEVICE`；
- socket buffer 设置；
- netlink 路由与邻居查询；
- 可选二层发送；
- Linux 权限和 capability 检查；
- 通过原生 nftables Netlink API 创建、验证、更新和清理本程序专属的 Netfilter RST 抑制链与规则；
- 可选通过受控 FFI 管理 legacy iptables；不得通过拼接 shell 字符串执行 `iptables` 或 `nft` 外部命令；
- 可选的 Tokio I/O 集成。

该 crate 可依赖 `udp2raw-ng-core`，但 `udp2raw-ng-core` 不得反向依赖它。

`udp2raw-ng-net` 是唯一允许在用户态管理 RST 抑制资源的 crate：它负责通过 Netlink 管理 nftables 规则，并可选管理 legacy iptables 规则；它不得通过外部 shell 命令修改防火墙。

### 2.3 `udp2raw-ng`

这是官方命令行 crate，Cargo package 名称和最终二进制名称均为 `udp2raw-ng`。

职责：

- 提供 `client` 与 `server` 子命令；
- 解析 CLI 参数；
- 读取密钥；
- 创建 Tokio 多线程运行时；
- 组装 `udp2raw-ng-core` 与 `udp2raw-ng-net`；
- 提供托管服务 API，管理 UDP listener、raw packet I/O、worker shard、定时器、日志和状态输出；
- 提供环境检查与 Netfilter 规则生命周期管理；
- 不实现核心协议逻辑，不重复实现会话状态机。

---

## 3. 官方 CLI 的运行模式

工具必须提供两个子命令：

```text
udp2raw-ng client [OPTIONS]
udp2raw-ng server [OPTIONS]
```

### 3.1 Client

Client 的职责：

1. 在本地监听普通 UDP 地址，例如 `0.0.0.0:3333`；
2. 接收本地 UDP 应用发送的数据；
3. 按 UDP 对端地址识别或新建 conversation；
4. 将 `conversation_id` 与 UDP payload 交给核心库；
5. 从核心库获得待发送的加密隧道帧；
6. 使用 FakeTCP raw packet 将帧发送到远端 server；
7. 通过所选 `rst-guard` 后端抑制内核 TCP RST，并由 AF_PACKET 接收 FakeTCP packet，随后交给核心库验证和解密；
8. 将还原的 UDP payload 发送回对应的本地 UDP 对端；
9. 一个 client 必须支持多个本地 UDP 对端，它们共享一个逻辑 session。

### 3.2 Server

Server 的职责：

1. 在指定 IP 与端口通过 AF_PACKET 接收 FakeTCP raw packet，例如 `0.0.0.0:4096`；
2. 管理多个独立 client session；
3. 完成 FakeTCP 外层握手和内层安全握手；
4. 解密并验证来自 client 的 UDP 数据帧；
5. 将 payload 转发到固定 UDP upstream，例如 `127.0.0.1:7777`；
6. 接收 upstream 的 UDP 回包；
7. 将回包交给核心库编码为对应 conversation 的隧道帧；
8. 使用 FakeTCP raw packet 发回正确 client；
9. 严格隔离不同 client 与不同 conversation，绝不能串流。

数据路径：

```text
本地 UDP 应用
    │ 普通 UDP
    ▼
udp2raw-ng client
    │ 加密、认证的 FakeTCP 原始 IP 报文
    ▼
公网 / NAT / 防火墙
    ▼
udp2raw-ng server
    │ 普通 UDP
    ▼
固定 UDP upstream 服务
```

---

## 4. 嵌入式库 API 设计

核心库必须提供稳定、清晰、文档化的 Rust API。

不要强迫嵌入方：

- 直接管理 packet number；
- 手动维护 replay window；
- 手动追踪握手状态；
- 手动派生密钥；
- 手动处理 session 恢复；
- 了解完整 FakeTCP 报文细节。

建议将 API 设计成事件驱动的引擎模型。

### 4.1 核心引擎

提供类似如下的高层概念：

```rust
Engine
EngineConfig
ClientEngine
ServerEngine
SessionHandle
ConversationId
PeerId
TunnelEvent
TunnelAction
```

核心库接收输入事件，返回需执行的动作：

```text
输入事件：

- 本地 UDP 数据到达；
- 已收到并提取的隧道帧；
- 定时器推进；
- 网络路径变化；
- 显式请求重连；
- session 或 conversation 清理请求。

输出动作：

- 发送加密隧道帧；
- 向某个本地 UDP 对端发送 payload；
- 向某个 upstream UDP socket 发送 payload；
- 创建或关闭 conversation；
- 创建、恢复或销毁 session；
- 安排下一次定时器；
- 记录可观测事件；
- 拒绝、丢弃或限流某个输入。
```

核心库不应在同步 API 内部执行网络 I/O。调用方负责执行 `TunnelAction` 并将结果重新输入引擎。

### 4.2 面向嵌入方的两层 API

提供两套 API。

#### 数据报引擎 API

适合已有网络循环、用户态网络栈、测试程序或自定义 I/O 的程序。

调用方可以：

1. 提交明文 UDP 数据；
2. 得到加密隧道帧；
3. 通过自有 transport 发送；
4. 提交接收到的隧道帧；
5. 得到应投递给本地 UDP 或 upstream 的明文数据；
6. 周期性调用时间推进接口；
7. 读取状态与指标。

该 API 不依赖 Tokio。

#### 托管服务 API

适合希望快速嵌入的 Tokio 程序。

该 API 不属于 `udp2raw-ng-core`。它应由官方 `udp2raw-ng` crate 提供，依赖 `udp2raw-ng-core`，并可选择接入 `udp2raw-ng-net`；`core` 仍保持同步、事件驱动且不执行 I/O。

提供可选的高级服务封装，例如：

```rust
ClientService
ServerService
ServiceBuilder
```

它们可以：

- 管理 UDP socket；
- 管理 worker shard；
- 管理定时任务；
- 接受自定义 `PacketTransport`；
- 暴露 session 事件、指标与关闭控制。

该托管 API 不应隐藏权限需求：如果调用方选择 Linux raw transport，调用方所在进程仍需要 root 或 `CAP_NET_RAW`。

### 4.3 可替换 transport 抽象

定义平台无关的 transport trait，例如：

```rust
trait PacketTransport {
    type Error;

    fn send(&mut self, packet: OutboundPacket) -> Result<(), Self::Error>;

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<InboundPacket, Self::Error>>;
}
```

或为异步环境定义等价 `async` trait / stream API。

抽象边界要求：

- `udp2raw-ng-core` 处理加密的隧道帧；
- `udp2raw-ng-net` 负责将帧放入 FakeTCP payload，并收取和解析 FakeTCP packet；
- 调用方可以实现自己的 transport；
- 测试可使用内存双向 transport；
- CLI 使用官方 Linux FakeTCP transport；
- 外层 TCP/IP 包头不作为安全边界；
- 所有安全校验仍由核心协议层执行。

---

## 5. 明确的非目标

以下内容不在项目范围内：

- 不支持 UDP、ICMP 或真实 TCP 作为外层 transport；
- 不建立真实 TCP socket 数据流；
- 不实现 TCP 重传、拥塞控制、可靠交付、流控或字节流语义；
- 不支持 Windows 和 macOS；
- 不支持任何配置文件，包括 TOML、JSON、YAML、INI 或自定义格式；
- 不自动读取默认配置文件；
- 所有运行参数只能通过 CLI、环境变量或受限权限的密钥输入方式提供；
- 不与任何外部实现进行协议级互通；
- 不使用 MD5、CRC32、XOR、固定 IV CBC、无认证加密或弱校验和；
- 不在 tunnel 内实现 IP 分片重组；
- 不支持 TC eBPF、netfilter queue、内核模块或未列出的 RST 抑制后端；
- 不通过调用 `nft`、`iptables` 或 shell 命令操作防火墙；
- 不依赖 shell 字符串拼接执行核心网络功能；
- 不承诺规避任何网络限制；
- 文档必须提醒使用者遵守网络、服务商和所在地的法律、协议与政策。

---

## 6. 多线程架构

项目必须支持多线程并发，且应充分利用多核 CPU。

使用“多线程运行时 + session 分片 + 有界队列”的模型。不要使用一把全局锁保护所有 session。

### 6.1 运行时

使用 Tokio multi-thread runtime：

```rust
#[tokio::main(flavor = "multi_thread")]
```

增加 CLI 参数：

- `--workers <N>`：Tokio worker 线程数；
- `--packet-workers <N>`：session / packet worker shard 数；
- `--io-threads <N>`：raw I/O 专用线程数；
- `--queue-capacity <N>`：内部有界队列容量。

默认 worker 数量应为逻辑 CPU 数量或经过合理限制的值。

### 6.2 Session 分片

根据已认证 `session_id` 做稳定哈希，将同一 session 始终分配到同一 shard。

要求：

- 同一 session 的 session state、packet number、replay window、conversation 表尽量只由一个 shard 串行访问；
- 不同 session 可以并行处理；
- 同一 session 不应因每包加锁而产生严重竞争；
- 在 session 恢复或外层 peer 地址变化时，session 仍保持在原 shard；
- server 的未知握手包可使用来源信息和短生命周期状态做初步分流；
- 不能让未经认证输入诱导昂贵 session 分配。

### 6.3 I/O 和计算分离

- AF_PACKET/raw socket 接收可在专用 I/O 线程或 Tokio task 中运行；
- 轻量过滤可在 I/O 阶段完成；
- 高开销 TCP/IP 解析、AEAD 加解密和 session 状态更新分派给 shard；
- 发送路径应避免所有 worker 竞争一个全局发送锁；
- 允许使用单独发送任务或按接口分片发送任务；
- channel 必须有界；
- channel 满时采用明确丢弃/背压策略，并记录指标。

### 6.4 定时器

不要为每个 conversation 创建独立线程或独立昂贵计时器。

使用分片定时器、时间轮或周期任务处理：

- heartbeat；
- 握手重试；
- session 超时；
- conversation 超时；
- session ticket 失效；
- 指标聚合；
- 队列与过载检测。

---

## 7. 仅 CLI 的命令行设计

不支持配置文件。

示例：

```text
udp2raw-ng client \
  --listen 0.0.0.0:3333 \
  --peer 203.0.113.10:4096 \
  --secret-file /etc/udp2raw-ng/client.secret \
  --bind-interface eth0 \
  --workers 4

udp2raw-ng server \
  --listen 0.0.0.0:4096 \
  --upstream 127.0.0.1:7777 \
  --secret-file /etc/udp2raw-ng/server.secret \
  --bind-interface eth0 \
  --workers 4
```

通用参数：

- `--listen <IP:PORT>`
  - client：本地普通 UDP 监听地址；server：FakeTCP raw listener 的本地地址和端口；必填。
- `--secret-file <PATH>`
  - 从文件读取预共享密钥（PSK）；应拒绝或高优先级警告权限过宽的密钥文件。
- `--secret-env <VARIABLE>`
  - 从指定环境变量读取 PSK；适合由 systemd、容器编排或密钥注入系统提供密钥。
- `--secret-stdin`
  - 从标准输入读取 PSK；适合交互式启动或由受控父进程传递密钥。
- `--secret <VALUE>`
  - 直接从命令行读取 PSK，仅用于测试；必须警告其可能出现在进程列表、shell 历史或审计日志中。
- `--crypto <chacha20poly1305|xchacha20poly1305|aes128gcm|aes256gcm|none>`
  - 默认 `chacha20poly1305`；
  - `chacha20poly1305` 使用由每方向随机 nonce prefix 和单调 `packet_number` 构造的 96 位唯一 nonce，适合作为默认的通用、低 CPU 套件；
  - `xchacha20poly1305` 使用 192 位 nonce，适合需要更大 nonce 空间或自定义 transport 的嵌入式调用方；
  - `aes128gcm` 与 `aes256gcm` 在 CPU 与所选加密库支持时自动使用 AES-NI、ARMv8 Crypto Extensions 或等价硬件加速；硬件不可用时自动回退到经验证的软件实现，并在启动日志和指标中明确标示；
  - `none` 表示不加密 payload，但仍使用基于派生方向密钥的强认证、握手认证与防重放；不得将其解释为关闭安全校验；
  - 双端必须协商并使用相同套件，协商结果必须被握手 transcript 认证和数据帧受认证上下文绑定。
- `--bind-interface <INTERFACE>`
  - 将 raw socket 与 AF_PACKET 绑定到指定网卡；可减少无关报文并确保从预期接口收发。
- `--workers <N>`
  - Tokio 多线程 runtime 的 worker 线程数；默认使用逻辑 CPU 数量或实现设定的安全上限。
- `--packet-workers <N>`
  - session/packet shard 数；同一 session 固定映射至一个 shard，不同 session 可并行处理。
- `--io-threads <N>`
  - raw I/O 专用线程数；用于 AF_PACKET 或发送路径，避免网络 I/O 阻塞协议处理。
- `--queue-capacity <N>`
  - 内部有界队列的每队列容量；队列满时按既定背压策略丢弃并计数，而不是无限占用内存。
- `--socket-buffer-kib <N>`
  - socket 收发缓冲区目标值，单位 KiB；系统拒绝或截断该值时必须记录实际生效值。
- `--mtu-probe <auto|off>`
  - 默认 `auto`；控制是否主动探测隧道可安全承载的最大 UDP payload。
  - `auto`：安全握手完成后进行双向认证探测；路径变化、重连、收到可信 ICMP "Packet Too Big"/"Fragmentation Needed" 或检测到大包黑洞后重新探测。稳定且存在业务流量时，最多每 10 分钟执行一次带随机抖动的低频上探，以尝试恢复先前下调的有效值。
  - `off`：不发送主动探测包，也不执行周期性上探；仅使用绑定接口、路由和保守协议开销推导初始有效 payload MTU。运行中收到可信 PMTU 下降信号或检测到大包黑洞时，仍必须下调当前有效值；在同一次 session 存续期间不得主动增大。
- `--max-sessions <N>`
  - server 最大已认证 client session 数；超过后拒绝新的合法会话建立。
- `--max-pending-handshakes <N>`
  - 全局最大未认证握手状态数；用于限制握手洪泛造成的 CPU 和内存消耗。
- `--max-conversations <N>`
  - 单个 session 最多可创建的 UDP conversation 数。
- `--conversation-idle-secs <N>`
  - conversation 无收发活动后的回收时间，单位秒；默认建议 180 秒。
- `--ttl <N>`
  - IPv4 外层报文 TTL，范围必须为 1–255。
- `--hop-limit <N>`
  - IPv6 外层报文 hop limit，范围必须为 1–255；仅 IPv6 transport 生效。
- `--log-level <error|warn|info|debug|trace>`
  - 控制结构化日志详细程度；生产环境默认 `info`，`debug`/`trace` 只用于短时排障。
- `--rst-guard <auto|nftables|iptables|manual>`
  - 默认 `auto`：优先通过原生 nftables Netlink API 管理专属规则；nftables 不可用时才尝试 legacy iptables 兼容后端；自动选择和原因必须记录到日志；
  - `nftables`：强制使用原生 nftables Netlink 后端；不调用 `nft` 命令；
  - `iptables`：仅用于明确需要 legacy xtables 的环境；优先使用受控 FFI 后端，不调用 `iptables` 命令；若后端不可用则拒绝启动；
  - `manual`：程序不创建、修改或删除 RST 抑制规则；管理员必须事先完成等效防护，程序启动时只做能力检查并输出明确风险警告；
  - 除 `manual` 外，选定后端初始化、规则安装或运行中健康检查失败时必须安全停止 FakeTCP transport。
- `--rst-guard-lifecycle <managed|manual>`
  - 仅适用于 `nftables` 和 `iptables`；默认 `managed`；
  - `managed`：程序只创建和删除拥有项目私有表、链、comment 与所有权标记的规则；
  - `manual`：程序不修改规则，只验证管理员预置的精确匹配规则存在且有效；
- `--check-environment`
  - 检查 `CAP_NET_RAW`、raw socket、AF_PACKET、接口、路由、端口、MTU 和所选 RST 后端所需 capability；
  - `auto` 模式进行无副作用的 nftables Netlink 探测，并在必要时探测 legacy iptables 后端；
  - 输出最终选择或可选择的 RST 后端及原因；不调用任何外部防火墙命令。
- 禁止提供关闭帧认证或握手认证的参数，例如 `--disable-authentication`、`--no-auth` 或等价选项。

Client 专用参数：

- `--peer <IP:PORT>`
  - 远端 server 的 FakeTCP 地址和端口；client 必填。
- `--source-ip <IP>`
  - 强制外层 raw IP 源地址；默认依据选定接口和路由自动选择。
- `--source-port <PORT>`
  - 强制 FakeTCP 外层源端口；默认重连时随机更换端口以提升 NAT/网络切换恢复能力。固定该值会降低恢复弹性。
- `--heartbeat-ms <N>`
  - client 发送认证 heartbeat 的间隔，单位毫秒；默认建议 750 ms。
- `--session-timeout-secs <N>`
  - client 在未收到可信 server 方向数据或 heartbeat 后判定 session 失效并重连的时间，单位秒；默认建议 10 秒。
- `--reconnect`
  - 启动完成后立即丢弃当前底层路径状态并发起一次新的 FakeTCP 与安全握手；用于管理员明确要求重建连接的场景。

Server 专用参数：

- `--upstream <IP:PORT>`
  - server 解封装后转发至的固定 UDP 上游地址；server 必填。
- `--handshake-limit-per-ip <N>`
  - 单个源 IP 可同时保有的未认证握手状态上限；用于限制单来源握手洪泛。
- `--session-idle-secs <N>`
  - server 无活动 session 的回收时间，单位秒；只有该 session 不再拥有活跃 conversation 时才可回收。

禁止提供：

```text
--config
--config-file
--settings
--load-config
--print-firewall-rules
--install-firewall-rules
--remove-firewall-rules
--mtu
--mtu-warn
```

---

## 8. Conversation 多路复用

Client：

- 本地 UDP 对端 `SocketAddr` 标识一个 conversation；
- 首次见到对端时生成安全随机的 64 位 `conversation_id`；
- 维护：
  - `SocketAddr -> ConversationId`
  - `ConversationId -> SocketAddr`
  - 最后活动时间
  - 收发统计
- 所有 conversation 共享一个逻辑 client session；
- 达到上限时拒绝新 conversation；
- 空闲超时后回收。

Server：

- 使用 `(authenticated_session_id, conversation_id)` 唯一标识 conversation；
- 每个 conversation 使用一个 connected UDP socket，连接固定 `--upstream`；
- upstream 回包只允许回到对应 conversation；
- 不同 session 即使生成相同 conversation ID，也绝不能串流；
- session 恢复时应保留 conversation 与 upstream socket。

应用帧至少包含：

```text
protocol_version
session_id
packet_number
frame_type
conversation_id
payload_length
payload
```

所有网络输入都必须进行长度、版本、类型和容量检查。

---

## 9. 安全协议

设计全新的、版本化、安全协议。

### 9.1 密钥与加密

- 使用 PSK 建立双方信任；
- 每个新 session 使用随机 client nonce、server nonce 与 session salt；
- 使用 HKDF-SHA256 派生密钥；
- client-to-server 与 server-to-client 必须使用独立密钥；
- 默认 AEAD：`ChaCha20-Poly1305`。每个方向使用随机 nonce prefix 与单调递增 `packet_number` 构造 96 位 nonce；同一方向密钥下 nonce 绝不能复用；
- 支持 `XChaCha20-Poly1305` 作为可选套件，使用更大的 192 位 nonce；
- 支持 `AES-128-GCM` 与 `AES-256-GCM`：实现必须优先使用经验证的加密库提供的运行时 CPU 特性检测，在 x86_64 上使用 AES-NI，在 aarch64 上使用 ARMv8 Crypto Extensions 或等价硬件加速；硬件加速不可用时自动回退到经验证的软件实现，并在启动日志和指标中标示；不得自行编写或嵌入未经审计的 AES 汇编实现；
- 提供 `none` 套件用于明确的低 CPU 场景：payload 不加密，但所有握手、控制帧、心跳和数据帧仍必须有基于方向派生密钥的强完整性认证；
- `none` 套件的数据帧认证应使用独立 MAC 密钥，例如 HMAC-SHA-256 或等价的标准、带密钥 MAC；不得用裸 SHA、CRC、MD5 或简单 checksum 替代；
- 无论选择哪一种套件，都必须验证来源于已认证握手的 session、受认证上下文、帧长度、packet number 和 replay window；
- 禁止提供同时关闭加密和认证的模式；
- 外层 TCP/IP header 不承担安全职责。

套件选择与安全语义：

| 套件 | 机密性 | 完整性与身份认证 | 推荐场景 |
|---|---|---|---|
| `chacha20poly1305` | 有 | AEAD | 默认；跨平台、低 CPU 开销，适合使用单调包号的会话协议。 |
| `xchacha20poly1305` | 有 | AEAD | 需要更大 nonce 空间或自定义 transport 的嵌入式场景。 |
| `aes128gcm` | 有 | AEAD | CPU 支持 AES 硬件加速时的高性能部署；密钥更短。 |
| `aes256gcm` | 有 | AEAD | CPU 支持 AES 硬件加速、且需要 256 位 AES 密钥的部署。 |
| `none` | 无，公网可见明文 | 强 MAC、认证握手、防重放 | 仅在链路已由其他机制提供机密性，或明确接受明文暴露时使用。 |

启动时必须记录协商后的套件和硬件加速状态，但不得记录密钥、nonce、明文或认证标签。选择 `none` 时必须输出高优先级警告，说明流量内容对路径上的观察者可见。

### 9.2 握手

实现三段式握手：

```text
ClientHello -> ServerHello -> ClientFinish
```

要求：

- 协议版本协商；
- client 与 server nonce；
- 随机、不可预测的 session ID；
- stable identity 或带过期时间的恢复凭据；
- 基于 PSK 的 transcript 认证；
- 防伪造、防降级和资源耗尽；
- FakeTCP 完成三次握手后，仍必须完成安全握手才能发送业务数据；
- 不以源 IP 或源端口作为逻辑 client 的唯一身份；
- 未认证握手状态必须有来源级和全局级上限、超时和限速。

### 9.3 数据帧

每个 session 的每个方向维护独立 64 位递增 `packet_number`。

受认证上下文至少绑定：

- 协议版本；
- session ID；
- packet number；
- frame type；
- 传输方向；
- 必要的外层上下文。

AEAD 套件将上述字段作为 associated data；`none` 套件必须将同一组字段纳入 MAC 输入。两种模式都不得遗漏 session ID、packet number、方向、frame type 或长度绑定。

nonce 从方向专属随机 prefix 和 `packet_number` 派生。

要求：

- 同一密钥下 nonce 绝不能复用；
- packet number 接近溢出时必须 rekey 或重新握手；
- 协议字段预留密钥轮换能力；
- 不允许密文被改动后仍被接受。

### 9.4 防重放

- 每个方向维护滑动窗口；
- 默认窗口大小 4096；
- 接受窗口内尚未出现的乱序包；
- 拒绝重复包；
- 拒绝过旧包；
- 认证失败、重放、未知 session 和格式错误分别计数；
- 防重放保护在所有构建和运行模式下均不可禁用。

---

## 10. Session、保活与恢复

逻辑状态：

```text
Idle -> Handshaking -> Ready -> Reconnecting -> Ready
                         └-> Closed
```

Client：

- 启动后主动发起 FakeTCP 和安全协议握手；
- `Ready` 状态下周期性发送加密 heartbeat；
- 超时未收到可信 server 数据时进入 `Reconnecting`；
- 默认更换随机 FakeTCP source port；
- 固定 `--source-port` 时需警告恢复能力下降；
- 重连后恢复已有 conversation；
- 非 `Ready` 状态下，本地 UDP 数据仅允许短暂进入严格有界队列；
- 超出队列时丢弃并记录指标。

Server：

- 通过认证的 stable identity 或恢复凭据识别逻辑 client；
- 同一 client 从新地址或新端口重连后，更新外层 peer 地址；
- 保留已有 conversation 与 connected upstream socket；
- 对旧路径迟到包执行严格认证和状态检查；
- 清理过期 session 与 conversation。

建议默认值：

- heartbeat：750 ms；
- handshake retry：1 s；
- handshake timeout：5 s；
- client session timeout：10 s；
- conversation idle timeout：180 s；
- replay window：4096。

所有时间计算必须使用单调时钟。

---

## 11. FakeTCP 与 Linux 网络层

FakeTCP 最小状态机：

```text
Client                                     Server
SYN  ----------------------------------->
     <-----------------------------------  SYN-ACK
ACK  ----------------------------------->
安全握手 + 加密隧道帧  <----------------->  安全握手 + 加密隧道帧
```

必须实现：

- 随机 ISN；
- SYN、SYN-ACK、ACK 与数据包；
- flags、seq、ack、源/目的地址和端口的状态一致性校验；
- 无效 ACK、重复 SYN、RST、超时和状态错误处理；
- 内层认证完成前拒绝业务数据；
- 每个加密帧独立作为 TCP payload；
- 不实现 TCP 字节流或重传；
- seq/ack 仅用于维持一致的 FakeTCP 外观。

支持 TCP options：

- MSS；
- Window Scale；
- SACK Permitted；
- Timestamp；
- NOP；
- EOL。

要求：

- option 长度 4 字节对齐；
- 安全处理损坏 options；
- 提供 `basic` 与 `realistic` 策略；
- 不模拟特定系统或工具的指纹。

Linux 实现：

- raw socket 发送手工构造的 IP/TCP packet；
- 默认 Netfilter 模式使用 AF_PACKET 接收 FakeTCP packet；其专属 nftables 或 legacy iptables 规则必须在内核 TCP 栈处理前丢弃精确匹配的目标入站 packet，以抑制自动 RST；
- `manual` 模式允许 AF_PACKET 接收，但管理员必须预先安装等效的 RST 抑制机制；
- BPF 尽早过滤无关流量；
- 支持 IPv4，架构上预留 IPv6；
- 正确计算 IPv4 header checksum 和 TCP pseudo-header checksum；
- 后续完成 IPv6 与 IPv6 TCP checksum；
- IPv4 外层 packet 必须设置 DF（Don't Fragment）位；IPv6 外层 packet 不得添加 Fragment Header；程序不得把超过当前有效上限的 packet 交给内核分片；
- 入站外层 IPv4 分片或带 IPv6 Fragment Header 的 packet 不得进入正常 tunnel 数据路径；不在用户态重组它们；
- 支持 `SO_BINDTODEVICE`；
- 支持 socket buffer 设置；
- 可选二层发送，应使用 netlink 路由/邻居信息或要求用户明确提供接口与 MAC；
- 不以 `/proc` 文本解析作为核心路由方案。

### 自动 Path MTU 管理

- 不提供 `--mtu` 或 `--mtu-warn`；普通用户不需要计算或手工设置 MTU；
- 启动时根据绑定接口、路由和 IPv4/IPv6、TCP options、隧道帧及所选加密套件的实际开销计算本地理论上限；
- 安全握手完成后、初始主动探测尚未完成时，业务数据必须使用由本地理论上限减去保守开销得到的安全下限；不得因等待探测而无限缓存、阻塞或拒绝所有本地 UDP 数据；
- 初始探测超时或失败时，继续使用最近已确认的值；若不存在已确认值则使用该安全下限，并记录探测失败；只有无法得出任何有效安全下限时才拒绝业务数据；
- `--mtu-probe auto` 时，client 与 server 在安全握手完成后，使用带认证的 padding probe 和确认帧对 client→server、server→client 两个方向分别进行应用层 PMTU 探测；
- probe ID、探测长度、方向和确认帧都必须在认证保护内；不得将普通 TCP ACK、未认证控制帧或普通业务 UDP 丢包当作 PMTU 成功/失败依据；
- 探测必须由小到大或二分搜索最大可确认的外层报文长度，并从中扣除实时协议开销，得到每方向有效 UDP payload MTU；探测上限取本地路由 MTU、绑定接口 MTU 与实现安全上限三者的较小值；
- 探测包必须使用与该 session 正常数据包相同的 IP 版本、最大可能 TCP options、隧道帧格式、加密/MAC tag 和外层开销；安全握手完成后这些会影响开销的策略不得在未重新探测前增大；
- `auto` 模式以事件触发为主：重连、路径变化、收到可信 ICMP "Packet Too Big"/"Fragmentation Needed"，或由连续失败的认证 probe 确认大包黑洞时必须重新探测或下调；不能只依赖 ICMP，也不得仅凭普通 UDP 丢包判定黑洞；
- 仅接受能引用近期本程序发送 packet、并与本地/远端地址、端口、协议和必要标识匹配的 ICMP PMTU 信号；不可信或无法关联的 ICMP 只能记录诊断，不得降低有效 MTU；
- `auto` 模式在路径稳定且存在业务流量时，最多每 10 分钟进行一次带随机抖动、限速的低频上探；它不是按秒持续探测，避免影响业务流量；
- `--mtu-probe off` 时不主动探测或上探，使用本地理论上限减去保守开销后的值；收到可信 PMTU 下降信号或检测到大包黑洞时仍必须下调当前有效值，但在同一次 session 存续期间不得主动增大；
- 不在隧道内实现分片或重组；超过当前方向有效 payload MTU 的本地数据报必须丢弃并限速记录 `mtu_dropped`，不得截断；
- 通过状态与指标公开 `effective_payload_mtu_tx`、`effective_payload_mtu_rx`、探测来源、最近更新时间、探测失败和 MTU 丢弃计数；
- 嵌入式库 API 必须允许调用方读取当前有效 payload MTU，并在值变化时订阅事件，从而由上层 VPN/TUN 或应用自行设置其发送大小；独立 CLI 无法自动修改上层应用的 MTU，持续发送超限 UDP 数据报的上层应用将被丢弃并限速告警。

---

## 12. RST 抑制后端与环境检查

FakeTCP 入站包若进入 Linux TCP 栈，内核可能因不存在对应真实 TCP socket 或状态而自动发送 RST。必须通过 `--rst-guard` 选择一个后端抑制该行为。

```text
入站 FakeTCP packet
        │
        ├─ nftables / iptables（默认 auto）
        │     ├─ AF_PACKET 向用户态提供报文副本
        │     └─ 专属 Netfilter 规则丢弃目标报文，阻止 TCP 栈发送 RST
        │
        └─ manual
              └─ 管理员预置等效保护；程序仅用 AF_PACKET 收包并检查配置
```

### 12.1 Netfilter 后端

- nftables 后端是必须实现的默认路径；必须直接使用 `nf_tables` Netlink API，不调用 `nft` 命令；
- `auto` 默认优先 nftables；只有 nftables Netlink 确实不可用时，才尝试已构建且可用的 legacy iptables 兼容后端；不得仅通过“命令存在”判断后端；
- legacy iptables 后端是可选兼容能力，必须通过受控 FFI 或同等 API 实现，不调用 `iptables` 命令；若该能力未构建、系统不兼容或无法安全支持，则 `--rst-guard iptables` 明确失败，而不是回退到 shell 命令；
- `managed` 生命周期下，规则必须位于项目专属 table/chain 或等价独立命名空间，携带项目私有 comment、版本与所有权标识；
- 规则必须精确匹配接口、入站方向、IP 协议、目的本地地址、FakeTCP 端口，及实现需要的其它地址/tuple 约束；不得丢弃接口上的全部 TCP；
- 正常退出仅删除本程序创建且可验证归属的规则；不清空用户 table、chain 或不属于本程序的规则；
- `manual` 生命周期下，程序以无副作用方式验证管理员预置的等效规则；验证失败时拒绝启动；
- 运行中规则被删除、替换或失效时，受影响 FakeTCP transport 必须安全停止或仅重建可验证归属的自身规则。

### 12.2 Manual 后端

- `manual` 的含义是“管理员手工管理 RST 抑制机制”；
- 程序不得创建、修改或删除 Netfilter 规则；
- 必须在启动日志中输出高优先级提示，说明管理员对 RST 抑制的正确性负责；
- 程序必须以无副作用方式验证管理员预置的等效规则；无法验证或验证失败时拒绝启动；不提供绕过该验证的危险参数。

`--check-environment` 必须输出：候选与最终 RST 后端、自动选择原因、所需 capability、raw socket、AF_PACKET、路由、端口、`--mtu-probe` 模式、本地理论外层上限和初始有效 payload MTU，以及 nftables/iptables 后端可用性与规则所有权冲突。不得调用外部防火墙命令。

---

## 13. 可观测性与资源保护

使用 `tracing` 输出结构化日志。

提供状态或指标：

- 活跃 session 数；
- 活跃 conversation 数；
- 每方向收发包数和字节数；
- 各 worker/shard 包速率；
- 各 worker/shard 队列深度和丢弃数；
- FakeTCP 握手成功和失败；
- 安全握手成功、失败与超时；
- session 重连次数；
- AEAD 认证失败；
- 明文认证模式的 MAC 验证失败；
- 当前协商的加密套件，以及 AES 硬件加速可用性、实际启用状态和软件回退次数；
- replay 丢弃；
- TCP/IP 解析失败和校验和失败；
- 未知 session；
- 每方向有效 payload MTU、探测来源、最近更新时间、探测失败和 MTU 丢弃；
- conversation/session 回收；
- upstream UDP、raw socket 与 AF_PACKET 错误；
- 当前 RST 后端、自动选择原因、Netfilter 规则安装/验证/删除和规则健康状态；
- nftables Netlink 与 legacy iptables 后端的探测、冲突和操作错误；
- 处理延迟统计。

绝不能记录：

- PSK；
- 派生密钥；
- 完整恢复凭据；
- UDP 明文 payload；
- 可复现完整认证材料的敏感数据。

必须限制：

- 最大未认证握手数；
- 单来源未认证握手数；
- 最大 session 数；
- 每 session 最大 conversation 数；
- 每个内部队列容量；
- 单包最大大小；
- 重连频率；
- 日志速率；
- Netfilter 专属规则、链和 table 的最大数量及所有权冲突处理。

---

## 14. 测试要求

### 核心库测试

- 帧编码与解码；
- 任意截断/畸形输入均不能 panic；
- HKDF 方向密钥隔离；
- AEAD 加解密与受认证上下文绑定；
- AES-256-GCM 与 XChaCha20-Poly1305 的向量测试、跨实现互操作测试和方向密钥隔离；
- 在可用的 x86_64 AES-NI 与 aarch64 ARMv8 Crypto 环境中验证 AES-128-GCM 与 AES-256-GCM 的硬件加速检测、自动启用和软件回退行为；
- `none` 套件的明文传输、MAC 验证、篡改拒绝、伪造拒绝与 replay 拒绝；
- 套件协商被篡改、降级或两端配置不一致时必须拒绝建立 session；
- `--mtu-probe auto` 的双向探测、二分搜索、协议开销扣除、重连/路径变化后重新探测、事件触发和低频上探；
- `--mtu-probe off` 的保守推导、可信 PMTU 下降信号和大包黑洞后的下调行为，以及不主动上探的约束；
- probe ID、长度、方向和确认帧的认证绑定；普通 TCP ACK、普通 UDP 丢包和未认证控制帧不得改变有效 MTU；
- 仅可信且可关联近期本程序发送报文的 ICMP PTB/Fragmentation Needed 可降低有效 MTU；
- IPv4 DF、IPv6 无 Fragment Header、外层分片拒绝，以及探测包与正常数据包最大开销一致性；
- 防重放窗口；
- session 状态机；
- 重连与恢复；
- conversation 映射和过期；
- 容量控制与限流；
- 纯内存 transport 的 client/server 端到端测试。

### Linux 网络层测试

- IPv4/TCP 校验和；
- IPv6/TCP 校验和；
- TCP options 编解码、对齐和错误处理；
- Ethernet、VLAN、IP、TCP parser；
- BPF 过滤策略；
- raw packet 构造；
- FakeTCP 握手状态机；
- nftables Netlink 规则创建、查询、精确匹配、所有权验证和安全清理；
- legacy iptables 后端的可用性、受控 FFI 操作和不可用时失败行为；
- `auto` 后端选择优先 nftables、必要时回退 iptables 的行为；
- `manual` 生命周期下对预置规则的无副作用验证；

### 并发测试

- session shard 路由稳定性；
- 多 session 分布到多个 worker；
- 有界队列满载时的背压；
- session 恢复与 upstream 回包并发时不串流；
- conversation 回收与收包并发时不产生数据竞争；
- 使用 `loom` 或其他方法验证关键并发状态。

### 集成测试

- 本地 UDP echo upstream；
- client 到 server 到 upstream 的双向转发；
- 至少 100 个本地 UDP 对端复用一个 client session；
- 至少两个 client 同时连接一个 server，数据完全隔离；
- 错误密钥、篡改包、重放包被拒绝；
- 小范围乱序包在 replay window 内可接受；
- client 更换外层 source port 后恢复既有 conversation；
- Linux network namespace 中执行真实 FakeTCP 端到端测试；
- 多 worker 模式下验证并行处理和队列指标；
- 验证默认 Netfilter 后端在不调用外部命令的情况下阻止内核 TCP RST，且只影响本工具精确匹配的流量；
- 验证 nftables、iptables 和 manual 后端选择失败时不发生静默降级；
- 验证 Netfilter 规则被外部移除、替换或所有权冲突时程序安全停止或只重建可验证归属的自身规则。

必须通过：

```text
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

提供 `cargo-fuzz` target 与使用说明。

---

## 15. 分阶段实施

### 阶段 1：核心库基础

完成：

- Cargo workspace；
- `udp2raw-ng-core`；
- 协议帧；
- 安全握手接口；
- AEAD、HKDF、防重放；
- `ChaCha20-Poly1305`、`XChaCha20-Poly1305`、AES-128-GCM、AES-256-GCM 的硬件加速检测与软件回退，以及明文认证 `none` 套件；
- 自动双向 PMTU 探测与 `--mtu-probe`；
- session 和 conversation 模型；
- 纯内存 transport；
- 单元测试与文档。

### 阶段 2：核心库服务化与并发

完成：

- `Engine` 事件/动作模型；
- client/server 高层 API；
- session shard；
- 有界队列与背压；
- 托管服务 API；
- 多 conversation、多 client；
- connected upstream UDP 逻辑；
- 端到端测试。

### 阶段 3：Linux FakeTCP IPv4 与 RST 抑制后端

完成：

- `udp2raw-ng-net`；
- raw socket、AF_PACKET 诊断、BPF；
- IPv4/TCP 编解码；
- checksum；
- SYN/SYN-ACK/ACK；
- FakeTCP 状态机；
- nftables Netlink RST 抑制后端、专属规则生命周期与 AF_PACKET 生产收包；
- legacy iptables 兼容后端或明确的“不支持即失败”实现；
- `auto|nftables|iptables|manual` 选择、检查与健康状态；
- CLI client/server；
- network namespace 集成测试，验证默认 Netfilter 能阻止内核 TCP RST；
- 验证非目标 TCP 流量不受影响。

### 阶段 4：恢复、RST 抑制生命周期与运维

完成：

- heartbeat；
- 自动重连；
- stable identity 或恢复凭据；
- source port 改变后的 session 恢复；
- Netfilter 规则被删除、替换或所有权冲突后的安全处理；
- 环境检查；
- shard 级指标；
- RST 后端指标；
- 压力与资源限制测试；
- 明确证明程序不调用外部防火墙命令，且只管理可验证归属的 Netfilter 资源。

### 阶段 5：IPv6 与完善

完成：

- IPv6 FakeTCP；
- IPv6 checksum；
- 常见 IPv6 扩展头；
- TCP options 增强；
- 嵌入式库使用文档；
- CLI 部署和排障文档。

每个阶段结束后必须报告：

- 已实现功能；
- 当前限制；
- 当前安全边界；
- 已执行测试及结果；
- 对外公开 API 的变更；
- worker/shard 并发模型；
- 下一阶段需要的权限、内核、network namespace 或 capability 条件。

---

## 16. 最终验收标准

最终交付必须证明：

1. 官方 CLI 可实现双向 UDP 隧道；
2. 外层 transport 仅使用 FakeTCP raw packet；
3. 多个本地 UDP 对端可复用单一 client session，且回包不串流；
4. 多个 client 可并发接入同一 server，且会话严格隔离；
5. 核心能力可由其他 Rust 程序以 library 方式复用；
6. 嵌入方可使用纯内存或自定义 transport，而不强制依赖 Linux raw socket；
7. 使用 Linux FakeTCP transport 的嵌入方能够获得明确的 capability、Netfilter 与内核 RST 诊断；
8. 内层采用版本化握手、HKDF-SHA256、防重放窗口，以及经过认证协商的 `ChaCha20-Poly1305`、`XChaCha20-Poly1305`、AES-128-GCM、AES-256-GCM 或明文认证 `none` 套件；
9. 在支持 AES 硬件加速的 CPU 上，AES-GCM 套件能自动使用经验证的 AES-NI、ARMv8 Crypto Extensions 或等价硬件实现；硬件加速不可用时自动回退到软件实现并记录状态；
10. `none` 模式不加密 payload，但仍验证握手、MAC、受认证上下文和防重放；篡改、伪造或 replay 包必须被拒绝；
11. 错误密钥、篡改包、重放包和非法 FakeTCP packet 不能建立或破坏 session；
12. client source port 变化后可自动恢复既有 conversation；
13. 多线程模式下不同 session 可并行处理，worker/shard 和队列状态可观测；
14. IPv4 完整可用，IPv6 按计划完整实现；
15. 无配置文件支持，所有配置仅通过 CLI、环境变量或密钥输入提供；
16. 默认 `--mtu-probe auto` 可双向确定隧道可安全承载的最大 UDP payload，并在路径变化、重连或黑洞检测后更新；`off` 使用保守推导值；
17. 外层 IPv4 设置 DF、IPv6 不使用 Fragment Header；不重组外层分片，超出有效 payload MTU 的本地数据报被丢弃并限速告警；
18. PMTU 下调只接受认证 probe 失败或可关联近期发送报文的可信 ICMP 信号；普通 UDP 丢包、普通 TCP ACK 或未认证控制帧不得改变有效 MTU；
19. 默认 `--rst-guard auto` 优先使用原生 nftables Netlink；不可用时才尝试 legacy iptables；程序不调用 `nft`、`iptables` 或 shell 命令；
20. Netfilter 后端只管理可验证归属的专属规则，精确匹配本工具 FakeTCP 流量，且不影响非目标 TCP 流量；
21. `manual` 模式不修改系统规则，但必须验证或明确警告外部 RST 抑制责任；
22. 所选 RST 后端不可用、初始化失败、资源被外部移除或健康检查失败时，程序安全失败，不进入可能产生 TCP RST 的静默降级模式；
23. 所有 workspace 格式化、Clippy、单元测试、集成测试和 fuzz/property 测试通过；
24. 在相同硬件、网络条件、报文大小、并发度和安全套件下，通过公平且可重复的基准测试验证吞吐量、CPU 占用和内存占用，并以相较同类型程序达到更高吞吐、更低 CPU 和更低内存为性能目标。
