# 当前实施状态

## 本轮目标

本轮只建立可演进、默认安全失败的最小脚手架，不尝试一次完成完整系统。

## 已实现

- Cargo workspace 和三个 crate 的单向依赖关系；
- 平台无关核心事件/动作 API 原型；
- 基础帧格式、长度上限和畸形输入拒绝；
- conversation 映射、容量和隔离原型；
- 防重放滑动窗口；
- PSK 输入的基本安全封装；
- Linux transport trait 及不可用占位实现；
- CLI 参数面和托管服务类型骨架；
- 单元测试、帧解码 fuzz target。

## 明确未实现

- HKDF-SHA256、方向密钥派生和 transcript；
- 三段式认证握手和 session 恢复；
- ChaCha20-Poly1305、XChaCha20-Poly1305、AES-GCM、认证明文模式；
- 加密帧 record layer；
- FakeTCP 状态机和 IP/TCP 报文编解码；
- Raw socket、AF_PACKET、cBPF、route/neighbor Netlink；
- nftables Netlink 和 legacy iptables 后端；
- PMTU 探测、可信 ICMP 关联和 MTU 事件；
- worker shard、有界运行时队列、真实 UDP upstream；
- heartbeat、超时、重连和恢复；
- IPv6。

## 当前安全边界

当前 `WireFrame` 只提供结构校验，不提供机密性、真实性或完整性。任何网络来源都不可信。CLI 在正常运行路径中始终拒绝启动，Linux transport 的所有操作也返回 `NotImplemented`，避免静默降级。

## 下一阶段建议

1. 固化握手与 record layer 状态模型；
2. 通过标准 RustCrypto crates 实现 HKDF、HMAC 和所有 AEAD 套件；
3. 将 replay window 接入“认证成功后、明文投递前”的唯一入口；
4. 添加纯内存双端 transport 和错误密钥/篡改/重放测试；
5. 再开始 Tokio shard 和 Linux FakeTCP 层。

该阶段不需要 root、`CAP_NET_RAW`、network namespace 或 Netfilter 权限。真实 Linux 网络层阶段才需要这些条件。
