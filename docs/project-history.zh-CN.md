# Shadow6 项目历史与 Core 演进

## 说明与范围

本文根据当前 Git 仓库和前期考古材料整理，覆盖从 Shadow6 开始开发的
2026-05-31 到 2026-10-02。5.31—9.5 的内容主要来自尚未提交的历史材料；
9.6 起进入可直接追踪的 Git 信史阶段。因此，最早可见提交 `deb56a8a`
（2026-09-06）不是项目起点，只是公开提交时间线的起点。

“Core 首次加入”按该 Core 目录第一次出现在 Git 树中的提交计算。首次出现
不等于功能已经完成：后续提交继续补齐控制面、原生数据面、测试、构建和
跨平台支持。十二个 Core 独立编译、各有协议和平台边界；共享 feature-report
和安全契约词汇，但不因此获得线缆级互操作性。

## 发展阶段

> **历史备注：** Extension 不是 9.6 之前已经独立完成的一条公开时间线。它的
> 思想根源来自 8 月底的平台化重构，9.1—9.6 才逐步整合为 Crosed application
> frame、签名 Plugin 和 typed Slot 的完整机制；当前可见的组合实现提交是
> `12ce0bd`。它一直位于组件层，不改变 Native Core 线缆协议，也不要求 Android
> APK 或 Native Core 重编译。

## 前置考古总览：2026-05-31 至 2026-09-05

### 5.31：Shadow6 的第一次定型

Shadow6 于 2026-05-31 开始开发。最早的 v1.1 原型已经确定 broker、agent、
client 三角色，而不是简单的 client/server；身份、密钥和认证从早期就属于
连接成立的前提。Go 先成为主要实现，5.31 晚 Rust 上位，形成 Go/KCP 与
Rust/QUIC 两条独立原生数据面。两者共享角色、安全和配置理念，却不是同一线缆
协议的两份翻译。

这一阶段还形成了配置驱动、身份优先和异构数据面的基本原则。C11Relay 最初
被设想为 Go/Rust 之间的 C11 桥接器，反映了双核时代试图在数据面解决异构性的
思路；后来它退回固定目标、专用 UDP relay 的组件定位，但代码和性能工程继续
保留至今。

### 6.1—6.7：双核秩序与安全工程化

6 月初的重点从“密码学组件是否正确”扩展到完整安全工程：认证失败、异常状态、
连接生命周期、资源释放、超时、重连、队列和并发都成为正式系统行为。Detector
开始作为流量/行为感知辅助成长，外围管理、诊断、网络控制和运维工具逐渐变厚。
Go/Rust 因而从两个实现变成事实上的制度中心，默认配置、构建、测试和控制路径
都围绕双核组织。

### 6.7—8.28：双核稳定期

这一时期主要是 Go/Rust 原生路径的巩固，以及 C11Relay、Detector、Gate、Guard、
控制、跨平台测试和发布工具的持续扩张。三角色、安全认证、配置驱动和原生数据面
差异没有被抹平；外围平台则开始承担越来越多的管理和安全职责，为后续多 Core
准备了共同的能力词汇。

### 8.29—8.31：平台化重构

8 月底的重点不是拆解 Rust 大文件或重写 Go/Rust 数据面，而是给 Core 周围建立
制度边界：第三方代码进入独立签名 Plugin 进程；Slot 规定允许扩展的位置；Crosed
以 L0—L5、签名请求、能力交集和域策略处理确需 Core 内部能力的场景；strict JSON、
未知字段拒绝、重复键拒绝、帧/队列/连接/TTL 上限逐渐成为统一安全语言。

这次重构还把“按 Core 类型判断”推进为“按 feature-report 和能力合同判断”。
C11Relay 的桥接皇位被取消，但其专用 relay 生命保留；Detector 则从实验性工具
逐步进入“事件—Sentinel—Orchestrator”的分层安全模型。到 8.31，Shadow6 已经
从“Go/Rust 隧道加脚本”变成一个拥有 Core、控制、安全、扩展、检测、构建和发布
制度的平台。Go/Rust 仍占据制度中心，但平台合同已经理论上允许第三个 Core。

### 前置阶段的历史结论

5.31 留下 Broker/Agent/Client、身份认证、配置驱动和异构数据面的基因；6.6—6.7
留下生命周期、资源边界、Detector 和外围控制器官；8.29—8.31 留下 Plugin、Slot、
Crosed、能力合同、严格输入和有界资源制度。9 月新 Core 运动没有推倒这些成果，
而是把原先服务 Go/Rust 的制度推广到十二个 Core。9.1—9.6 的 Extension 整合正
处于这次制度推广的过渡带，随后 9.6 进入可逐提交验证的信史时代。

### 1. 基础双 Core 与可复现构建（2026-09-06）

最早可见提交已经包含 `Core-Go` 和 `Core-Rust`，并以跨平台 CI、权限测试、
Android/原生构建和发布产物为主要工作。随后同日加入 Core-Zig、Core-D 和
Core-Ada，项目从双实现基础扩展为多语言、独立数据路径的 Core 家族。默认
构建逐步固定为最低权限配置，Crosed、应用传输和 Qubes-inspired 域策略
保持关闭。

### 2. 多语言 Core 家族形成（2026-09-07 至 09-12）

Core-Cpp 带来 TLS 1.3 WebSocket 与 SCTP 数据面，Core-Nim 引入基于
libdatachannel 的 UDP 路径，Core-Hare 保留固定路由的受限 UDP 端点，
Core-Gleam 建立 BEAM/Gleam 原生栈，Core-Carp 提供受限 C 编译运行时和
分层加密编解码，Core-Idris 引入依赖类型约束下的安全诊断与固定对等端
数据面。到 Idris 加入时，Core 数量达到十一种。

### 3. Pony、三角色契约与全 Core 验证（2026-09-13 至 09-16）

Core-Pony 于 9 月 13 日加入，补齐第十二个独立实现，并逐步增加认证 UDP、
可靠会话、重传、路由和 OCap 边界。同期项目把 broker/agent/client 三角色、
签名授权、Crosed L5 变体和插件 RPC 收敛为可检查的共享契约；VCore 发现、
统一 CLI 和真实原生基准测试把验证范围扩展到所有 Core/backend 组合。
这些工作同时明确了 legacy 模式、单会话限制、地址族和可选工具链边界。

### 4. 安全契约、适配层与发布纪律（2026-09-17 至 09-20）

这一阶段集中修复 Crosed 授权/重放一致性、Idris 签名格式、秘密文件检查、
跨平台审计和打包排除规则，并记录十二 Core 的协议全景。9 月 20 日加入
安全的 Network Adapter（S6NA）：它是可选的规范化层，不是任何 Core 原生
部署的前置依赖。Android 状态、统一基准输出、发布归档和组件 doctor 也在
此阶段形成较稳定的验证入口。

### 5. 虚拟访问与性能工程（2026-09-21 至 09-25）

后续提交加入可配置 S6NA/Virtual Broker、受限虚拟 Broker 数据报和 Public6
邀请/虚拟对等端流程；CI 扩展到 Hare、QEMU 组件、BSD/Windows/OmniOS 等
平台边界。最后一组提交聚焦原生 iperf3 证据、Gate UDP 并发上限、C11Relay
批量发送、Ada/Go/Rust 缓冲区复用、高延迟窗口和 Idris broker admission
测试。当前顶端提交还补充了 Android VPN 控制、QEMU 组件脚本、Hare 编译
入口和虚拟接口“计划后显式应用”工具。

## 2026-10-02：应用边界、跨平台回归与文档基线

10 月 1 日至 2 日的工作把“Core 能否被外围组件安全调用”从约定推进为机器可读合同。
每个 Core 的 feature report 现在包含 `application_boundaries`：TCP 代理 Core
声明有界的 JSONL stream 入口，Hare、Carp、Idris、Pony 声明带顺序号和窗口背压的
`seqpacket-fd` message 入口，Network Adapter 单独声明 credited companion 边界。
这些入口描述调用语义，不改变各 Core 的原生线缆协议，也不把 Network Adapter 变成部署前置。

Node-IPC 在此阶段完成 FastRPC、RawIPC、C11Relay 和 Control Center 的只读边界，
并增加候选组件观测、批量请求、每 peer 队列/速率/burst 限制和 Windows 运行时适配。
Control Center 的变更入口仍需显式授权；未知字段、递归 IPC 调用和超出帧/响应预算的请求
继续失败关闭。Windows 不执行依赖 POSIX Control Center 运行时的跨进程测试，避免把平台
限制误报为协议回归。

同一时间，Go/Rust/Hare/Pony 的本地应用 ingress 增加有界背压或 Micro-Mux credit，
保留每次 poll 的 drain 上限和总工作预算。Hare 的两个 `match` 语句补齐严格语法后，
Linux、Linux ARM64 和 FreeBSD 的 Hare 构建路径重新共享同一源码状态。CI 仍会分别验证
FreeBSD、NetBSD、OpenBSD、Windows、macOS、QEMU 和 Android；失败日志只代表对应平台
或工具链，不应推导出所有 Core 的互操作性。

10 月 2 日的文档基线因此明确三件事：Core 独立部署仍是默认模型，应用边界是调用合同而
不是新 wire protocol，发布 ZIP 是纯文本交换包而 tar 才是包含已构建产物的发行包。性能
报告继续区分 loopback 上限、原生三角色链路和应用入口吞吐，历史数字不自动代表当前提交。

## Core 首次出现顺序

| 顺序 | Core | 首次出现提交 | 日期 | 首次出现时的定位 |
| ---: | --- | --- | --- | --- |
| 1 | Go | `deb56a8a` | 2026-09-06 | 初始完整 broker/agent/client 基础实现 |
| 2 | Rust | `deb56a8a` | 2026-09-06 | 初始完整实现，独立控制与 QUIC 数据路径 |
| 3 | Zig | `c99c56b4` | 2026-09-06 | ENet 栈及 Go/Rust 控制面兼容入口 |
| 4 | D | `cf4c6e9b` | 2026-09-06 | BetterC、rle-udp 与认证流传输 |
| 5 | Ada | `1602b45e` | 2026-09-06 | SPARK 取向的认证 cell relay |
| 6 | C++ | `170e3ebd` | 2026-09-07 | C++20、TLS 1.3 WebSocket、SCTP |
| 7 | Nim | `2a7aad91` | 2026-09-07 | libdatachannel 支持的认证 UDP |
| 8 | Hare | `a54628d8` | 2026-09-08 | L0 固定路由 IPv6 UDP 端点 |
| 9 | Gleam | `c7be81a1` | 2026-09-08 | BEAM/Gleam 原生栈与加密 TCP 流 |
| 10 | Carp | `fb568c47` | 2026-09-11 | 受限 C 编译、分层 AEAD 编解码 |
| 11 | Idris | `aa3e7893` | 2026-09-12 | 依赖类型安全检查与固定对等端 UDP |
| 12 | Pony | `7c81f2e6` | 2026-09-13 | OCap、认证 UDP 与可靠会话 |

提交标题有时重复（例如同日的 C++ 提交）或描述的是后续修复，因此上表以
Git 路径首次出现为准，而不是以标题推断。完整的当前能力和限制见
[`core-matrix.md`](core-matrix.md) 及各 `Core-*/README.md`。

## 架构演进要点

1. **从单一实现到独立家族。** Go/Rust 奠定基础后，每个新 Core 都保留独立
   的控制协议、原生数据面、构建入口和测试；不能把角色名称误解为协议兼容。
2. **从“能连接”到有边界的会话。** 重放窗口、序列空间、重传次数、并发数、
   帧大小、密钥生命周期和超时逐步成为显式契约；legacy 端点继续保留其
   单会话或固定对等端限制。
3. **从可选功能到显式变体。** 默认二进制维持 L0；Crosed L5、应用传输、
   Qubes-inspired 域策略和 Public6 通过明确的构建/变体流程启用，并在授权
   时取构建能力、签名请求、Mod 等级、能力清单和域策略的交集。
4. **从伴随脚本到可验证交付。** 统一 feature-report、组件 doctor、真实原生
   基准、跨平台 CI、离线审计和原子打包逐步加入；Network Adapter、插件和
   Slots 保持进程外、签名、资源受限的边界。
5. **从功能扩展到部署纪律。** 控制中心 API 保持 loopback、bearer 认证、
   有界且只读；接口创建先生成计划再由操作员显式应用；工具链和网络监听
   不因构建或安装步骤被静默启用。

### 6. 统一接入、Detector 与 CI 收敛（2026-09-26 至 09-30）

这一阶段加入统一长邀请码、平台无关协议封装、Android Keystore AES 生成修复，
以及适用于公开 PCAP 的 Detector 离线提取和按流分组验证。Detector 使用 CTU-42
公开 botnet-only PCAP 与真实 Shadow6 本机链路训练 RF/LSTM，模型和评估结果作为
本机 Artifact 保存，源码包排除数据集与权重。9 月 30 日修正 Linux iperf chain
TCP fixture 的 FIN 排空顺序，避免把正常半关闭显示为 RST/EPIPE；最新 CI 实测
结果已合并进 README。当时最新提交为 `b479ae2`；后续的 10 月 1 日提交继续扩展了组件接口与本地流控。

这一时间段的性能变化也有独立记录：9 月 26 日 TCP 原生吞吐以 Rust 约
3.63/3.83 Gbit/s、C++ 约 2.72/2.75 Gbit/s、Gleam 约 1.57/1.47 Gbit/s
领先；9 月 27 日 D 提升到约 3.13/3.20 Gbit/s，Rust 为 2.62/2.59，Go
出现 14.7/24.5 Mbit/s 的低点；9 月 28 日 Go 回升到约 487.6/489.9 Mbit/s，
D、Rust、C++ 仍保持约 1.5–3.2 Gbit/s，Nim 约 341/383 Mbit/s。UDP 核心在
1.1 Gbit/s offered load 下仍普遍丢包约 74–97%，不能据此宣称可靠容量。不同
日期使用共享 runner 的短时回环测试，必须同时比较基线，不能直接当作跨日排名。

## 2026-10-01：S6P1 通用凭据与社区协议接口

`9c8f650` 将 S6P1 从预留字段封装提升为各组件可直接消费的通用凭据：
identity、routes、components、credentials 四个 section 统一参与校验和传递，
pack/unpack 对浮点值采用一致的拒绝规则，单 envelope 上限提高到 256 KiB。
Public6 提供社区协议兼容入口，并以 Passport/Visa admission metadata 支持社区
自定义协议；Visa-free 必须由接收策略显式开启。Control Center 的
`orchestrator.client.knock` engine enum 扩展到十二个 Core；C11Relay 文档更新
为当前按 peer、队列、速率和 burst 的实际边界。上述改动均在 Python/CLI/Public6
层完成，不要求原生 Core 重新编译。

## 2026-10-01：Passport/Visa 全组件凭据化

`e4b28d5` 在 S6P1 之上推广通用 Passport/Visa：Passport 绑定 subject、组件、
角色和有效期，Visa 再绑定 audience、组件和更短有效期；两类凭据均可直接放入
S6P1 的 credentials section，由 CLI、Public6、Gate、Detector、Control Center
和其它无须重新编译的组件验证。Visa-free 仍由接收策略显式允许，过期和格式错误
凭据默认拒绝。新增回归测试覆盖签发、验证、过期和组件范围。

## 2026-10-01：可配置打包与 S6AR1

`6e20c7a` 让发布脚本支持 `--tar`、`--zip`、`--both`、`--root` 和
`--output-dir`，不再依赖硬编码工程路径或必须同时生成两种归档。Control Center
新增统一 API Receiver/Router 元协议 S6AR1，以严格的 receiver、router、payload
section 承载请求、响应和事件；该接口属于无须重新编译原生 Core 的统一组件层。

## 2026-10-01：S6P1/S6AR1 生产级边界收紧

`b29e3f2` 完善两项统一协议：S6P1 Passport 支持 Ed25519 issuer 签名验证，
Visa 生命周期不再超过父 Passport；S6AR1 要求 receiver.component、router.route
和 request/response correlation_id，新增统一 request 构造器，并保持严格大小与
portable JSON 边界。两者继续位于组件层，不要求十二个原生 Core 重新编译。

## 历史快照（`b29e3f2`，2026-10-01）

- 十二个 Core 均有独立目录和 README；能力、协议和平台边界见能力矩阵。
- 默认 `shadow6-*` 构建保持 `CROSED_LEVEL=0`、`APP_TRANSPORT=0`、
  `QUBES_ISOLATION=0`，显式变体另行生成并恢复默认二进制。
- Go、Rust 是基础默认路径；其余 Core 是否能在某主机编译取决于对应的
  可选工具链，不能从目录存在推断为已启用。
- 近期提交重点是跨平台构建证据、原生性能测量和有界并发；这些证据描述
  测试环境下的结果，不代表所有部署平台的性能或安全保证。
- README 已记录 2026-09-30 Linux 4CPU iperf chain CI 实测；性能数据保留基线、
  方向、吞吐、丢包/重传、CPU 和内存字段，不将预期的 FIN 清理噪声列为错误。

## 2026-10-01：S6P1 全入口接入与 Android 安全检查

`fcc0afe` 将完整 S6P1 从“可编码格式”推进为所有无须重新编译组件都能直接消费
的统一入口。Public6 新增统一 envelope/Passport/Visa scope resolver；CLI Connect
支持直接传入完整 `S6P1.` 或受保护文件，并继续兼容 Join Code、`S6INV1.` 和旧的
profile/pin 参数；Virtual Broker、Virtual Peer、Detector 都支持同一 S6P1 输入并在
启动边界校验 component、role、audience、社区 admission 和凭据有效期。Control Center
新增 `protocol.envelope.validate`，旧 JSON-RPC 方法仍可用，S6AR1 同时拒绝重复字段、
浮点数和非有限值。Android Public6 导入也支持完整 S6P1，保留旧长邀请码流程。

本次验证通过：Public6、CLI、Control Center S6AR1/旧 RPC、Detector 共 57 个 Python
测试，以及 Android 项目/原生资源静态测试 10 个。Android 源码复核确认 SecretStore
使用 `KeyGenParameterSpec` 正确初始化 Android Keystore，Manifest 保持禁用明文流量、
非导出服务和应用私有存储；本次没有在本机重新编译 APK，构建仍交由 CI。

同时修正发布预检器在 `--root` 或非默认目录名下仍硬编码 `Shadow6/` 的问题；tar.gz
和 zip 的预检现在使用实际项目目录名，打包脚本继续支持分别选择归档格式。

随后提交 `dd55444` 收紧 Visa 的 component scope：带有组件字段的 Visa 必须与
实际消费组件完全一致，防止仅凭通用 Passport 格式跨组件重用。

## 2026-10-01：S6P1/S6AR1 完整组件协议契约

`2633b38` 完成了协议骨架到生产级组件契约的收紧。S6PASS1 现在可以由 Ed25519
issuer 签名，验证默认拒绝未签名凭据；S6VISA1 必须由同一 issuer 签发，并携带父
Passport 的 canonical digest、subject、component 和 audience 绑定，生命周期不能超过
父 Passport。签发 Visa 前也会检查 Passport 的 component scope；接收端会再次验证
父链、签名、过期时间和 scope。

S6AR1 的 receiver 现在只接受 `component`/可选 `instance`，router 只接受 route、
有界 hops 和 timeout；request 必须有 action、correlation_id，response 必须严格二选一
携带 result 或结构化 error，event 也有固定 event/data 形状。payload 可携带完整 S6P1
context，Control Center 在旧 RPC 桥接前按 receiver component 和 router audience 验证
该 context，并把成功和失败都包装为 S6AR1 response；原 JSON-RPC/HTTP/JSONL 入口继续
兼容。

Android Public6 对完整 S6P1 同步校验九个顶层字段、十二 Core/角色、Passport/Visa
Ed25519 签名、父 Passport digest、issuer、scope 和有效期，避免移动端成为较弱验证端。
本次仍不在本机编译 APK，交给 CI 生成最终构件。

### 2026-10-01 当前提交

代码提交：`fcc0afe`；历史文档提交：本节对应的后续提交。当前统一协议仍位于组件层，
十二个原生 Core 不需要重新编译。

## 2026-10-01：Node FastRPC/RawIPC 与 C11Relay 组件层收尾

同日 action 日志复核修复了跨平台 IPC 回归：Windows 使用系统 `python` 解释器而不是
POSIX 专用的 `python3`，Unix socket 专属候选组件测试在 Windows 明确跳过，Windows
仍覆盖 TCP、认证、RawIPC 加密和协议互操作性。旧的仍在运行 action 已取消，避免过期
提交继续消耗资源或覆盖修复结果。

本次在不改动、也不重新编译十二个 Native Core 或 Android APK 的前提下，完成了
Node 组件层的生产化收尾。`Node-IPC/` 只使用 Node 内置模块，不依赖 npm：FastRPC
采用 canonical safe-integer JSON、方向分离 HMAC-SHA256、时间窗、nonce、有限重放缓存、
有界帧和通用错误；RawIPC 采用方向分离 AES-256-GCM、认证头、时间窗、重放保护、响应
绑定和 1 MiB 帧上限。Unix socket 强制私有目录与 `0600`，TCP 只允许数字回环地址；密钥
加载拒绝符号链接、硬链接、错误所有者/权限及读取期间替换。

`Node-IPC/c11relay.mjs` 为 C11Relay 提供固定目标、按 peer 隔离的 UDP companion，
支持 FastRPC 的 capabilities/status/exchange/batch 和 RawIPC 的 datagram/metrics/batch
类型。批处理上限 256，peer、队列、速率、burst、超时和空闲回收均在发包前检查，重复
peer 保持 FIFO；不暴露任意 Relay 控制、路由或防火墙操作。既有 C11Relay 原生协议与
高性能批处理实现保持不变。

统一 CLI 新增 `shadow6 ipc`，Control Center 新增 `ipc.catalog`、`ipc.call`、`ipc.raw`、
`c11relay.ipc.status` 和 `c11relay.ipc.schema`。这些方法由共享 schema 自动进入 JSONL、
HTTP、MCP、LSP 与 OpenAI function tools；旧 API 继续可用，AI 调用不能提供密钥、配置
路径、主机、命令或 Relay 目标，变更操作仍受显式 mutation gate 保护。安装布局同步
包含 `s6ar.py` 和 IPC bridge，保证源代码与安装树一致。

本次进一步把候选组件接入同一安全合同：Virtual Broker、Detector、S6NA 现在可通过
独立 owner-only key 提供只读 `*.capabilities` 与 `*.status` FastRPC/RawIPC 调用。
它们不开放配置变更、原始包注入或凭据绕过，仍分别遵守 Virtual Broker admission、
Detector 数据边界和 S6NA 原生传输认证；不支持的组件名在配置加载时 fail closed。
这样 Control Center、C11Relay、Virtual Broker、Detector 与 S6NA 共同覆盖控制面、
数据面、运行时、检测面和适配器面，而不会把 IPC 变成万能后门。

CI 的 Node 适配矩阵覆盖 Node 22/24、Linux/macOS/Windows；Linux runner 额外运行真实
C11Relay normal/high-speed 回环链路。当前本地通过 Node IPC 18 项（含 Control Center
实桥）测试、Control Center 35 项、CLI 7 项和 C11Relay 原生 sanitizer/回环测试。全仓
清查未发现生产代码中的 TODO、未实现异常、空壳 stub 或 Mock；测试中的替身仅用于权限
竞态、故障注入和跨协议边界，生产路径不依赖它们；Detector 的 synthetic/dummy 数据命令
仅用于回归测试，真实训练仍使用 PCAP/实测提取器流程。

C11Relay 的 `compile.sh` 同时完成跨平台 hardening 收尾：保留可移植 C11 警告基线，
对 Fortify、栈保护、格式检查、LTO、PIE、控制流/栈冲突保护、自动变量初始化以及
RELRO/NOW/no-exec-stack/undefined-symbol 链接检查逐项探测，当前工具链不支持的选项
只跳过该项。Linux high-speed API 仍由 C 源码自身的条件编译决定，脚本不会把 Relay
扩展到源码未支持的协议或平台。

## 如何继续维护

新增 Core 时，同时记录首次加入提交、原生控制/数据协议、角色和平台限制，
并更新 `docs/core-matrix.md`。协议或安全契约发生变化时，在本文件的阶段
时间线补充提交号和原因；不要用“兼容所有 Core”之类的概括替代具体边界。
## 2026-10-01：原生 Core 本地入口背压与 Gleam Micro-Mux credit

在不改变 Hare、Carp、Idris、Pony 远端 wire protocol 的前提下，补齐本地应用入口的
流控合同：UDP 继续兼容并允许 best-effort admission；支持的本地 flow ingress 使用
有界 message-preserving 入口，窗口耗尽时向 producer 返回 backpressure。Carp 已接入
继承的 `SOCK_SEQPACKET` FD（`SHADOW6_APP_FLOW_FD`），其余 Core 保留原生 runtime
抽象并在 feature report 声明 `udp`/`seqpacket-fd` 能力，逐步接入不会旁路认证或 S6NA。

Gleam Micro-Mux 同步增加本地 `application_credit()` / `applicationCredit()` 和
flow-controlled send helper。credit 由现有 ACK/window 状态恢复，不新增 S6NA frame、
不改变 1100-byte MTU、64-frame window、AEAD 或重传语义；持续 producer 超过 consumer
时仍会明确阻塞/返回 backpressure，而不是无限缓存。
## 2026-10-01：Node IPC 候选组件只读观测扩展

Virtual Broker、Detector 与 S6NA 的 Node IPC 合同扩展为窄只读观测面：除
`capabilities/status` 外，提供有界 `metrics` 以及 routes/sessions/alerts 的空摘要或
快照结构。它们仍是组件合同层观察，不模拟运行时、不替代 admission、policy、Core
credential 或 transport authentication；mutation、packet injection、reload 与任意
目标路由继续 fail closed。这样统一了发现和监控命名空间，同时保留各组件原有权力边界。

## 2026-10-01：跨平台 IPC 修正与运行时候选扩展

`5776acd0` 将 Node IPC 的候选组件适配扩展为运行时注册合同，并补充相应 CLI
参数校验和测试；候选仍需遵循固定组件名与只读边界。`a64efca7` 修正 Network
Adapter 与 IPC 动作在跨平台环境下的处理，并调整对应测试，保持本地 IPC 的固定
动作集合。

## 2026-10-01：本地入口背压与组件观测边界

`f16f7758` 为 Carp 增加可选继承 `SOCK_SEQPACKET` 应用入口，并让 Hare、Idris、Pony
在 feature report 中声明 UDP 与 `seqpacket-fd` 模式；UDP 仍是默认入口。Network
Adapter 的 Micro-Mux 增加由现有 ACK/window 状态驱动的本地产生端 credit，不改变
wire frame、MTU 或重传语义。该变化可能改善后续 UDP Loss 表现，但 9 月 30 日性能
表尚未复测，不能作为已验证的改善结果。

`99dfb172` 为 Virtual Broker、Detector 和 S6NA 的 Node IPC 增加有界 metrics、摘要
和快照查询。返回值明确标为本地只读合同观察，不冒充运行中组件的状态，也不替代
其 admission、policy、credential 或 transport authentication。

## 当时快照（`99dfb172`，2026-10-01）

- 仓库包含十二个独立 Core；具体传输、Crosed 能力和工具链要求按 Core 分别说明，不能从 Go/Rust 旧路径推断所有 Core 等价。
- 默认 `shadow6-*` 构建仍保持 `CROSED_LEVEL=0`、`APP_TRANSPORT=0`、`QUBES_ISOLATION=0`；显式变体构建后恢复默认二进制。
- 当前提交扩展 Node IPC 只读观测合同，并补充 Network Adapter credit 与部分 Core 的本地 flow ingress 能力声明；不表示各 Core 的远端协议或可靠性相同。
- README 中的 Linux iperf chain 数据截至 2026-09-30；UDP Loss 在 10 月 1 日入口流控相关改动后可能改善，但尚无更新测量证实。

## 2026-10-01：Windows Node IPC CI 回归修复

`99dfb172` 的 Windows Node 22 与 Node 24 IPC job 都在 Control Center RPC 边界测试失败：
测试将 Python 子进程命令固定为 `python3`，Windows 上未能得到有效的 `system.schema`
结果。提交 `6e411efd` 让该测试按平台选择解释器（Windows 使用 `python`，其他平台使用
`python3`），与生产入口已有的平台选择一致。

本机 Node 22 验证通过：Network Adapter 10 项通过；Node IPC 19 项通过、1 项因未提供
预编译 C11Relay 而跳过。本次没有编译组件。

## 2026-10-01：本地入口运行时接入与双向 Core-blind 边界

`f16f7758` 先给 Carp 接通继承的 `SOCK_SEQPACKET` 本地应用入口，并给
Pony、Hare、Idris 建立 `udp`/`seqpacket-fd` 能力词汇；Gleam Micro-Mux 的
应用 credit 位于 S6NA companion，并未给 Gleam 原生 wire 增加 ACK。
随后 `deb6b12c` 将 Pony、Hare、Idris 的 **client runtime** 真正接到
`SHADOW6_APP_FLOW_FD`，并收齐 Carp 路径的有界读取、窗口背压、EOF 和硬错误处理。
这补上了能力声明与运行时行为之间的缺口，但不能据此推断 broker/agent 也支持该
FD、各 Core 的原生可靠性相同，或默认 UDP 入口已经具备产生端背压。

这一边界具有双向含义：外围只需依据 Core 合同选择和驱动原生数据面，不必读取
各语言的调度器和 wire 内部；Core 也不必知道输入由 S6P1、Public6、Control
Center 还是第三方控制面准备。理论上可以保留某个 Shadow6 Core 而替换身份、
授权、编排和可靠层；也可以让未来的新 Core 实现相应合同，接入 Shadow6 外围。
这不产生跨 Core 家族的原生 wire 互通。新增英文文档 [`Core-Blind.md`](../Core-Blind.md)
（`c228e8f5`）明确区分 Core、外围及整套部署的兼容性，并把能力发现、启动配置、
消息入口、压力反馈和生命周期列为独立演化的边界。

目前 `seqpacket-fd` 仍是可选的客户端入口原语，而非冻结的完整 Core ABI：各 Core
的记录上限不同，反向应用出口仍沿用各自机制，feature report 尚未表达模式的
角色范围。一次本地 `send` 成功仅代表内核队列接受记录，不代表 Core 已读取或
远端已交付；要获得更强的所有权承诺，仍需明确的 admission ACK 和恢复规则。
S6NA 的 `application_credit()`/`applicationCredit()` 则提供组件层的另一种
背压路径；其 `S6NA_BACKPRESSURE`、`S6NA_CLOSED`、`S6NA_RETRY_EXHAUSTED`
是 S6NA 语义，不能当成 Gleam 原生 ACK。README 已将旧 UDP 性能注释改为英文：
9 月 30 日数据早于 `f16f7758` 及后续运行时接入，尚未按新入口复测；任何 Loss
或 goodput 改善幅度都不能从旧表推定。

## 2026-10-01：应用边界机器合同与结构化发现

实现提交 `c1b5b29d` 修复共享 feature-report validator 对 UDP 四核
`app_transport_modes` 的拒绝，并将四核的 `seqpacket-fd` ingress 规范为严格
`message` boundary：报告 client role、各自的最大 record、message-preserving、
native-window admission、成功 `send()` 仅表示内核队列接收，以及 oversized record、
`EAGAIN`/`EINTR`、硬错误、EOF 和 drain 行为。Pony、Hare、Carp、Idris 对应 runtime
继续在 native window 满时停止读取；超长记录丢弃并继续，硬读错误 fail closed。

Go、Rust、Gleam、Zig、Ada、D、Nim、C++ 八个 TCP proxy Core 的 feature report 现在
使用统一 `stream` 描述，包含双向、有序、可靠字节流、TCP flow control、half-close、
listener owner、连接上限、shutdown/EOF 及 local/native flow 映射。各客户端在
loopback listener bind/listen 后写出 `shadow6.ready` JSONL endpoint；测试读取结构化
事件，Gleam Micro-Mux 的独立 UDP proxy 也已加入对应 ready event。S6NA Python/Node
credit 边界统一报告 `S6NA_BACKPRESSURE`、`S6NA_CLOSED` 与
`S6NA_RETRY_EXHAUSTED`；Node 原有 credit 错误测试也改为检查稳定错误码。

共享 validator 被 VCore inventory/discovery、`shadow6 --version`、audit、Security
Assistants 和 `crosedctl` 共用。实现还加入 UDP source-contract 与本地
`SOCK_SEQPACKET` 记录边界/队列饱和测试，并更新 `Core-Blind.md`、README 和能力矩阵，
说明双向 Core-blind 的机器边界及尚未提供 admission ACK、统一 egress 和统一 bootstrap
的限制。文档提交 `86754ae7` 详述当前合同；本历史更新单独提交并跳过 CI。

本机运行 `Crosed/test_feature_contract.py`（12 项）、Network Adapter Python
测试（11 项）和 Node 测试（10 项），均通过；`git diff --check` 通过。按要求没有
本地编译任何 Core，也没有执行依赖已编译 Core 的端到端 runtime 测试；这些行为回归
由共享 source-contract 测试覆盖，真实二进制接入仍需正常 CI 验证。README 中已有
UDP 性能数据仍未使用本次新入口重测，不能据旧数据推定 Loss 改善幅度。

## 2026-10-02：无感应用入口 shim 与 client-only 边界

新增 `Tools/app_flow_proxy.py`，把无需修改的本机 TCP/UDP 应用接到
`SHADOW6_APP_FLOW_FD`。代理只绑定 loopback，以 64 条记录为上限；Core 窗口
耗尽时暂停 listener 读取，避免 producer 侧无限缓存。它改善的是本地 admission
和排队行为，不会把 UDP 应用（包括 iperf3）变成具备端到端确认的 TCP，也不宣称
能够单独消除远端丢包。

client-only ingress 是正式架构边界：本地应用是 producer，client 负责把记录
纳入认证 native path，broker/agent 不消费继承 FD。shim 保持这一边界，采用显式
FD 传递和 opt-in 启动，不通过全局环境变量制造不存在的 egress 或 admission ACK。

同日推出 `libshadow6` 薄壳。它依赖本机已安装的 `shadow6` CLI，只提供命令转发和
JSON 结果读取，不内置 Core 名称、默认核心、协议栈或第二套策略。调用方通过安装
环境决定可用功能；`SHADOW6_CLI` 仅用于指定已安装命令的位置。

### 10 月 2 日后续：Facade、胶囊生命周期与 Node IPC 收口

CLI 的 `shadow6 features` 现在输出单个 `shadow6.features.v1` 聚合 JSON 文档，
`--component` 用于筛选单一 Core；`libshadow6.features()` 直接消费该合同。Facade
安装到所选 Python 解释器的标准 `site-packages`，实例调用不再临时修改进程级环境变量。

`app_flow_proxy` 将 TCP peer 数限制为 64。待发记录达到 64 条时，它暂停 listener 和
所有已接入 peer 的读事件；队列降到 32 条后恢复，并监听 seqpacket FD 的可写事件，
让背压解除及时唤醒发送。UDP 超长报文也会在截断后被拒绝。

Control Center capability capsule 从注册 Core 的 feature report 选择 client boundary：
`seqpacket-fd` 使用 socketpair、proxy 与启动就绪握手；`localhost-tcp-proxy` 则等待
Core 自己发出的 `shadow6.ready` 事件并使用 Core listener。相关 executable、配置、
proxy 和上限在启动常驻进程前完成校验。后台 reaper 到期即关闭进程组；受授权的
`capsule.pause/resume` 会实际暂停或恢复 Core 与 proxy。只有具备 client boundary 的
注册 Core 可启动，这不会声明不同 Core 的原生 wire 互通。

Node IPC 的八个通用 adapter identity 现为
`virtual-broker`、`detector`、`s6na`、`app-flow`、`capsule-observer`、`plugins`、
`slots`、`gate`。`capsule-observer` 读取 Control Center 的真实胶囊目录且不暴露 token；
通用只读 adapter 不再伪造本地 `paused` 状态。app-flow 的通用 IPC 也不再宣传 pause/resume；
进程生命周期操作集中在 Control Center 的受限 capsule API。

### 10 月 2 日后续：Python 应用会话入口

`libshadow6.open(require, config=...)` 从 Control Center 的只读
`capsule.candidates` 清单选择注册 Core，并逐项匹配 client application boundary，随后
启动 capsule、返回 loopback endpoint，并通过 `Session` / `Shadow6` context 管理停止。
seqpacket message boundary 要求显式 listener port；stream boundary 使用 Core readiness
事件提供的 endpoint。它把发现和 capsule 生命周期收进 Python 入口，但仍不抽象 Core wire
protocol，也不代表外围边界相同的 Core 可以互换通信。

### 10 月 2 日后续：Gleam Micro-Mux boundary 纳入统一合同

Gleam feature report 现在同时声明 `localhost-tcp-proxy` stream 与
`localhost-udp-datagram-proxy` message boundary。后者明确标记 best-effort、无顺序和
可靠性保证。共享 feature validator 对两种合同分别严格校验；Control Center 候选目录
逐项列出它们，capsule 按请求的 boundary mode 等待对应 readiness event，
`libshadow6` 可选择 UDP 并通过 `Session.protocol` 和 endpoint 暴露其本地入口。

### 10 月 2 日后续：近期实现与打包修正

近期提交按时间顺序收口了以下工作：

- `636b17e9`：修复 Hare 0.24.2 运行时兼容问题，并保留 FreeBSD 可用的动态 PIE hardening。
- `f1b53040`：修复 libshadow6 聚合 JSON、Python 安装与并发调用；修正 app-flow 背压；
  让 capability capsule 按 boundary 选择 Core、主动执行 TTL 并提供真实 pause/resume；
  收敛 Node IPC capsule observer，并补充独立测试与 CI。
- `17564da7`：加入 Python 应用 session facade，负责从注册 boundary 选择 Core、启动
  capsule、返回 endpoint 并管理 session 生命周期。
- `b3582098`：将 Gleam Micro-Mux UDP datagram boundary 加入 feature contract、capsule
  候选发现与 libshadow6，且明确声明 best-effort、不保证顺序或可靠交付。
- `8cb6439e`：修复 Hare 接收分支的语法与类型错误，及 Windows iperf3 TCP/UDP 联合端口
  探测失败。
- `c5bfe01d`：取消 tar 预检对 Go/Rust 默认与 Crosed 二进制必须存在的要求。发布目录有
  编译产物时仍会随 tar 收入；没有这些产物时，源码包也可通过预检并完成打包。

对应修复均有针对性本地测试；Gleam 和 Hare 还运行了各自的 Core 测试目标。跨平台
Actions 在 `8cb6439e` 后重新触发，最终平台结果应以该次 workflow run 为准。
## 2026-10-02：Deployment v1、S6ABI/1 与 Core-Blind 验收入口

本轮新增严格 `shadow6.deployment.v1` 清单、逻辑 Broker 身份的 replica/standby
多入口语义、`shadow6 deployment validate/lock/plan` 与统一
`shadow6 acceptance`。应用侧新增有界 `S6ABI/1` control/data framing 和
stream/message/credited 边界，继续复用 S6P1 admission 与 S6AR1 signed request，
不修改 native Core wire protocol。

VCore、driver 与 `libshadow6` 按 feature-report/application boundary 发现外部 Core，
不再把十二个内置名称当成 ABI 前提；Node IPC 增加只读 `abi` contract adapter，接入
最新 Node IPC、Control Center 与 strict schema。OCaml 控制面模块提供无外部依赖的有界
类型检查器，Python strict parser 仍是权威解析器。native 矩阵和跨架构构建交给 CI，
本机 acceptance 明确区分 source-only 与 native runtime 验证。

## 2026-10-03：Privacy Envelope 与命名服务生命周期

新增可选 OCaml External Privacy Envelope（S6EPE），支持 authenticated-envelope 的
stream 与 datagram-preserving 模式。它位于公网入口和本地 Core endpoint 之间，只做认证、
授权、资源限制和不透明字节转发；十二个 Core 的 native wire protocol、magic、frame layout、
crypto、ACK、重传和 peer compatibility 均未改变。CLI 与 Control Center 提供
`privacy-envelope status/feature-report/compatibility` 及只读聚合状态，服务可通过
`privacy = "native"` 或显式 `privacy = "envelope"` 选择外层。

命名服务现在贯通 install、init、setup、create/configure、lock、apply、run、ready、connect、
status、restart、stop、remove 生命周期。状态持久化 ServiceSpec、CoreBinding、DeploymentLock、
实际 Core、endpoint、ready 时间和 drift；重复 setup 会复用健康 runtime，Core 变化必须显式
重新配置。此前仅有骨架的 envelope 运行时已补齐：stream 使用 nonce/HMAC challenge，
datagram 使用 HMAC 前缀并保留 datagram 边界；未认证连接不会建立上游 Core 连接。
OCaml/Dune 构建和 datagram 边界测试已纳入 CI。


### 2026-10-03 后续落实与验证边界

上述生命周期与隐私目标保留。本轮把注册表状态模拟替换为 Linux 实际进程监管，
增加绑定内容漂移检查、pidfd 停止、TTL、私有原子状态文件，并恢复 Public6 connect
路由。重复同配置 setup/run 复用进程；配置变更要求显式停止和重新配置。
`ready` 目前准确报告为 `process-alive`，跨 Core 原生握手就绪和动态 endpoint 发现
仍是后续需要完成的部分，不把进程存在等同于 E2E 成功。

EPE 的新双端协议为 version 2：密码学随机 nonce、相互 HMAC 握手、双向流和 UDP、
方向绑定、防重放、会话资源限制、真实私有计数与本地 E2E。加密外层传输、IPv6/Unix
端点和 WebRTC/SCTP 专用适配仍保留为待落实目标；当前外层本身不声称提供加密。
详细完成项、测试数与既有二进制审计限制见[本轮记录](review-2026-10-03.md)。

### 2026-10-03 后续：原生拓扑合同与运行时审计收口

提交 `12479b84` 将 native topology 选择与节点配置实现收敛到共享合同：一次部署的
broker、agent、client 必须使用同一 Core wire family，不隐式翻译 native 协议；保留
受限的 Zig broker 控制面声明例外。Auto-Orchestrator 与 Deployment 使用同一节点配置
实现，避免调度入口和部署入口产生不同的 native realization。

命名服务增加 supervisor contract、实际进程运行器及启动材料漂移检查；Detector 增加
对已部署服务的合规核验。Service-Init 补充受限 service runner 和 supervisor 能力报告。
Privacy Envelope 更新了配置、会话、防重放存储、Sodium FFI 与相关测试，并同步更新
部署、服务连接和 envelope 文档；跨平台 CI 增加对应 topology 测试，并调整 Idris 运行时
产物叠加方式以保留仓库中的源文件。

本轮部署、拓扑、服务上下文与生命周期、初始化、Detector 合规和 CI 工作流 Python 测试
通过；有一项 envelope runtime 测试因本地二进制不可用而跳过。OCaml/Dune 测试因环境中
没有 `dune` 或 `opam` 未运行，因此 OCaml 变更仍需由具备工具链的 CI 验证。详细实现见
提交 `12479b84`；本中文历史更新单独提交并跳过 CI。
