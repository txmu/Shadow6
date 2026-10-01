# Shadow6 项目历史与 Core 演进

## 说明与范围

本文根据当前 Git 仓库中可见的提交历史整理，覆盖从最早可见提交
`deb56a8a`（2026-09-06）到 `b479ae2`（2026-09-30）。Shadow6 的实际开发
早在 2026-05-31 已开始；此前阶段尚未提交到当前 Git 仓库，因此 Git 可见
历史不能代表项目的真实起点。

“Core 首次加入”按该 Core 目录第一次出现在 Git 树中的提交计算。首次出现
不等于功能已经完成：后续提交继续补齐控制面、原生数据面、测试、构建和
跨平台支持。十二个 Core 独立编译、各有协议和平台边界；共享 feature-report
和安全契约词汇，但不因此获得线缆级互操作性。

## 发展阶段

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
结果已合并进 README。当前最新提交为 `b479ae2`。

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

## 当前快照（`b29e3f2`，2026-10-01）

- 十二个 Core 均有独立目录和 README；能力、协议和平台边界见能力矩阵。
- 默认 `shadow6-*` 构建保持 `CROSED_LEVEL=0`、`APP_TRANSPORT=0`、
  `QUBES_ISOLATION=0`，显式变体另行生成并恢复默认二进制。
- Go、Rust 是基础默认路径；其余 Core 是否能在某主机编译取决于对应的
  可选工具链，不能从目录存在推断为已启用。
- 近期提交重点是跨平台构建证据、原生性能测量和有界并发；这些证据描述
  测试环境下的结果，不代表所有部署平台的性能或安全保证。
- README 已记录 2026-09-30 Linux 4CPU iperf chain CI 实测；性能数据保留基线、
  方向、吞吐、丢包/重传、CPU 和内存字段，不将预期的 FIN 清理噪声列为错误。

## 如何继续维护

新增 Core 时，同时记录首次加入提交、原生控制/数据协议、角色和平台限制，
并更新 `docs/core-matrix.md`。协议或安全契约发生变化时，在本文件的阶段
时间线补充提交号和原因；不要用“兼容所有 Core”之类的概括替代具体边界。
