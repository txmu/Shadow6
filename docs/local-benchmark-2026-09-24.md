# Shadow6 本机安装与性能记录（2026-09-24 UTC）

## 来源与机器

- GitHub Actions：[`multiplatform.yml` 成功运行 35930237152](https://github.com/txmu/Shadow6/actions/runs/35930237152)，提交 `f809eca0d964cf36be6e63edbe69d13bf7ac8b6d`；下载 `shadow6-linux-release`，使用其中的 Linux x86_64 tar 安装到 `/usr/local`。CI 下载包约 111 MB，内含 tar 约 53 MB、文本 zip 约 1.1 MB。工作树基于同一提交，后续本机修复见下文。
- Linux 6.12.107 Debian 13，KVM 上 Intel Xeon Platinum 8259CL；**1 个物理核心、2 个逻辑 CPU**，内存 1.9 GiB、无 swap。测试时根分区约 1.8 GiB 可用，`/tmp` 是 969 MiB tmpfs。
- `iperf3` 3.18；Python 3.13.5 常规构建；Python 3.14.7 free-threading 构建用于同版本 GIL 开/关比较，`cryptography==50.0.1`。这些 Python 3.14t 环境位于本次测试临时目录，测试后清理。
- CI 产物包含全部 12 个 Core（Go、Rust、Gleam、C++、Zig、Ada、D、Nim、Pony、Hare、Carp、Idris）。本机具备 Go、Cargo、GCC/G++、Zig 0.16、GNAT、Nim、Hare、LDC 和 vendored Gleam/Pony/Carp；未发现本机 Idris 2 编译器，但 CI Idris 二进制可运行。

## 安装与验证

`make install` 使用 CI 编译产物跳过重编译，安装十二个 Core、适用的 Crosed/Public6 变体、Gate、Guard、Relay、CLI、插件、Slot、助手与共享树。默认 Go/Gleam Core 的特性报告为 L0、应用传输与 Qubes 标志关闭；相应 Crosed 变体为 L5，Gate 默认关闭。安装后的插件、安全、控制中心和 Slot 目录命令均可执行。安装后 `shadow6-security doctor` 为 **20/20 通过**。

发现并修复了三个源码/安装问题：

1. Idris 安装树的 `_app` 目录缺少随包提供的 `libsodium_ffi.so`。`Tools/install_tree.sh` 现将库复制到默认和 Crosed 运行目录；隔离的安装树验证中两个特性报告均可运行。
2. CI Zig 二进制在此 CPU 上触发 `Illegal instruction`。`Makefile` 现为 Linux x86_64 Zig 构建显式指定可移植目标；本机重编译、Zig 测试和 8 路链路复测通过。CI 原包二进制故障仍保留于原始结果。
3. Gleam Broker 原先在完成连接注册前回复认证；并发测试还用 `/proc/net` 快照判断 Agent 就绪，回声目标在工作负载屏障等待时可能提前超时。Broker 现先注册再回复；Agent 发出认证完成标记；测试等待此标记并为首个应用字节提供有界启动时间。Gleam Core 合约、双向认证、真实转发测试通过。2 路与 4 路复测通过；在本机 8 路曾失败，未继续高内存复测。

本机修复后的 Gleam 默认与 Crosed 二进制已分别重建，默认报告 L0，Crosed 报告 L5；两个变体与相关脚本已更新到本机安装。Zig 本机二进制也已更新。

## 性能结果

所有网络测试只使用 loopback。下表是单次运行，不是可重复的容量上限；不同 Core 的传输协议与处理路径不同，不能直接排序为产品优劣。

### TCP 基线与原生 Core

- `iperf3 -c 127.0.0.1 -P 12 -t 15 --json`：12 条 TCP 流，接收侧汇总 **26.914 Gbit/s**。这不是 12 核，也不经过 Shadow6。[原始 JSON](../Benchmark/results/local-2026-09-24/iperf3-p12.json)；[独立复现流程](iperf-local-benchmark.md)。
- 原生 Core：每个 Core 独立的 Broker/Agent/Client 三角色链，4 KiB × 每路 8 次请求；测试程序最大 8 路。速率为经过本机链路的应用有效负载，单位 Mbit/s。

| Core | 8 路状态 | 吞吐 Mbit/s | 说明 |
| --- | --- | ---: | --- |
| Ada | 通过 | 33.01 | 早先 64 KiB × 32 × 8 轮耗时过长，已中止 |
| Hare | 通过 | 31.72 | 有界数据报路径 |
| Idris | 修复后通过 | 28.76 | 首轮缺 FFI |
| Rust | 通过 | 27.11 | 原生链路 |
| Carp | 通过 | 23.96 | 有界数据报路径 |
| Zig | 本机重编译后通过 | 10.82 | CI 二进制触发非法指令 |
| Go | 通过 | 10.50 | 原生链路 |
| C++ | 通过 | 7.47 | 本机 SCTP 可用 |
| Nim | 通过 | 4.89 | 原生链路 |
| D | 通过 | 1.04 | 原生链路 |
| Pony | 通过 | 0.99 | 有界数据报路径 |
| Gleam | 8 路未通过 | — | 修复后 2 路 13.78、4 路 7.68 Mbit/s；未在 1.9 GiB 无 swap 机器上继续 8 路 |

[每个 Core 的原始 JSON](../Benchmark/results/local-2026-09-24/) 保留了首次失败、Zig/Idris 复测和 Gleam 2/4 路复测。8 路用 24 个 Gleam 角色进程，不能由这台机器的结果推断十二核性能。

### S6NA 与 Virtual Broker

- S6NA Python 与 Node 后端分别经过每个 Core 的真实三角色链，4 KiB × 8 请求 × 1 路：**24/24 通过**。[原始 JSON](../Benchmark/results/local-2026-09-24/s6na-network.json)。
- [组件矩阵](../Benchmark/results/local-2026-09-24/components.json)：**884/884 通过**，其中 864 项为 12 个 S6NA 配置的 Python/Node 编解码、AEAD 与恢复工作，20 项为 Virtual Broker/直接回声及签名准入。组件矩阵的 S6NA 并发是单 worker 的独立逻辑适配器，不能当作原生多核扩展性。
- [Virtual Broker 数据报矩阵](../Benchmark/results/local-2026-09-24/virtual-broker-datagram.json)：Gate/S6NA listener × 签名/匿名 × Hare/Carp/Pony/Idris，**16/16 通过**，每行 512 B × 64 请求。此测试只测本机回声代理，不包含 Core 原生传输。

### 同一 Python 3.14t 的 GIL 开/关

两轮均运行相同的 884 行，均为 **884/884 通过**；报告在导入依赖后实际记录 GIL 开启与关闭状态。下表是行级吞吐中位数，单位 Mbit/s；负载大小不同的行混在一起，仅用于本机回归观察，不应解释为通用加速比。

| 模式 | 实测 GIL | S6NA Python 432 行 | S6NA Node 432 行 | Virtual Broker 18 条数据行 |
| --- | --- | ---: | ---: | ---: |
| Python 3.14t `PYTHON_GIL=1` | 开 | 384.57 | 79.91 | 1471.21 |
| Python 3.14t `PYTHON_GIL=0` | 关 | 376.36 | 78.58 | 1776.18 |

原始报告：[GIL 开](../Benchmark/results/local-2026-09-24/components-py314t-gil1.json)、[GIL 关](../Benchmark/results/local-2026-09-24/components-py314t-gil0.json)。另有 Python 3.13.5 常规构建的 884/884 基线，不作为 GIL 开关的等版本对照。

## 检查与边界

- 已运行：本机 Zig 编译与 `test-zig`、Gleam 默认及 L5 变体编译并恢复 L0、`test-gleam`、Benchmark 18 个单元测试、组件与真实链路矩阵、`shellcheck Tools/install_tree.sh`、Python 编译检查、安装树 Idris 双变体验证、离线审计。审计 **110 通过、0 失败、18 跳过**；跳过项包含未在当前工作树构建的可选变体。
- `make check` 的 Go vet 阶段因临时编译空间不足而失败；关闭 Go/Guard/Gate 检查后的其余 `make check` 阶段通过。未执行完整 `make test`、Android 构建或新的 `make package`；本次安装源自已成功的 CI 发布包。
- `/tmp` 是 tmpfs；本次下载和临时 Python 环境占用曾影响安装树验证，清理本次创建的临时数据后，以 127 MB 发布树重新完成隔离验证。
- Qubes 标志是应用策略报告，不代表真正的 Qubes OS 隔离。单机 loopback 测试不能替代跨机 WAN、丢包、长期稳定性或 12 个物理/逻辑核心的测量；测试结果也不保证软件没有漏洞。
