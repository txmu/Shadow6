# Actions 性能分析：36354745667

来源：[最新已完成运行](https://github.com/txmu/Shadow6/actions/runs/36354745667)，提交 `e0fbc5b5a63c5cdc2d7e9921897bb37a23a6d20e`，2026-09-27 22:17 UTC 启动；对比[上一轮](https://github.com/txmu/Shadow6/actions/runs/36353663175) `df4a5bc7a1ef16fc62529cfc8afa9ac9e7b1215f`。

## 构建与失败原因

55 个 job 中 53 成功、2 失败。实际失败为 `iperf3 netbsd (x86-64)`；`Cross-platform support summary` 正确传播生产任务失败。NetBSD 安装依赖成功，32 项中仅 IPv6 TCP reverse P4 超过 36 秒超时，其余 31 项成功。服务端记录控制消息读取/发送错误，但日志不足以确定 iperf3 或内核内部根因。

本次将既有 NetBSD ARM64 的有界超时重试扩展至 x86-64：仅超时可重试一次，保留两次结果，重复超时仍失败；非超时错误立即失败。该变更缓解孤立超时，是否恢复该平台 CI 必须由新运行确认。

Linux x86-64 已完成十二 Core 的默认构建（Go、Rust、Gleam、Zig、Ada、Nim/libdatachannel、Pony、Hare、D、Idris/Chez、Carp、C++），相关原生工具链可用。Crosed L5 构建涵盖 Go/Rust/Gleam/Pony/Idris，另执行 Nim/Ada 变体目标并恢复默认 L0。此 Linux job 未执行 Public6 变体目标。其他平台按各自支持矩阵构建，不能把 Linux 的十二 Core 覆盖推广至所有平台。

已完成的 Linux 阶段：make build、变体构建、make test（含组件/ML/集成测试）、make check、make audit、doctor、SBOM、observe、暂存安装检查、网络/组件/iperf 基准、打包和归档检查。离线 audit：114 passed / 0 failed / 15 skipped；doctor：20/20。跳过项包含未构建的可选变体，不等于全部审计项执行。

Linux 日志包含缓存恢复/保存失败和 setup-zig 的 Node 20 弃用警告；该 job 最终成功。发布产物位于 `shadow6-linux-release` artifact（GitHub 外层 ZIP 112,275,491 bytes），其中 `ci-artifacts/linux/Shadow6.tar.gz`、`ci-artifacts/linux/Shadow6.zip` 的生成及检查通过；本次未下载发布包，未核实这两个内部归档的单独大小。性能汇总位于 `shadow6-performance-all` artifact（GitHub 外层 ZIP 2,529,124 bytes）。

## Shadow6 原生链路接收吞吐

条件：Linux x86-64 Azure runner，4 logical CPUs，每方向 3 秒，单 iperf 数据流、单组三角色部署。控制连接直连回环且不计入数据路径；数据经过相应 Core 原生链路。TCP 测试还经过有界 Python 转发夹具，UDP offered rate 为 1.1 Gbit/s。以下以 receiver 为准，单位均为 Mbit/s（十进制）。不同传输不表示协议或可靠性相同。

| Core / profile | iperf 数据 | 正向 | 反向 | 正向/反向丢包率 | 相对上一轮正向/反向变化 |
|---|---|---:|---:|---|---|
| zig | TCP | 412.64 | 401.12 | — | +1.2% / -2.7% |
| ada | TCP | 718.23 | 727.59 | — | +3.0% / +1.5% |
| d | TCP | 3127.69 | 3195.71 | — | +0.3% / +7.1% |
| nim | TCP | 338.47 | 377.47 | — | -1.6% / -0.2% |
| cpp | TCP | 1578.97 | 1547.17 | — | +4.0% / -0.1% |
| pony | UDP | 22.05 | 21.69 | 96.36% / 96.39% | +7.9% / -32.2% |
| hare | UDP | 200.29 | 222.49 | 81.56% / 79.54% | +10.5% / -7.4% |
| carp | UDP | 168.33 | 208.72 | 83.98% / 80.78% | -3.5% / +0.0% |
| gleam | TCP | 1130.64 | 869.69 | — | +10.7% / -6.0% |
| idris | UDP | 214.16 | 281.73 | 80.37% / 74.20% | -14.1% / +0.6% |
| go | TCP | 14.67 | 24.46 | — | -61.8% / +133.3% |
| rust | TCP | 2616.00 | 2585.94 | — | +1.3% / +4.3% |
| gleam-mux | UDP | 87.06 | 88.02 | 90.98% / 91.28% | +21.8% / +17.5% |

52 条结果含 26 条夹具/直连基线和 26 条真实原生结果（十二 Core 加 Gleam mux profile）。原生结果 26/26 均产生有效测量，但仅 7/26 满足 ≥1 Gbit/s 且丢包 ≤0.1%：D/Rust/C++ 双向，Gleam stream 正向。其余 19 条未达标，10 Gbit/s 达标数为 0。CI 未启用 `--require-gbps`，所以功能成功不代表带宽合格。

D（3.13–3.20 Gbit/s）、Rust（2.59–2.62）、C++（1.55–1.58）领先本次 TCP 测量；Gleam stream 仅正向超过 1 Gbit/s。Go 仅 14.67/24.46 Mbit/s，相对上一轮 38.43/10.48 出现相反方向的大幅变化，不能由一次 3 秒测量认定稳定回归或收益。Nim 约 338–377 Mbit/s，前后两轮接近。

UDP 丢包约 74–96%，说明当前高 offered rate 下交付质量很差；要测可持续容量需逐级降低发包速率并重复采样，现有数据无法给出低丢包上限。TCP 对照夹具为 5.78–8.17 Gbit/s；它本身低于 10 Gbit/s，本轮不适合验证 TCP 万兆能力。UDP 发送上限 1.2 Gbit/s，更不能用于认证万兆。

从采样 CPU 时间看，Zig/Ada 的忙碌端约占满单个 CPU，Nim 三角色合计约 2.6–2.7 CPU；这是 CPU 开销可能限制吞吐的线索，不能替代 profiling。部分角色 RSS 为零、Idris CPU 计数为零，因此不能用这些字段认定真实零占用。多个成功 TCP 结果含连接 reset/broken-pipe 夹具诊断，应在更长稳定性测试中复查。

以上只有单次短时回环数据，无多次重复/置信区间、跨主机 WAN、外部网卡或长期稳定性测量，不应将不同 hosted runner 的数字直接作为平台排名。

## 主机回环上限（没有穿过 Shadow6）

15 个平台 artifact 合计 480 项：463 成功、1 超时失败、16 个 Windows 多流 UDP 项不适用。峰值取自不同 IPv4/IPv6、方向和并发组合，仅用于理解主机测试环境。

| Platform | 成功 TCP 峰值 Gbit/s |
|---|---:|
| alpine-aarch64 | 187.055 |
| alpine-x86_64 | 107.285 |
| freebsd-arm64 | 4.378 |
| freebsd-x86-64 | 70.974 |
| linux-arm64 | 177.213 |
| linux-x86_64 | 98.926 |
| macos-arm64 | 106.109 |
| macos-x86_64 | 56.944 |
| netbsd-arm64 | 1.073 |
| netbsd-x86-64 | 11.665 |
| omnios-x86-64 | 54.441 |
| openbsd-arm64 | 1.364 |
| openbsd-x86-64 | 55.212 |
| windows-amd64 | 187.152 |
| windows-arm64 | 48.619 |

## 本地验证与证据

本次仅修改工作流超时重试适用平台及本报告。本地通过：`test_iperf3_matrix.py` 4 项、`test_linux_ci_workflow.py` 4 项、BSD 六组合重试策略执行检查、六组合 POSIX shell 语法检查、`git diff --check`。没有本地原生构建、全量发布流程、审计或打包，也未在本机模拟 NetBSD 故障。新提交在真实 NetBSD runner 上的结果待 CI 验证。

原生 `shadow6-linux-iperf-chain/report.json` SHA-256：`7e40706e9640440db6e34813f97d6c6fb0ffcaebbd074526d60fa1dd1b986fff`。原始 receiver JSON、三角色采样与主机报告保留在上述运行的 artifacts 中，可用以下命令取回：

```sh
gh run download 36354745667 -n shadow6-linux-iperf-chain -D evidence-chain
gh run download 36354745667 -n shadow6-iperf3-netbsd-x86-64 -D evidence-netbsd
gh run download 36354745667 -n shadow6-performance-all -D evidence-all
```
