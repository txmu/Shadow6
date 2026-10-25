# Shadow6

[English](README.md) · [中文文档](docs/README.zh-CN.md) · [组件详细参考](README.reference.md)

Shadow6 提供十二套独立编译的原生网络 Core，以及配置、观察和运维工具。broker、agent、client 构成各自的原生数据路径，不依赖 Ziokt 或可选 Network Adapter 才能联网。应用通过明确的原生接口或带信用背压的 companion 边界接入。

## 选择实际需要的路径

| 层次 | 职责 |
| --- | --- |
| 原生 Core | Go、Rust、Gleam、Ada、Nim、Pony、Idris、Zig、D、C++、Hare、Carp 各自提供文档约定的传输 |
| Named Services 与 Application SDK | 配置审查、按内容寻址的材料、生命周期锁与显式应用接入 |
| Control Center | 统一 CLI/工具 schema、诊断，以及默认只读、需要鉴权的回环服务接口 |
| 可选组件 | Guard、Gate、C11Relay、签名 Plugin、Crosed、Slots、适配器、助手和 Android |

同一原生拓扑的每一跳必须使用同一 Core 家族。十二家族并不自动线缆兼容；十三种 Native Profile 描述应用边界，并不让各 Core 获得相同可靠性、多路复用或平台能力。请结合 [Core 矩阵](docs/core-matrix.md) 与选定 Core 的 README 使用。

## 无需编译即可开始

下载匹配平台的受信任预构建 tar，核对摘要后解压。纯文本 ZIP 不含可运行 Core。运行环境需要 Python 3.11+ 及所选 Core 的动态库。

```sh
python3 /absolute/path/Shadow6/CLI/shadow6.py doctor --human
python3 /absolute/path/Shadow6/CLI/shadow6.py core profiles --installed
```

先按所选 Core 手册准备当前用户控制的原生配置，再检查服务计划：

```sh
python3 /absolute/path/Shadow6/CLI/shadow6.py setup home/nas --core go --profile go-kcp --native-config /absolute/path/core.json --check --human
```

只有已安装功能报告和 doctor 确认可用时，才选择示例 Go/KCP。完整 setup、run、status、应用接入步骤见 [入门指南](docs/getting-started.zh-CN.md)。Named Service 监督目前要求 Linux pidfd；其他平台使用各自原生或 init 路径。

## 默认值与权限

默认 Core 构建关闭 Crosed、应用传输和 Qubes 风格域策略。显式 `*-crosed`、`*-public6` 变体有各自功能契约，应读取真实 feature report。Plugin 保持签名、隔离、进程外和有界；Gate 默认关闭。应用策略不能替代 Qubes 虚拟化边界，也不会自动隐藏网络元数据。

## 文档

- [架构](docs/architecture.zh-CN.md)：Core 独立性、Profile、控制面与数据面。
- [运维](docs/operations.zh-CN.md)：材料审查、生命周期锁、重启和迁移。
- [安全与隐私](docs/security.zh-CN.md)：凭据、能力、匿名载体及暴露范围。
- [验证](docs/verification.zh-CN.md)：原生测试、Ada/SPARK、Idris、Lean 和发布证据。
- [全部文档](docs/REFERENCE.zh-CN.md)：全部维护组件、平台手册与历史记录。

三联合生态发行版保持 **v1.0**，Shadow6 保留原生组件版本与独立发行能力。实际平台以 [发布目录](https://github.com/txmu/Ziokt-Releases) 和精确提交的 [Actions](https://github.com/txmu/Shadow6/actions) 为准；存在源码契约不代表每个平台二进制或物理部署都已验收。
