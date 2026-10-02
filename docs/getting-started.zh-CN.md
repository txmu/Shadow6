# 入门指南

欢迎来到 Shadow6。第一次使用时，不必一口气弄懂所有组件。先运行功能报告：
它只读、不会修改系统，还会如实告诉你当前有哪些 Core 和 Gate 功能。

```sh
shadow6 guide --lang zh
shadow6 features
shadow6 privacy
shadow6 control -- status
```

如果你在源码目录中工作，还没有安装 `shadow6`，把它换成
`.venv/bin/python CLI/shadow6.py` 即可。若提示组件缺失，请在仓库根目录运行
`make build`，完成后再试。

Shadow6 现有十二套独立编译的 Core：Go、Rust、Gleam、Ada、Nim、Pony、Idris、
Zig、D、C++、Hare 和 Carp。十二套均提供原生 broker/agent/client 路径；
Idris、Hare、Carp 的三角色路径采用签名握手及有界固定路由 UDP，同时保留原有
双端、编解码或 adapter 模式。它们都可以
独立部署，但不保证线缆兼容，也不保证相同的可靠性、多路复用或 broker 行为；每一
条连接的所有 hop 都应使用同一个 Core，并以该 Core 的 README 为部署边界准则。
可先查看[Core 能力矩阵](core-matrix.md)，快速了解角色和传输边界。

默认构建关闭 Crosed、应用传输和域策略；在该 Core 支持的范围内，带 `-crosed`
后缀的独立二进制才启用 L5 功能契约。某些 Core 还需要额外的可选工具链。

可选网络适配器提供线缆兼容的 Python 与 Node.js 后端，为接入的调用方提供分块、确认、
重传、去重和多路复用语义。它不会隐藏 Core 自身的数据报上限，也不替代 Core 的原生
认证和传输。运行 `shadow6 network catalog` 可查看各 Core 与适配器 profile 的边界。
十二个 Core 均可脱离 adapter 独立部署；任何 Core 都不需要 adapter 或其它 Companion
才能获得原生网络能力。安全与部署要求见
`Network-Adapter/README.md`。
两种后端都必须遵循 `Network-Adapter/SPEC.md`；可分别运行
`shadow6 network catalog` 与 `shadow6 network-node catalog` 明确选择。

Control Center 默认只读。它的 HTTP API 只监听本机回环地址，并要求从普通、
仅所有者可读写的 `0600` 文件加载 bearer token。在你确认具体操作前，请保留
默认设置，不加 `--allow-mutations`。可直接照着
[Control Center 中文说明](../Control-Center/README.zh-CN.md)中的示例试用。

遇到问题时，先做下面三项检查，通常就能找到下一步：

```sh
shadow6 features
.venv/bin/python Security-Assistants/shadow6_security.py doctor
shadow6 control -- --help
```

Doctor 只观察本地项目，不会改服务、防火墙或路由。日常快速检查和完整发布
流程见[验证与发布指南](verification.md)。慢慢来，每一步都有明确的失败提示。

功能报告里的 `application_boundaries` 描述可选应用调用入口，例如有界 TCP stream、
本地 seqpacket message 或 adapter credit。它不是 Core wire protocol 的协商结果，也不
代表十二种实现可以混合组成一条原生隧道。部署时仍须沿整条路径使用同一 Core 家族。

[Read this guide in English](getting-started.en.md)

分享诊断前，看看[隐私与接口说明](privacy-interfaces.md)中的适用范围和排错建议。
