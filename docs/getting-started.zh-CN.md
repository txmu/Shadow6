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

Shadow6 现有十二套 Core 实现：Go、Rust、Gleam、Ada、Nim、Pony、Idris、Zig、
D、C++、Hare 和 Carp。它们在发现、功能校验、安装、编排与基准测试中地位平等；
各 Core 的 README 是其已实现角色与数据路径的权威说明。一条连接从头到尾应使用
同一种 Core；平等对待不代表默认线缆兼容。默认构建关闭
Crosed、应用传输和域策略；在该 Core 支持的范围内，带 `-crosed` 后缀的独立二进制
才启用 L5 功能契约。

统一网络适配器提供地位相同、线缆兼容的 Python 与 Node.js 后端，并隐藏报文大小限制。运行 `shadow6 network catalog`
可查看各 Core 是使用原生流、需要分块/可靠性补足，还是使用经过认证的 companion
数据面。D 与 Idris 的原生程序没有生产流接口，因此由 companion carrier 提供真实
传输；文档会明确这一归属，不会把诊断功能包装成原生数据面。安全与部署要求见
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

[Read this guide in English](getting-started.en.md)

分享诊断前，看看[隐私与接口说明](privacy-interfaces.md)中的适用范围和排错建议。
