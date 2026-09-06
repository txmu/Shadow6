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

Go 与 Rust 各是一套完整协议栈。一条连接从头到尾应使用同一种 Core。
默认构建关闭 Crosed、应用传输和域策略；带 `-crosed` 后缀的独立二进制才启用
L5 功能契约。

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

Doctor 只观察本地项目，不会改服务、防火墙或路由。需要完整构建与验证时，
请按仓库 `AGENTS.md` 的流程执行。慢慢来，每一步都有明确的失败提示。

[Read this guide in English](getting-started.en.md)

分享诊断前，看看[隐私与接口说明](privacy-interfaces.md)中的适用范围和排错建议。
