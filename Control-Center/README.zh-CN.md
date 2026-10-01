# Shadow6 Control Center

新增的 `privacy.report` 与 `system.guide` 在 CLI、MCP、LSP、函数工具和 HTTP
中共享同一契约。JSONL 也默认只读，详见[隐私与接口说明](../docs/privacy-interfaces.md)。

Control Center 把功能检查、配置校验、插件清单、Slots 和固定运维动作收在同一个
入口里。它不接受任意命令，远程和工具接口默认只读。

先从这几条安全、只读的命令开始：

```sh
shadow6-control schema
shadow6-control status --root /path/to/Shadow6
shadow6-control call system.status --params '{}'
```

本机 Web API 需要 bearer token。token 文件必须是普通文件、不能是符号链接，
权限应为 `0600`，内容至少 32 个可见 ASCII 字符。

```sh
shadow6-control serve --token-file /etc/shadow6/control.token

curl --fail --header "Authorization: Bearer $(< /etc/shadow6/control.token)" \
  --header 'Content-Type: application/json' \
  --data '{"method":"system.status","params":{}}' \
  http://127.0.0.1:9466/v1/rpc
```

API 只监听回环地址，并拒绝异常 Host、重复认证头、跨站浏览器请求、压缩请求体
以及未明确声明为 JSON 的 RPC 请求。请求大小、连接数和并发数均有限制。
只有在明确加入 `--allow-mutations` 后，状态变更方法才会开放。

如果收到 `401`，请检查 token 文件内容；收到 `403`，请使用启动信息里显示的
本机地址和端口；收到 `415`，请添加 `Content-Type: application/json` 并发送
未压缩的 UTF-8 JSON。这样的错误信息是路标，不必靠猜。

## 组件 IPC

`ipc.catalog` 返回无 npm 依赖的 Node FastRPC/RawIPC 契约；`ipc.call`、
`ipc.raw` 调用运维者预先配置的本地服务；`c11relay.ipc.status` 和
`c11relay.ipc.schema` 提供 Relay 状态与数据报格式。运维者在服务环境中设置
`SHADOW6_IPC_CONFIG`，调用者不能传入密钥、配置路径或目标地址。发送数据及转发
调用仍受显式 mutation gate 保护。这些方法共用 JSONL、HTTP、MCP、LSP 和
OpenAI 函数工具发现，参见[配置与协议说明](../Node-IPC/README.md)。

[Read in English](README.md)
