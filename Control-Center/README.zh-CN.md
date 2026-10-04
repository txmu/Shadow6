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

打开 `http://127.0.0.1:9466/` 可使用随程序安装的自适应仪表盘。静态 HTML/CSS/JS
不含账户数据，因此可以无 Token 加载；只读 API 仍要求 Bearer Token。输入本机 Token
后可查看主机状态、分页命名服务和已安装 Native Profile 的诊断。页面只在内存中持有
Token，通过同源请求读取信息，不提供生命周期变更入口。新增
`GET /v1/services/page?limit=50&offset=0` 返回有界且删减敏感字段的分页结果；原有
`/v1/services` 保留以兼容既有 API 客户端。

如果收到 `401`，请检查 token 文件内容；收到 `403`，请使用启动信息里显示的
本机地址和端口；收到 `415`，请添加 `Content-Type: application/json` 并发送
未压缩的 UTF-8 JSON。这样的错误信息是路标，不必靠猜。

## Capability capsule

胶囊注册表由运维者通过 `SHADOW6_CAPSULE_REGISTRY` 指定，JSON 文件必须由当前用户
拥有且权限为 `0600`。每个条目只登记 Core 名称、可执行文件和可选的记录上限：

```json
{"hare":{"binary":"/usr/local/bin/shadow6-hare","max_record":978}}
```

`capsule.start` 会读取已登记 Core 的 `--feature-report`，按 client
`application_boundaries` 选择入口：`seqpacket-fd` 使用 socketpair 和 loopback
`app_flow_proxy`；`localhost-tcp-proxy` 由 Core 自己创建 listener，并通过
`shadow6.ready` JSONL 事件报告实际地址。stream Core 不接收 proxy 参数。没有声明
受支持入口的 Core 会被拒绝。

seqpacket 胶囊需要设置 `SHADOW6_APP_FLOW_PROXY`，并在 `capsule.start` 提供监听端口；
协议默认 TCP，回环地址默认 `127.0.0.1`。Core 与 proxy 都确认启动后，API 才返回成功。
TTL 由后台 reaper 主动执行；
`capsule.pause/resume` 会实际暂停或继续胶囊的 Core 和 proxy 进程组。
`capsule.list` 只返回不含 bearer token 的运行摘要。所有变更仍受默认关闭的 mutation
授权控制。

`capsule.candidates` 是只读发现接口：它只列注册表中的 Core，并附上 feature report
声明的 client boundary。Python `libshadow6.open(require, config=...)` 用它匹配
`kind`、`reliable`、`ordered` 等约束，再调用 `capsule.start`；应用得到实际 loopback
endpoint。`Session.close()` 或退出 `Shadow6` context 会停止所拥有的 capsule。配置文件
可通过 `SHADOW6_CONFIG` 提供默认值。候选选择只判断外围 boundary，不会推断 Core wire
兼容性。

## 组件 IPC

`ipc.catalog` 返回无 npm 依赖的 Node FastRPC/RawIPC 契约；`ipc.call`、
`ipc.raw` 调用运维者预先配置的本地服务；`c11relay.ipc.status` 和
`c11relay.ipc.schema` 提供 Relay 状态与数据报格式。运维者在服务环境中设置
`SHADOW6_IPC_CONFIG`，调用者不能传入密钥、配置路径或目标地址。发送数据及转发
调用仍受显式 mutation gate 保护。这些方法共用 JSONL、HTTP、MCP、LSP 和
OpenAI 函数工具发现，参见[配置与协议说明](../Node-IPC/README.md)。

[Read in English](README.md)
