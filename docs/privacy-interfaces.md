# Privacy across interfaces / 各接口隐私说明

Use `shadow6 privacy` when you want to share a quick health result. It returns
only total, passed and failed check counts. Raw diagnostic text, paths, identity
fields, versions and timestamps are excluded by constructing a fresh result
from an allowlist. This is data minimization, not network anonymity.

想分享健康检查结果时，可以运行 `shadow6 privacy`。摘要只保留检查总数、通过数和
失败数，不复制原始诊断、路径、身份字段、版本或时间戳。它减少分享的信息量，
并不会隐藏网络 IP。详细排错请在本机运行 `shadow6 control -- status`，分享前
自行检查完整结果。

| Entry / 入口 | Privacy summary / 隐私摘要 | Shared guide / 共享帮助 |
| --- | --- | --- |
| Unified CLI | `shadow6 privacy` | `shadow6 guide --lang zh` or `--lang en` |
| Control CLI | `shadow6-control privacy` | `shadow6-control guide --lang zh` |
| JSONL / HTTP RPC | `privacy.report`, params `{}` | `system.guide`, params `{"lang":"zh"}` |
| MCP | `shadow6_privacy_report` | `shadow6_system_guide` |
| LSP executeCommand | `shadow6_privacy_report`, arguments `[{}]` | `shadow6_system_guide`, arguments `[{"lang":"zh"}]` |
| Function tool adapter | `shadow6_privacy_report` | `shadow6_system_guide` |

The shared schema is the source for tool discovery. `shadow6 openai-tools`
exports function definitions; `shadow6 schema` lists every method. Guide output
is a structured JSON object on every interface, including the CLI.

接口从同一份 schema 生成工具清单。`shadow6 openai-tools` 导出函数工具定义，
`shadow6 schema` 列出全部方法。帮助内容在所有接口中均为结构化 JSON，便于终端
和客户端使用同一份内容。

## Permissions and compatibility / 权限与兼容性

JSONL RPC now follows the same read-only default as MCP, LSP, function tools and
HTTP. Scripts that intentionally change state must explicitly start
`shadow6 rpc -- --allow-mutations`. This flag does not relax capability checks,
signature verification or fixed-command restrictions. Direct local `call`
commands continue to represent an explicit operator action.

JSONL RPC 与其他服务接口统一为默认只读。有意执行写操作的脚本需明确使用
`shadow6 rpc -- --allow-mutations`。该选项不放宽能力检查、签名验证或固定命令限制。
本机直接执行 `call` 仍视为操作者明确发起的动作。

`--json-events` emits component names and argument counts, never argument values.
It does not filter the child program's own output. Service errors use fixed
messages and retain an error class or protocol error code. Component progress
printed through Python stdout is discarded by JSONL and tool adapters; stderr
and output from child processes are not a universal redaction boundary.

`--json-events` 只记录组件名与参数数量，不回显参数值；它不会过滤子程序自身的
输出。服务错误使用固定提示并保留错误类别或协议错误码。JSONL 和工具适配器
丢弃组件通过 Python stdout 打印的进度，但 stderr 和子进程输出并非全面脱敏。

Existing detailed methods intentionally retain their useful data. The privacy
summary is the sharing surface; signed documents are never rewritten for
redaction. Tokens, keys and local access controls still matter. A user with
control of the host account can read what that account can read.

原有详细方法保留排错所需的数据。请用隐私摘要分享概况；签名文档不会为脱敏而
改写。token、密钥和本机访问控制仍需妥善管理，拥有主机账户控制权的人仍可读取
该账户有权读取的内容。

## Verified changes / 本轮检查记录

- P1, closed: raw arguments in CLI event output could expose secrets; replaced
  with an argument count. CLI 事件原始参数可能泄露秘密，已改为仅记录数量。
- P1, closed: JSONL permitted mutations by default; an explicit flag is now
  required. JSONL 默认写权限已收紧为明确开启。
- P2, closed at control error boundaries: exception messages could expose paths
  or input values; fixed recovery messages are used across the adapters.
  控制接口异常文本可能暴露路径或输入，现统一为固定恢复提示。

Scope: Control Center and unified CLI. This is a targeted hardening review,
not a penetration test of deployed hosts or a guarantee of anonymity.
范围为 Control Center 与统一 CLI；不代表对部署主机进行过渗透测试或保证匿名。
