# Shadow6 Threat Model

## Scope and assumptions

范围包括 Core/Guard/Gate、Control Center、插件/包仓库、Android 客户端和 GitHub Actions。假设 Control Center 预期仅本机 loopback，插件为签名的 out-of-process 组件，构建 runner 不应被不受信任提交者控制。

## Assets

- Ed25519 私钥、Bearer token、SPA secret 和 Android API key。
- 发布的 Core 二进制、APK、插件和包索引。
- Control Center 的配置、迁移包、审计 ledger。
- runner cache、构建日志和生成制品的完整性。

## Trust boundaries and abuse paths

1. 本机调用者 -> Control Center HTTP/stdio：攻击者尝试绕过 loopback、Bearer 或 mutation gate，目标是执行包安装、迁移或 runbook。现有控制包括 loopback/Host 校验、Bearer、默认只读、schema 拒绝未知字段和有界资源；残余风险是 token 泄露或同机权限失陷。
2. 签名插件/包 -> Core/Control Center：攻击者替换插件目录、索引或路径，目标是加载恶意代码。现有 Ed25519、哈希、权限和 out-of-process 约束；构建验证器内 `exec` 是额外边界风险。
3. GitHub Actions/下载源 -> 发布制品：攻击者移动 Action tag 或篡改未校验 tarball，目标是污染 runner 和 release。该边界是当前最高优先级，见 S6-SC-001/002。
4. Android -> OpenAI-compatible/MCP endpoint：恶意 endpoint 或模型尝试诱导工具调用或获取上下文。当前工具集合只读、调用次数有界且 MCP approval=always；仍需将 endpoint 视为不可信并最小化发送数据。

## Prioritized mitigations

- 高：对具备构建权限的 Actions 做 SHA pinning，Pony 下载签名/哈希验证，制品 provenance/签名。工具链版本应可在新 runner 上重新安装：固定的是版本/兼容范围、来源身份和内容摘要，不是机器、缓存或绝对安装路径。
- 中：隔离动态 Python 加载，构建目录 owner-only，CI 检查缓存和工作区权限。
- 中：为远程 MCP 增加显式 allowlist、显示 endpoint 变更提示，并在发送前过滤敏感配置字段。

## Residual assumptions

若 Control Center 被部署到非 loopback、token 文件可被其他本机用户读取，或 CI 接受不受信任 PR 且拥有写入凭据，则风险等级会显著上升；这些部署条件需要在上线前确认。CI runner 可以按平台、架构和生命周期变化，只要每次都从受信任来源安装满足版本约束的工具链并验证摘要/签名；不可把“复现性”误解为依赖某个固定 runner 或永不更新的工具链。
