# Shadow6 安全审计报告

审计范围：仓库源码、Android 客户端、Control Center、插件/包管理、GitHub Actions 构建链。审计方式为定向静态审查、人工验证和已有安全/基础设施测试；未运行外部目标扫描、未执行重型全量构建或联网 SCA。结论基于当前工作树（含 Idris feature-report 工作目录修复和 EasyBuild 加固提交 `1d0ff1f6`），未把未跟踪生成文件视为源码。

## 摘要

运行时控制面整体采用了较好的最小权限设计：HTTP API 固定 loopback，Bearer token 使用常量时间比较，默认只读并限制请求体、连接数和并发；拓扑 YAML 使用 `SafeLoader`、拒绝 alias 并限制结构；插件和包路径有签名、路径及权限校验。已运行的 Security/Infrastructure 测试 6/6 通过。

仍有一个高优先级供应链风险和两个中优先级加固项。它们不会证明当前已经被利用，但在构建器或上游下载被攻陷时会直接影响发布制品。这里的“固定”指固定信任身份、兼容版本范围和内容校验，不要求所有 runner 永远使用同一台机器或同一份工具链缓存；CI 应能在新 runner 上重新安装满足约束的工具链。

## Findings

### S6-SC-001（高）：CI 使用可变第三方 Action 引用

证据：`.github/workflows/multiplatform.yml:14,159,214,224,226-240,853-885` 使用 `actions/checkout@v4`、`actions/setup-go@v5`、`dtolnay/rust-toolchain@stable`、`goto-bus-stop/setup-zig@v2`、`setup-nim-action@v2`、`setup-dlang@v2`、`setup-android@v3`、`gradle/actions/setup-gradle@v4` 等 tag/major tag。只有少数 Action 被固定到 commit SHA（例如第 48 行和第 646 行）。

影响：上游 tag 被移动、账号/仓库被接管或 runner 拉取到恶意版本时，任意构建步骤可读取源码、缓存和构建凭据，并污染发布二进制/APK。工作流虽设置了 `permissions: contents: read`（第 2-3 行），但这不能限制第三方 Action 在 runner 上执行代码。

建议：对有权执行构建步骤、读缓存或接触制品的第三方 Action 固定完整 commit SHA，并在注释中保留版本号；对 SHA 做定期依赖更新和变更审查。只读、无凭据的辅助 Action 可以采用经过组织策略批准的版本引用，但应明确记录例外。该措施不限制 runner 类型、架构或工具链安装位置，也不等于要求每次构建使用相同机器。对 release job 增加 provenance/attestation 和独立签名验证。

### S6-SC-002（中，已解决）：CI 下载的 Pony 工具链未做内容校验

历史证据：`.github/workflows/multiplatform.yml:19-23` 曾下载版本 URL 固定的 tarball，检查仅为 `test -x .../ponyc`，没有 SHA-256、签名或可信 manifest 校验。

影响：若 GitHub release 资产、CDN 或传输链被篡改，恶意 `ponyc` 会在 runner 上执行并生成受污染的 Core-Pony 制品。其它 Android 原生依赖在第 892-908 行使用 commit checkout，说明该项目已有更强模式可复用。

处置：`.github/workflows/multiplatform.yml` 现在为 Ubuntu x86_64、Ubuntu ARM64、Alpine x86_64 和 Alpine ARM64 的 0.72.0 资产分别固定 SHA-256，并在解压前执行 `sha256sum -c`；摘要不来自下载响应，校验失败立即终止。工具链升级必须同时审查版本、来源 URL 和摘要变更。该漏洞条目保留用于审计历史和回归追踪，不再表示当前 workflow 仍缺少内容校验。

### 对 S6-SC-001 建议的批判性复核

原建议把“所有具备构建权限的第三方 Action 固定完整 commit SHA”和“增加 provenance/attestation”放在同一优先级。这是有价值的方向，但需要更精确：

- SHA pinning 能阻止 tag 被移动，却不能证明该 commit 本身没有恶意代码，也不能约束 runner 上的 `curl`、包管理器和自定义脚本；它必须与最小权限、受信任 PR 边界、缓存隔离和制品签名验证配套。
- 对每一个辅助 Action 全面 pin 会增加升级和应急响应摩擦。应优先固定能读取源码、缓存、签名材料或发布制品的 Action，并对纯只读辅助步骤采用组织级 allowlist 和定期审查，而不是把“永不变化”当成安全目标。
- provenance/attestation 证明构建来源和声明，不自动证明二进制内容正确，也不能抵抗被信任 runner 生成的恶意构建；仍需要独立的摘要/签名验证、可审计的构建输入和发布门禁。
- 因此本报告保留 S6-SC-001 为未解决的供应链加固项，但将建议解释为分层控制：高权限 Action 的 SHA pin、受保护的更新流程、最小权限和独立制品验证共同降低风险，而不是单独依赖 SHA 或 provenance。

### S6-HARD-001（中）：构建验证器通过 `exec` 动态加载仓库代码

证据：`EasyBuild/shadow6_easybuild.py:168-174` 读取 `Plugin-System/shadow6_plugins.py`，`compile` 后执行 `exec(code, namespace)`，随后实例化并加载插件。

影响：该函数本身不是远程输入注入，且当前代码来自本地 checkout；但一旦构建目录、插件源码或缓存被低权限用户替换，验证阶段会在构建进程权限下执行任意 Python。它削弱了“先验证再加载”的隔离边界。

建议：将插件验证放到独立、无网络、低权限子进程；优先通过固定入口调用并验证模块哈希/签名，避免在验证器进程内 `exec` 任意源码。若保留现状，应明确构建树必须 owner-controlled、不可被共享写入，并在 CI 中检查目录权限。

## 已验证的控制与残余风险

- `Control-Center/shadow6_control.py:961-1066`：loopback 绑定、Bearer token、Host/Origin 检查、16 并发/64 连接上限、65,536 字节请求上限；变更默认关闭。
- `Auto-Orchestrator/shadow6_auto.py:118-134`：YAML alias、深度和事件数均受限，使用 `yaml.SafeLoader`；未发现可达的 `yaml.load` 不安全 loader。
- `Android/.../OpenAiCompatibleClient.kt:18-46,87-108`：API key 与 endpoint 绑定、HTTPS-only、输入/响应有界；远程 MCP URL 由操作者配置且请求标记为始终需要审批，仍应将远程服务器视为不可信并避免把敏感上下文放入 prompt。
- 已运行 Security Assistant/Infrastructure Assistant 测试：6 个测试全部通过；修复后 EasyBuild 测试 4/4、Infrastructure Assistant 测试 2/2 通过，Python 模块编译检查通过。
- Idris feature-report 现在从其 launcher 目录执行，以适配 Chez 运行时树；这解决了“换 runner 后工作目录不同导致失败”的兼容性问题，但不替代对工具链来源和内容的验证。
- 未运行 `govulncheck`、OSV/Trivy/Semgrep 全量扫描；因此不能据此声称依赖无已知漏洞。建议在隔离 CI 中补充锁文件级 SCA、secret scanning 和 Action SHA 审计。

## 优先级顺序

1. 固定具备构建权限的第三方 Actions 到 commit SHA，并给构建工具/制品生成 provenance；保留经过审查的版本更新流程和必要例外。
2. 为 Pony tarball 增加强制哈希或签名校验，按平台/架构维护允许资产清单。
3. 隔离 EasyBuild 的动态插件加载，或加强构建目录权限与签名校验。

本报告未发现已由当前证据证明的 pre-auth RCE、Control Center 远程暴露或明显 shell 注入。部署时仍需确认运行目录、插件目录和 token 文件不被同机低权限用户写入。
