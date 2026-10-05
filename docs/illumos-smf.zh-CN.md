# illumos/OmniOS SMF 支持

Shadow6 通过 `smf` typed system-operation backend 接入 illumos 与 OmniOS 的
Service Management Facility（SMF）。`illumos`、`omnios` 和 `solaris` 初始化系统
名称都会规范化为 `smf`。

Named Service 生成锁定的 SMF manifest，其中包含固定的 runner、锁定的 plan
路径、网络依赖、单实例约束和失败关闭语义。生成 manifest 不会自动安装或启动
服务；操作者必须显式执行 SMF 的导入、启用、重启、禁用和删除操作。

typed operation contract 支持 `install-definition`、`activate`、`deactivate`、
`restart`、`status`、`remove-definition` 和 `logs`。SMF 的 FMRI、method context、
权限和 readiness 结果仍需由 illumos/OmniOS 主机上的 provider 返回；Shadow6 不会
把进程存在误判为服务 ready。

GitHub Actions 的 OmniOS job 负责平台工具链和组件验证。SMF lifecycle provider
应在 OmniOS runner 上执行完整的 manifest 导入、`svcadm` 生命周期、漂移拒绝、
readiness、日志和删除测试。当前 Linux、macOS、Windows 的 typed contract CI
不会伪造 SMF 原生执行结果。
