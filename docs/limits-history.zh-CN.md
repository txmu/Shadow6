# 统一弹性 Limits：实现历史与验证边界

## 2026-10-04：由零散边界转向共享解析契约

此前，Native Profile 的应用连接数、消息长度与外围组件配置各自保存
资源上限。安装树和源代码不一致时，旧 doctor 也可能只报告组件存在，
不足以证明新生命周期契约可用。

本次引入 `Crosed/limits.py`，定义唯一的 HostBudget、LimitResolver 与
LimitResolution；Native Profile Registry 声明协议硬限、保守默认、推荐值、
容量成本、实现上限和执行者。协议硬限与当前实现的容量上限分别记录，
不能把实现常量宣传成协议的无限扩展能力。

HostBudget 获取实际 RAM、当前进程的 RLIMIT_NOFILE、Linux nr_open、CPU
亲和性及 cgroup v2 层级限制，并识别根路径的旧 cgroup 内存限制。
所有生效值必须为有限正整数；未知 override、浮点、布尔值、零值以及
超越主机或协议边界的请求均拒绝。不可调整的 Native 容量不能假装扩大。

Named Service 将解析结果写入 DeploymentLock，旧锁必须显式重新锁定。
CLI 接受 `--limits-mode safe|elastic|custom` 和 owner-only JSON 文件
`--limits-overrides`。启动计划携带同一解析结果，supervisor 设置
RLIMIT_NOFILE，消息适配器使用锁定的记录上限。Linux 观察检查实际进程
的 FD 限制，doctor 输出锁定解析明细与当前主机预算。预算改变要求显式
停止、重新锁定；不会自动缩减正在运行的服务。
Named Service 的 systemd/procd 定义采用锁定的主机 FD ceiling；Detector
重新验证同一解析结果及运行观察，报告限额或预算 drift。

## 验证记录与未完成范围

初始限额/配置/Profile/安装回归组：56 项通过。加入限额观察字段后的
首次生命周期回归暴露 schema 不匹配，已修复，最终结果以测试日志为准。

此前真实 Native 生命周期已验证 9 个 Profile。Carp、Hare、Pony、Idris
仍需取得包含当前结构化 ready 事件的 CI 产物再测；旧产物不可用 PID
存活替代 ready。已安装十二个默认 Core，不等于十二个新契约均已验证。

当前阶段没有完成全部外围组件的资源维度收口、全平台主机资源后端、
所有旧配置迁移及全矩阵 CI。本文件记录实施历史，不代表发布验收。
源码提交、推送与源码包必须另列实际提交和产物信息。
