# 防守反击（Counterstrike）：分级主动防御

防守反击是 Shadow6 的可选主动防御引擎。它把 Detector 层从单一的有界
Tarpit 升级为一套**分级、完全由运维配置的响应阶梯**，同时保留全部既有
安全不变量：默认失败关闭、严格解析、有界资源，以及带预算的全局 MTD 路径。

它由纯 Python 实现（asyncio + 标准 socket/HTTP 构件），**无需重新编译任何
Core 二进制**。

## 设计契约

- **可选启用、失败关闭。** 不加载策略时引擎是空操作，检测行为与之前完全
  一致；策略必须显式设置 `enabled: true` 才会启用。
- **严格策略解析。** 策略是带未知字段拒绝、禁止浮点数、绝不调用 shell 的
  JSON 文档，从常规、非符号链接、属主可控、`0600` 权限的文件加载，并在
  打开后再次校验。
- **处处有界。** 被追踪攻击者数量、并发交战数、每源预算以及全局每分钟
  上限全部封顶。伪造证据的洪泛无法耗尽线程、套接字或内存。
- **绝不主动外联。** Counterstrike 从不会主动向攻击者发起连接。欺骗与交战
  只作用于攻击者已经建立的连接；最高层级仅向既有 Sentinel **请求**轮换，
  而 Sentinel 仍保留其多源/多端口多样性与令牌预算。

## 响应阶梯

事件以有界的 `SHADOW6_THREAT` v1 行到达（一个带方向的源 IP 加一个目标
端口——绝不包含数据包载荷文本）。每个不同的恶意源会沿严重度阶梯攀升；
来自同一地址的重复攻击会逐级升级。

| 层级 | 名称 | 作用 | 上界 |
| --- | --- | --- | --- |
| 1 | `deception`（欺骗） | 常开的诱饵伪装（SSH/FTP/SMTP/MySQL/Redis/HTTP/401），消耗扫描者时间 | ≤32 个监听，每个 ≤256 客户端，载荷 ≤16 KiB |
| 2 | `engagement`（交战） | Tarpit 粘住恶意连接，消耗攻击者资源 | ≤256 并发，保持 ≤600 秒，每源/每小时预算 |
| 3 | `throttle`（限速） | 对被交战源以封顶速率回送字节，使自动化工具停滞 | 速率 ≤65535 kbit/s，每源/每小时预算 |
| 4 | `rotation`（轮换） | 通过 Sentinel 请求全局 MTD 轮换 | 每周期一个令牌 + 多样性阈值 |

较低层级可立即对单个恶意源生效。轮换仍要求 Sentinel 自身的证据多样性与
轮换预算，因此防守反击永远无法强制一次未预算的全局网络变更。

## 配置

复制示例配置，然后只启用你需要的层级：

```sh
cp Detector/counterstrike.policy.example.json /etc/shadow6/counterstrike.json
chmod 600 /etc/shadow6/counterstrike.json
```

顶层字段：

- `version`（整数，必须为 `1`）
- `enabled`（布尔总开关；为 `false` 时强制关闭所有层级）
- `global_actions_per_minute`（整数 1–10000，全局响应上限）
- `attack_decay_seconds`（整数 60–86400，源被追踪的时长）
- `tiers`（包含 `deception`、`engagement`、`throttle`、`rotation` 四个层级）

部署前校验策略：

```sh
.venv/bin/python Detector/counterstrike.py --validate /etc/shadow6/counterstrike.json
```

## 运行

运行本地自测（仅绑定 `127.0.0.1`，使用临时端口）：

```sh
.venv/bin/python Detector/counterstrike.py --test
```

把引擎挂到线上 Sentinel，让真实的 `SHADOW6_THREAT` 事件驱动阶梯：

```sh
.venv/bin/python Detector/watch.py \
  --topo Auto-Orchestrator/local-test.yaml.example \
  --counterstrike-policy /etc/shadow6/counterstrike.json
```

## 它不是什么

防守反击是对*入站*恶意连接的防御性欺骗与资源消耗，外加一次有预算的对
既有 MTD 轮换的请求。它不是端口扫描、漏洞利用、凭据收集、任意出站流量
或防火墙变更。宿主机防火墙与运维授权的 Guard 策略仍是独立的部署控制。
