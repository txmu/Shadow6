# 未达标 Core 性能修改与接手方案（2026-09-29）

## 当前授权与执行范围

最新指示已扩展为：落实 Zig 和本方案其他未达标核心的轻量优化及可用的本地验证。以下逐核心方案保留为设计依据，实际落地差异与验证记录见文末。**禁止本地重新编译 Pony 和 Idris**，包括经 `make build/test` 间接触发的编译。不要为了验证下载依赖、修改宿主机网络参数或启用额外权限。默认 L0、隔离、签名、限额及独立协议家族要求仍遵守根目录 AGENTS.md。

起点提交：`a97aff6e`。初始受版本控制工作树干净。规划以 `docs/linux-iperf-history-2026-09-26-to-28.md` 的 9 月 28 日记录为准。目标沿用报告定义：原生接收 >=1 Gbit/s，UDP 丢包 <=0.1%；不能把测量状态 `ok` 当成达标。下列数值均为正向/反向 Mbit/s：

| Core/profile | 最近 CI 接收 | 处理范围 |
|---|---:|---|
| Zig | 417.81 / 416.96 | 本轮实现并验证 |
| Ada | 751.94 / 720.63 | 接收端定长 Cell 批处理 |
| Nim | 340.62 / 383.32 | 双向唤醒、回调队列和复制成本 |
| Pony | 24.81 / 21.56 | actor 调度、批次处理及信用背压 |
| Hare | 197.99 / 230.44 | 有界非阻塞批收与发送公平性 |
| Carp | 168.57 / 212.37 | 有界非阻塞批收与发送公平性 |
| Idris | 221.44 / 273.80 | C 数据通道有界批收；仅 CI 编译 |
| Go | 487.59 / 489.87 | KCP 调度、拥塞与记录开销定位 |
| Gleam stream | 821.05 / 858.20 | 有界 TCP 收发聚合 |
| Gleam mux | 87.11 / 81.60 | UDP 有限 active credits |
| D、C++、Rust | 均双向超过 1 Gbit/s | 保留作回归对照，无计划代码修改 |

Pony/Hare/Carp/Idris/Gleam mux 最近 CI 丢包约 75–97%，必须同时改善丢包。各家可靠性与线格式不同，不统一协议，也不直接把 UDP 与 TCP 数字当成语言排名。

## 先纠正诊断前提

- Zig 的 256 × 1144 = 292,864 字节，即 286 KiB；上限约为 `292864*8/RTT秒`。1 ms RTT 时约 2.34 Gbit/s，50 ms 时约 46.9 Mbit/s。该窗口限制高 RTT 容量，但单凭它不能解释回环 410 Mbit/s。
- UDP 用户态实现不必然比内核 TCP 慢，io_uring 深队列也不必然更快。Ada 仍要处理逐 Cell 认证和重组；需要用同机数据确定热点。
- Zig 现有 Linux `receive/tcpRead/tcpWrite` 每次只提交一个请求并等待 CQE；每轮窗口扫描还逐槽调用时钟。这些是已见源码开销，尚不能在 profiling 前给出占比。
- 放大窗口必须同时评估 TX/RX 内存、16 channel/16 grant 总额、4 MiB worker 栈、拥塞和旧端兼容。不能只改一个常量；旧接收端遇到超窗数据会拒绝。

## Zig：本轮工作和验收方向

文件：`Core-Zig/src/backend.zig`、`tunnel.zig`，以及必要的 ENet 边界测试与 README。

1. 将每轮逐槽时钟调用改为一次采样；重传扫描以有界时间间隔执行，保留原有重试次数、密文复用和拥塞回退。
2. 已知 TCP 就绪后的非阻塞读写避免单请求 submit/CQE 往返；保留 Linux io_uring 初始化失败即拒绝运行、poll/cancel 完整回收和 UDP 批量发送。
3. UDP 发送批次从 32 评估至 64，与原来每 channel 的 64 次工作预算一致；不改成几千条突发、不取消公平性。ring 容量、CQ 回收、ACK 刷新须一起检查。
4. 批收及窗口扩大仅在同机结果和内存边界支持时落地；保持 MTU、认证、未知版本拒绝、重放及半关闭契约。窗口未扩大时应明确说明其 WAN 限制，而不能声称性能问题彻底消失。
5. 本地仅构建 Zig 默认 ReleaseSafe L0，运行 Zig 单元/协议、三角色测试和真实链路基准。记录 CPU/基线/方向、接收速率、重传及诊断。不能拿修改前旧二进制与当前源码重编译结果直接认定代码收益。

本轮实际结果在文末更新。

## 其余核心：一次实现包，逐项保留验证证据

### Ada

文件：`Core-Ada/src/relay.adb`、`platform.c`、`native.ads`，现有 Cells 协议保持。

已见：Writer 已将最多 35 个 Cell 合并发送并批取随机 padding；Reader 每个 512-byte Cell 单独 Ready/Read/Touch。不要重复实现已有发送优化。

方案：接收端使用固定 `35*512` 字节缓冲，一次读取当前可用数据；保留不足一个 Cell 的尾部，逐 Cell 按原序列认证并交给 `Cells.Accept_Cell`。不能为了填满批次阻塞小消息。FIN 后多余数据、残帧 EOF、认证失败仍拒绝，不能跨 FIN 释放明文。Health 时钟检查按有界批次执行，任务取消和线程内 SSL 限制保持。

验收：拆包、粘包、损坏中间 Cell、半关闭、满批/小消息与双向流；本机 GNAT 可用，但由下一阶段决定执行。

### Nim

文件：`Core-Nim/src/runtime.nim`、`rtc_bridge.c`、`native.c`、`rtc.nim`。

已见：RTC 接收已有条件变量，但空闲时最多等 1 ms，TCP 到达不能直接唤醒它。20 个 ID 每个仅 4×65536 字节回调槽；SCTP 收发各 262144 字节。热循环每次最多处理一个 TCP/RTC 消息。此前队列唤醒优化已存在，不应重复提交。

方案：先加入仅诊断模式的队列满等待、buffered(dc)、空闲等待统计；对 TCP 和 RTC 建立共同就绪唤醒（例如每连接有界 eventfd/pipe，跨平台使用对应有界机制），处理关闭/复用 ID 的 generation。循环每方向最多 16 条后轮转。若证据确认队列抖动，再把槽从 4 增至 16，计算总固定内存从约 5 MiB 到 20 MiB；保留 5 s 回调背压及不丢已接收的可靠消息。避免无证据放大 SCTP 缓冲和改变 16384-byte 线格式。

验收：混合 TCP/RTC 唤醒、无丢失 FIFO、队列满/删除/ID 复用/关闭竞态、双向半关闭；C 队列 sanitizer 和 Nim 检查后再原生基准。共同唤醒比简单常量修改复杂，应独立提交便于审查。

### Pony（不在本地编译）

文件：`Core-Pony/runtime.pony`、`protocol.pony`。

已见：16 包接收调度与批量 actor handoff 已存在；SocketActor 的 256 inflight 满额会继续 KeepReading 并丢弃，ReliableSession 允许最多 4096 序列跨度。批处理使用 `Array.shift()`；重传每 10 ms tick 扫描 Map，但每次最多重发 32 包。

方案：将批次消费改为保持顺序的线性遍历/所有权转移，避免重复数组搬移。不要用逆序 pop 改变报文顺序。在核对当前 Pony net API 后，信用耗尽时暂停对应 socket 读取，由 consumed 恢复；可靠网络与原生 application UDP 分开统计丢包/背压，未知 peer 仍限 16 admission。批次初值仍 16，不先增加 4096 窗口。重传维护下一扫描期限，避免无到期包时遍历全 Map；保持每 tick 32 次上限。

验收：只能先做源码审阅；Pony 编译、类型能力/iso 转移、socket 暂停恢复和压力测试交 CI。须覆盖满信用时仍可处理 consumed/close、ACK 进展、短批 flush 和公平性。不能仅靠增加邮箱上限宣称解决 96% 丢包。

### Hare

文件：`Core-Hare/src/runtime.ha`。

已见：已有 256 窗口及每 20 ms 重传扫描；数据通道每轮 poll 后通常每 socket 读一包。每轮另读 deadline 和毫秒时钟。

方案：单次时钟采样用于 deadline/retry；使用工具链支持的非阻塞读取，在每次 poll 后各方向最多 drain 32 包，重新计算每次发送的窗口许可。ACK 和已认证网络数据优先服务，之后轮转应用数据，EAGAIN 回到 poll。保留总迭代/运行时限；不能复用当前一百万次预算却将总可处理报文无意放大 32 倍。UDP 无法保证远端发送者遵守背压，仍要记录 application 侧丢包。

验收：Hare 工具链 API 必须先核实；覆盖窗口绕回、乱序、丢 ACK、重传、持续双向和非法包下公平性。原来已做的 socket buffer 请求无需重复扩大。

### Carp

文件：`Core-Carp/src/runtime.h` 与 `src/main.carp` 的驱动契约。

已见：broker 已有 64 包非阻塞 burst；endpoint `chain_receive()` 每次 poll 并偏向应用读取，已有 20 ms 重传扫描。

方案：针对 endpoint 添加最多 32 包的就绪批次与方向轮转。可采用固定小批缓存，但先核对 main.carp 每包 schema 校验和 dispatch 的顺序，不能在 C 批路径绕过验证。每次发送重新检查 pending 槽，网络 ACK 在应用洪峰期间不能饿死；非阻塞读没有数据时清空 readiness。保持固定堆栈、无分配器、窗口 256、重传 8 次和总包数预算。

验收：schema 拒绝、双向顺序、满窗口、ACK 丢失、应用源地址固定和 idle/deadline；C 检查与 Carp 原生构建应分别报告。

### Idris（不在本地编译）

文件：`Core-Idris/ffi/sodium_ffi.c`、`native_chain.h`。

已见：broker 已有 64 包非阻塞 burst；endpoint 每轮 select 后各读一包，已有 20 ms 重传扫描。不能重复优化 broker 或只改 Idris 高层包装。

方案：endpoint 用固定上限 32 的非阻塞 drain，按网络/应用双向轮转；每条独立检查来源、长度、AEAD、序列和窗口，并保留旧模式与 native-chain 的各自限制。计数继续按实际包/尝试消耗，时限和最终关闭不延后。可复用单轮时钟，不缓存跨越阻塞调用的过期时间。

验收：本轮不调用 Idris/Chez 构建，也不运行会编译 Idris FFI 的本地测试以免违反用户限制。FFI 编译、native self-test、端到端和边界测试交 CI，明确标注本地未验证。

### Go

文件：`Core-Go/data.go`、`performance.go` 及已有性能测试。

已见：桌面 KCP 窗口已达 65535，socket 请求 32 MiB，拥塞控制已经开启；`SetNoDelay(1,20,2,...)`、ACKNoDelay、32 KiB AEAD record 和 buffer pool 已存在。本机内核可把 UDP 缓冲限制在远低于请求的大小。

方案：先记录实际 socket buffer、KCP 重传/拥塞/等待以及 CPU profile，再比较 flush interval 20/10 ms 与现有 records 批量写的成本。只保留在相同基线、重复测量中改善的调度参数。保持拥塞控制、小回复关闭前 flush、32 KiB 认证边界和移动端预算。不扩大 65535 窗口、不把改宿主机 sysctl 作为修复。

验收：race、双栈、内核小缓冲、大流双向半关闭、小回复立即关闭；低 RTT 和有延迟环境各重复测量，后者仅在已有授权的隔离环境中运行。

### Gleam stream

文件：`Core-Gleam/src/shadow6_forward.erl`、`shadow6_role.erl`。

已见：TCP active once，每次输入重新 setopts；decode_frames 每个解密 frame 单独 `gen_tcp:send`。发送侧已经聚合 encode_chunks 为 iolist。当前 Pending+Data 必须 <=2*MAX_FRAME。

方案：接收解密结果聚为单个有界 iolist，按当前 read 中已验证 frames 一次发送，保留 partial frame。显式设置有限 TCP 接收 buffer，保证与 2*MAX_FRAME 边界相容；不要简单启用 active true 导致邮箱无界。认证 FIN 前数据按序送出，再 shutdown；FIN 后任何附加 frame 拒绝。首轮不改变加密线格式/最大 frame。

验收：多 frame 合并、跨 read 残帧、坏 MAC、FIN 尾数据和半关闭；记录 BEAM reductions、调度与字节复制成本。当前 shell 未发现 erl，先查 `.tools`，缺失时不得自行下载。

### Gleam mux

文件：`Core-Gleam/src/shadow6_mux.erl`。

已见：每个 UDP 报文重新 `{active,once}`。与 stream 完全独立，不能套用 TCP 结论。

方案：每 socket 改为有限 `{active,32}`，仅收到对应 `{udp_passive,Socket}` 时补充 32 credits；删除每包重新加 credit 的路径，以免信用累积失去边界。只接受本 relay 拥有的 socket passive 通知。计算每 socket 最坏 32*65536 字节排队量及角色总量；如预算不容许则用 8/16。保留每包认证、来源约束、重放窗口及 lifetime。

验收：32 包恰好耗尽、短批、双 socket 公平性、非法源洪峰、关闭期间 passive 消息及 mailbox 上限；同样测 UDP offered-rate 梯度和丢包。

## 执行顺序与完成门槛

1. 按核心独立小提交实施上述包，先安全回归再测性能，避免一次改多个参数后无法归因。固定 CPU 环境、同版本编译参数，每方向至少 3 轮；保存原始接收端 JSON 和中位数。
2. TCP 保留单流与基线；UDP 先在 100/250/500/750/1100 Mbit/s 阶梯测可持续低丢包速率。不能降低 offered rate 后还声称原 1.1 Gbit/s 目标达标。
3. 后续 CI 执行完整构建、L0/L5 报告、测试、check/audit、doctor、SBOM、observe 和必要安装校验；全通过再打包。Pony/Idris 的编译只能发生在 CI，不能本地跑聚合 make 目标绕过禁止。
4. 报告逐项列出达到/未达到/未验证；无证据的参数改动不进入最终提交。轻量修改不保证所有核心达到千兆，尤其单核 CPU、协议开销和高 RTT 限制。
5. 用户已授权落实其他核心；按文末记录区分实际实现、未采用的设计建议与待 CI 验证项。

## 初始环境证据

初始已有 Zig 二进制的本机短测：Linux x86_64、2 logical CPUs、单流、每方向 3 s；接收 62.19/83.16 Mbit/s，基线 4826.78/4973.65 Mbit/s，TCP 重传 8/9。原始数据暂存 `/tmp/shadow6-perf.K1zSBE/zig-before.json/report.json`。此二进制时间戳为 9 月 24 日，不能证明对应当前起点源码，故仅作初始环境记录，不作严格代码前后对照。
