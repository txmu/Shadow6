# Actions 36034077459 性能分析与整改记录

来源：[multiplatform / ad09e87f](https://github.com/txmu/Shadow6/actions/runs/36034077459)。下载的两个 Artifact：`shadow6-iperf3-linux-x86_64`、`shadow6-linux-network-benchmark`。以下为旧版本实测，不能当作本次修改后的性能。

## 测量口径

- iperf3：4 个逻辑 CPU 的 GitHub runner，32 项 TCP/UDP IPv4/IPv6 正反向用例。TCP 单流约 34–38 Gbit/s，多流最高 94.762 Gbit/s；这些数据完全绕过 Shadow6。UDP 约 2 Gbit/s 是设置的发送速率，不是测出的系统最大容量。两个 artifact 来自不同 job，不能假定独占相同硬件或相同 CPU 调度。
- Shadow6 pressure：36/36 通过，十二核心 × native/Python/Node；4 个独立 ABC 三角色部署，每路 4096 字节 × 8 请求，每 512 字节等待完整回声。它测串行往返 goodput，不是持续单向吞吐。
- 旧 companion 测试每次操作经过持久 Python/Node 子进程的 JSON/hex IPC，且 TCP 两端没有设置 NODELAY。这些 IPC 属于测试驱动，不能直接归因到所有原生 Core 的生产路径。
- 组件矩阵 884/884 通过；其中无模拟丢包的 216 行 Python 编解码中位数 750.915 Mbit/s、Node 102.847 Mbit/s。不同负载尺寸/并发混合，不能当作跨语言排名。存在 >1 Gbit/s 的组件记录，因此现有证据不支持所有核心均完全受 ChaCha20-Poly1305 限制。

## 旧 pressure 结果

| Core | Native Mbit/s | Python Mbit/s | Node Mbit/s | Native p95 ms |
|---|---:|---:|---:|---:|
| go | 33.765 | 0.202 | 0.201 | 5.715 |
| rust | 59.795 | 0.201 | 0.201 | 2.989 |
| zig | 37.304 | 0.202 | 0.202 | 15.468 |
| ada | 63.584 | 0.201 | 0.202 | 3.795 |
| d | 0.486 | 0.150 | 0.149 | 322.493 |
| nim | 2.583 | 0.188 | 0.187 | 55.974 |
| cpp | 3.997 | 0.040 | 0.039 | 247.230 |
| pony | 1.044 | 0.607 | 0.659 | 194.961 |
| hare | 60.285 | 6.287 | 4.386 | 2.960 |
| carp | 65.981 | 6.364 | 4.440 | 2.633 |
| gleam | 32.461 | 0.201 | 0.200 | 8.670 |
| idris | 63.188 | 6.255 | 4.310 | 2.393 |

## 可由源码确认的问题与本次修改

- D：空闲循环固定等待 10 ms；每个 1 KiB 记录分开写帧头和密文。现改为事件等待、独占序列号的双向线程、最多 16 个原有格式记录合并一次写出；错误时唤醒对端并 join，线程栈和缓冲区固定上限，TLS 对象不跨线程共用。没有更改线上帧格式。
- Pony：原来每收到一个 UDP 包就主动让出 actor；现使用运行库已有的 16 包/轮限制批量读取，仍保留 32 包 ingress credit 上限。Pony 已有多线程 actor runtime，这项变化不等于已解决会话内串行处理。
- Nim：转发循环每次迭代都 sleep(2)，现在只在无进展时休眠；libdatachannel 本身已有线程，Nim 对象仍由其所属线程访问。
- C++：为 TCP/SCTP socket 设置对应 NODELAY（SCTP 选项在平台提供时启用），既有 16 个会话 worker 上限不变。
- 测试适配器：TCP carrier 设置 NODELAY，避免 ACK 与回声被小包合并等待放大。
- Hare/Carp 等原生路径仍有单包待 ACK 限制；提高调度线程数量不能直接消除这个窗口。扩展窗口需要独立的乱序、重放、重传、nonce 和资源边界验证，不能用裸 UDP 替换现有安全协议。

## CI 的新验收

`Benchmark/iperf_chain.py` 为每个 Core 生成真实凭据并启动 broker/agent/client。TCP Core 使用 iperf3 TCP 数据流，UDP Core 使用 900 字节 iperf3 UDP 数据报（低于所有数据报契约上限），均测试正反向。

iperf3 的 TCP 控制连接直接走 loopback；测量的数据经过 Core 的原生路径。TCP 测试夹具额外使用有界 Python 转发，因此必须同时看匹配夹具基线；UDP 数据直接进入 Core 应用端口。某些家族的 broker 只负责控制平面，测试不谎称它转发这些家族的数据。

默认单个三角色链；`--parallel 1..4` 代表独立三角色链，明确不代表 Core 内部 worker 扩展性。保存 iperf 客户端/服务端 JSON、角色日志、CPU/线程/上下文切换快照。只接受 receiver 统计，禁止回退到 sender；Gbps 目标要求接收吞吐至少 1e9 bit/s、UDP 丢包不高于 0.1%。CI 使用 `--require-gbps`，未达标会失败并仍上传 artifact。

新 artifact：`shadow6-linux-iperf-chain`。新测试不能证明长时间稳定性、WAN 拥塞控制或十二核心全部具备会话内多线程扩展能力。

## 验证与未完成项

本地按用户要求仅做轻量验证：D 模块编译、C/C++ 语法检查、Python 编译检查、4 项 receiver 统计单测及各 1 秒的 TCP/UDP 夹具冒烟。完整构建、安全/可靠性回归、性能验收交给 CI。没有本地执行完整 release workflow、变体构建、审计或打包。

截至提交前，不能宣称所有核心已多线程化或全部达到 Gbps。Go/Rust/Gleam/Pony/C++/Zig 已有相应并发运行机制，D 在此改为双向线程；Ada/Hare/Carp/Idris 的原生数据路径以及 Nim 主循环仍需继续设计和验证。安全控制保留，真实性能结论必须等待 CI。

## 下载文件 SHA-256

```text
e1be2d5d5e5b0c681a79e22707e5f191e1c2903b392a24b4b7f02ed1f5b06a2e  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-forward-p1.json
ca7778f8a306d67edea737afc9977b650eb22ecadc27a87b4fbbc26cd38fb3cc  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-forward-p12.json
967a2e88a0c82b2ac062b0fe4c5a14c58efede932f75027c45c12be4b3aa6e2d  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-forward-p2.json
0d8e70381bd485ca7e7f7acb0f4485f6aeb32631536e6b245782846696060b78  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-forward-p4.json
d14c0c6a790d56407cf60472bfaec1929834adfb9f4fa7c67c12e8428cf28701  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-forward-p8.json
456273140f20f301fc3f97be78007764daa15679529a90189ddc0f5e7df2034e  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-reverse-p1.json
d78944411d884e94c48fa7b979ad4c798f3c362a5e5057b3cc487f966b82c62a  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-reverse-p12.json
03533444dcbd356bf4b1d6ff2806643a91f0f7d28c509b351d573b46f68f6aa3  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-reverse-p2.json
a6a0e31cc0c0ba1ef72e5583c9b686e0609ef1890dbcae18c3f39134d55fa340  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-reverse-p4.json
819c82976a48ecda96334f02227ca9836306c4b0a4a725162f61493f6b2a0777  shadow6-iperf3-linux-x86_64/raw/tcp-ipv4-reverse-p8.json
309322476731e9260e1270f389a5d1dd0411f79d83f0ccb7c46da66ad6a701c1  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-forward-p1.json
1d303687b3803eb36f71f4ce41d87c73a426845a76db12070dfa4682bc942688  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-forward-p12.json
9ec319c166007df51bd14761704f2d7c84fa4a313481e90c2ee6f1ae80384ae0  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-forward-p2.json
7e738971fc17c06412834cc5a6278889bd0f0bcd7f078f5d32639f2a3df93201  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-forward-p4.json
fb93342393e7f908b04d2040f550d5a20f54cfdaa74e6539838b79c84df384bc  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-forward-p8.json
5b6344be9c98c6b2ea99edf05d8a4b00f6bd97bcdbb05a6a9b7ad398f5e90b1c  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-reverse-p1.json
6071f2a314d91bd614f348d36164a5afac750d4a9c591accec72583cf1be11a1  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-reverse-p12.json
fa539dfe777dc0f5b4a648ba936e652804b769e973de6d4080c9a6e43888a5c3  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-reverse-p2.json
4d1066f7584c839a83fb7d2d2fe43da44fd0334347cf6313616998f06197e704  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-reverse-p4.json
d785da1b294b7971d3d2f895a99427300b8c9a6b95b5d2cffba9638c4abb7f95  shadow6-iperf3-linux-x86_64/raw/tcp-ipv6-reverse-p8.json
020c550c510a5ce48b0215b46282a11afa446bf1509cfb5efcd69596cfe373b4  shadow6-iperf3-linux-x86_64/raw/udp-ipv4-forward-p1.json
d5804d5ef1cac5e6f18fdb36bc1e223c8733dcc2236466c51ace586aa47c321f  shadow6-iperf3-linux-x86_64/raw/udp-ipv4-forward-p12.json
9aa4c670de12e51d1c24f296682b63c10302c4c78798aa374a09d276602af41e  shadow6-iperf3-linux-x86_64/raw/udp-ipv4-forward-p4.json
9158bf0b415dc6201d465ded6b2272dd9e5dd9fe647e49742459ed205d5d9d11  shadow6-iperf3-linux-x86_64/raw/udp-ipv4-reverse-p1.json
57173481f455535c931ec8be665a87d9ccc1c8975ea0f9b7d24b049a471c6fde  shadow6-iperf3-linux-x86_64/raw/udp-ipv4-reverse-p12.json
46425a79a54381a96ee678e133aad380bdb8c7aec77f183c52e41312b0f97839  shadow6-iperf3-linux-x86_64/raw/udp-ipv4-reverse-p4.json
cc033df6cb2c6168c7d8a79a7f6ecda7dedc5b5a024eba3005c7218c75b6d4d2  shadow6-iperf3-linux-x86_64/raw/udp-ipv6-forward-p1.json
7b9a048207f97f6dc9b98eff9fa9e291bc856227f9455f0ec02ae390630fc9b9  shadow6-iperf3-linux-x86_64/raw/udp-ipv6-forward-p12.json
e022a5c2d0e9e320c34d842cba9a4a90dccb3e10c50fe83184fc9f9f6d54873c  shadow6-iperf3-linux-x86_64/raw/udp-ipv6-forward-p4.json
5f3cc7f8c179e401531b958200154943bd0f1b49d58840ae2ffa7df4754af31c  shadow6-iperf3-linux-x86_64/raw/udp-ipv6-reverse-p1.json
aabe765fe012f267a4ede9f9c1204149efbaadb2725c677017a0865b35b3f9ae  shadow6-iperf3-linux-x86_64/raw/udp-ipv6-reverse-p12.json
975e7fb1619902a851fd5c61906cc396f266c4e1b075918a33f7a5454df17d87  shadow6-iperf3-linux-x86_64/raw/udp-ipv6-reverse-p4.json
46608376f7bcbe350aab0f216e7221a2bd9c2b1e7cd023b0f596d54ba550b9cd  shadow6-iperf3-linux-x86_64/report.json
d9cced29add2da1e9f4a5234ad217256a0b571a29b74530270dc13c8e33b2744  shadow6-iperf3-linux-x86_64/report.md
5e5a0bdcae4e21841c2f24b6cf7124e960c638706372c57c678438ee011c7565  shadow6-linux-network-benchmark/benchmark-linux-components.json
c4e172d32d95d30e1282b6808da157a6578c7a0774b5a50eed39266eedffe249  shadow6-linux-network-benchmark/benchmark-linux-network.json
10622649045172bcede5742ab7ad73f19afccf5b5ac1b1b6fd5149086263904a  shadow6-linux-network-benchmark/benchmark-linux-network.md
892891dfb05f25a27a8fdc00bca2a8450f55aab85ca43fe1013c4e17e456521c  shadow6-linux-network-benchmark/benchmark-linux-network.txt
4e8f96d6584c100b4d038bda6a492514da87b8b141b26aed804b120233683037  shadow6-linux-network-benchmark/benchmark-linux-pressure.json
e05dcc0235cff12f7db903771e617bc29fba53ac22eb69ede531d331b69417c7  shadow6-linux-network-benchmark/benchmark-linux-pressure.md
d894c0fee83c88fdd039ac72f83855eaed60f6a427c34916a165865f4ec220c9  shadow6-linux-network-benchmark/benchmark-linux-pressure.txt
```
