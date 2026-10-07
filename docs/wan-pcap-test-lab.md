# Shadow6 WAN / PCAP Test Lab

This guide is bilingual. The Test Lab consumes the Native Profile Registry and
the existing Native config generators and Named Service lifecycle. It does not define another
Core list or normalize Core wire protocols. Reports always name the Core,
Profile, native transport, application boundary, adapter, and carrier.

## English

### Fetch a successful Actions artifact without compiling Cores

Authenticate the GitHub CLI, then ask the Test Lab to fetch the most recent
successful `multiplatform.yml` run on the repository's default branch. The
fetcher verifies the completed run, workflow artifact name, source commit,
available GitHub artifact digest, zip bounds, safe archive paths, Profile
contract digests, and every available binary SHA-256. A successful older run
that predates the per-file manifest is still bound to GitHub's run/commit and
download digest; the report shows that per-file provenance was unavailable.

```sh
python3 Test-Lab/shadow6_test_lab.py --fetch-artifacts --check
python3 Test-Lab/shadow6_test_lab.py --fetch-artifacts --all-profiles \
  --scenario clean --scenario good-wan --scenario high-jitter \
  --scenario failure-recovery --capture --payload-bytes 4096 --requests 2
```

Use `--run-id RUN_ID`, `--commit FULL_SHA`, or `--tag TAG` to pin a source. To
consume an artifact directory downloaded by another workflow, use
`--artifacts-dir PATH`. `--check` is read-only and prints all twelve primary
Cores plus every registered Profile. `--all-cores` executes each Core's
primary Profile; `--all-profiles` also executes the additional Gleam
micro-mux Profile. `--core` and `--profile` narrow a debugging run.

The runner creates temporary Named Services through the existing setup, lock,
run, status and connection APIs. Binary and config material are locked before
launch, and structured readiness, owned endpoints and RuntimeObservation are
required before attaching. The deterministic 4 KiB logical payload is compared
byte for byte, with sent/received lengths and SHA-256 recorded. Message Profiles
use whole records bounded by the Profile max_record, including the real
seqpacket-fd attachment; stream Profiles use the registered TCP boundary.
Each measured goodput result is accepted only after payload correctness passes.
Failure/recovery schedules latency-only baseline, degraded and restored phases
after the worker emits its structured workload-ready event. Twelve bounded
probes span the phases while preserving the exact echo contract for best-effort
datagram profiles. RTT excludes explicit test pacing, whose value is reported
separately. This does not prove loss recovery, reconnect or migration.

### Simulated network and PCAP

```sh
python3 Test-Lab/shadow6_test_lab.py --list-scenarios
python3 Test-Lab/shadow6_test_lab.py --fetch-artifacts --all-cores \
  --scenario clean --scenario good-wan --scenario high-jitter \
  --scenario failure-recovery --capture
python3 Test-Lab/fingerprint_cli.py capture.pcap --run-id RUN_ID \
  --core go --profile go-kcp --link-type native --scenario good-wan \
  --output flow.json
```

The runner checks Linux `ip`/`tc` (including standard sbin locations),
`CAP_NET_ADMIN`, `CAP_SYS_ADMIN` and capture `CAP_NET_RAW`. Clean namespace
capture does not require tc. Run with explicit operator-provided sudo privileges
when the current process lacks these capabilities. Downloaded artifacts must be
owned by the execution identity or root before feature admission. Namespace
workers drop to the checkout owner after namespace entry. A namespace-local
dummy interface provides Native address discovery/ICE candidates with no host
uplink; its routes exist only inside the owned namespace. Simulated
WAN runs use a private network namespace and `tc netem` on its loopback path;
the configured directional profile is reduced to a conservative symmetric
loopback impairment because one loopback qdisc cannot distinguish endpoint
directions. `NamespacePair` contains a veth/netns helper for future separated
endpoint runs, but the current matrix runner does not yet route its Core trio
over that pair. Failure-recovery uses bounded latency-only baseline, degraded
and restored phases so best-effort datagram profiles can still meet the exact
echo contract; it does not claim loss recovery or reconnect. These results are explicitly **simulated**, never real-WAN
measurements. When namespace capability is missing, the affected rows are
`BLOCKED` with the detected reason; a requested capture never falls back to
capturing a host interface.

PCAP uses `tcpdump` if installed, records interface/namespace/time/run/Core/
Profile/scenario metadata, and caps each file at 4 MiB. `tshark`, Zeek and
nDPI are optional observers; missing tools are reported. Unknown traffic stays
`unknown/custom`. The leak scanner reports hashes for explicit forbidden
fixtures and does not echo the fixture contents. No private key, bearer token,
or native configuration is included in the CI Test Lab artifact.

The fingerprint schema is `shadow6.wan-pcap-fingerprint.v1`. It reports
observable flow tuples, packet and byte counts, packet-size distributions,
directionality, timing/bursts, conservative handshake observations, and leak
scan status. It does not infer DPI resistance, concealment, security defects,
or protocol identity from IP/port differences.

### Artifact-backed CI bundle

After producer jobs finish, the `Platform/architecture artifact bundle` job
downloads same-run `shadow6-*` artifacts and publishes `shadow6-artifacts-all`.
The ZIP contains `platforms/<platform>/<architecture>/` groups, each with an
`artifacts.tar.gz`, a self-contained `manifest.json`, `README.md`, `install.sh`,
`install.ps1`, and the shared bounded installer helper. Each group can be
copied out and still verify its source commit, payload digest, and every
contained file digest before installing or staging it. Linux x86_64 runs the existing prebuilt release
installer when the full release tar is present. Android uses `adb install -r`
on a connected, already-authorized device. Component-only groups are staged in
the current user's local artifact directory; they do not enable services,
install packages, or change firewall/routes. `manifest.json` binds file hashes
to the workflow run and source commit; `SHA256SUMS` covers the overall ZIP.

The Linux `native-test-lab` job downloads the same-run Linux release artifact
and runs every registered Native Profile with bounded correctness, simulated
WAN, PCAP and fingerprint analysis. It never recompiles the Core binaries.
Environment capability failures are reported as `BLOCKED` and uploaded; both
`BLOCKED` and Core/Profile `FAIL` fail that job. A missing requested PCAP cannot
produce a scenario PASS. Ordinary PR execution uses no public VPS.

### S6EPE, real WAN and Android limits

The current Test Lab derives the legal S6EPE Core/Profile/Carrier rows from the
existing `Control-Center/privacy_envelope.py` compatibility source. It does
not yet run the four-carrier raw/TLS 1.3/SCTP/WebRTC PCAP endpoint tests or
baseline indistinguishability experiments. The legal matrix is source
compatibility, not runtime evidence. `standard-tls13` is not browser TLS
indistinguishability; `standard-webrtc-datachannel` is not browser
indistinguishability, anti-DPI, or censorship resistance.

Remote SSH/VPS orchestration, remote PCAP, NAT observation, and grouped
Detector adversarial train/test experiments are not wired into this runner
yet. Do not pass credentials through command-line arguments or check them into
the repository. Future real WAN scenarios must be explicitly enabled and label
operator-supplied endpoint/region/network-kind data. The current netns suite is
not a substitute.

Android builds its 13 Profile descriptors directly from
`Crosed/native_profiles.py`; the app lists all twelve Native Cores and marks
the artifact/runtime binding available for the four currently packaged Core
engines. In a Client Profile, **Connect Core** waits for the Core's structured
`shadow6.ready` event. **Run 4 KiB application echo correctness probe** sends
bounded bytes through the local Client ApplicationBoundary and verifies exact
echo bytes and SHA-256; configure the remote Agent target as a controlled echo
service first. Copying the Android Test Lab JSON reports Profile, transport,
boundary, readiness and explicit capability limits, and excludes configuration
secrets. Device-side PCAP, the desktop supervisor, S6EPE, S6SG1 and desktop LLM
Lifecycle remain `unavailable`; the app does not add a shared platform ABI or
embed the Python Control Center.

## 中文

### 从 Actions 取预编译产物，不重新编译 Core

先让 GitHub CLI 登录，再运行以下命令。下载器默认查找默认分支上最新
成功的 `multiplatform.yml`，校验已完成的 workflow run、artifact 名称、源提交、
GitHub 可提供的 artifact digest、ZIP 边界与安全路径、Profile 合同摘要和每个可用
二进制的 SHA-256。早于逐文件 manifest 的成功 Actions 产物仍会与 GitHub run/commit
及下载 ZIP digest 绑定，但报告会指出逐文件 provenance 当时不可用。

```sh
python3 Test-Lab/shadow6_test_lab.py --fetch-artifacts --check
python3 Test-Lab/shadow6_test_lab.py --fetch-artifacts --all-profiles \
  --scenario clean --scenario good-wan --scenario high-jitter \
  --scenario failure-recovery --capture --payload-bytes 4096 --requests 2
```

可用 `--run-id RUN_ID`、`--commit FULL_SHA` 或 `--tag TAG` 固定来源；已有下载目录用
`--artifacts-dir PATH`。`--check` 只读显示十二个 Native Core 和全部注册 Profile。
`--all-cores` 跑每个 Core 的主 Profile；`--all-profiles` 还会跑 Gleam micro-mux。
调试时用 `--core` 或 `--profile` 缩小矩阵。

当前 runner 复用 Named Service 的 setup、lock、run、status 和 connection API，先锁定
binary/config，再要求结构化 readiness、归属正确的 endpoint 与 RuntimeObservation。
确定性 4 KiB 逻辑 payload 检查逐字节一致性、长度和发送/接收 SHA-256。message Profile
按 max_record 分段，真正使用声明的 seqpacket-fd 或 UDP record 边界；stream 使用 TCP
边界。failure/recovery 在 workload-ready 后施加 latency-only baseline、退化和恢复阶段，
用 12 次有界 probe 跨越三个阶段，以便 best-effort datagram 仍可验证 exact echo。RTT 不含
单独记录的 pacing；不声称验证了丢包恢复、reconnect 或 migration。

### 模拟网络和抓包

```sh
python3 Test-Lab/shadow6_test_lab.py --list-scenarios
python3 Test-Lab/shadow6_test_lab.py --fetch-artifacts --all-cores \
  --scenario clean --scenario good-wan --scenario high-jitter \
  --scenario failure-recovery --capture
python3 Test-Lab/fingerprint_cli.py capture.pcap --run-id RUN_ID \
  --core go --profile go-kcp --link-type native --scenario good-wan \
  --output flow.json
```

runner 会在 PATH 和标准 sbin 目录检测 `ip`/`tc`，并检查 `CAP_NET_ADMIN`、`CAP_SYS_ADMIN`
和抓包所需的 `CAP_NET_RAW`。clean 抓包不依赖 tc；需要时由操作者显式使用 sudo。
进入 namespace 后，worker 降权为 checkout owner。dummy 地址和路由只存在于该隔离
namespace，不连接主机 uplink。模拟 WAN 在隔离 network namespace 的
loopback 上使用 `tc netem`。单一 loopback qdisc 无法区分两个端点方向，因此会将双向参数
合成为保守的对称 impairment。`NamespacePair` 已有 veth/netns helper，但当前矩阵 runner
尚未把 Core trio 接到这一端点分离网络。报告明确标为 **simulated**，不能当作真实公网
WAN。缺少 namespace 能力的项目记为带具体原因的 `BLOCKED`；PCAP 请求不会退回抓取主机网卡。

若系统有 `tcpdump`，runner 会抓包，并把 interface、namespace、时间、run/Core/Profile 与
scenario 写入 sidecar metadata；每份 PCAP 上限 4 MiB。`tshark`、Zeek 与 nDPI 都是可选观察器，
缺失时明确报告。未识别的协议保留为 `unknown/custom`。泄漏扫描器可对禁止明文 fixture
报告摘要，但不会把 fixture 内容回显。CI Test Lab artifact 不含私钥、bearer token 或 native
配置。

fingerprint schema 为 `shadow6.wan-pcap-fingerprint.v1`，输出 flow tuple、包/字节数、长度分布、
方向、时间间隔/burst、保守握手观察和 leak scan 状态。不从 IP/端口不同推断协议，也不推断
DPI resistance、隐蔽性、安全缺陷或协议身份。

### CI 平台/架构总包

所有产物 job 汇合后，`Platform/architecture artifact bundle` 会下载同一 run 的 `shadow6-*`
artifacts 并上传 `shadow6-artifacts-all`。总 ZIP 按
`platforms/<platform>/<architecture>/` 分目录，每目录含 `artifacts.tar.gz`、自己的 `manifest.json`、
`README.md`、`install.sh`、`install.ps1` 和共享的有界安装 helper。单独提取的目录也能校验
run/commit、payload digest 与逐文件 SHA。若有完整 Linux x86_64 release tar，会
调用现有免编译预编译安装器；Android 目录通过 `adb install -r` 安装到已连接且已授权设备。
仅组件目录会暂存到当前用户目录，不会启服务、装系统包或改防火墙/路由。`manifest.json`
绑定工作流 run、源 commit 和各文件 hash；`SHA256SUMS` 校验外层总 ZIP。

Linux `native-test-lab` job 会下载同一 run 的 Linux release artifact，以有界正确性、模拟 WAN、
PCAP 与 fingerprint 对所有注册 Native Profile 测试，不重新编译 Core。环境能力问题作为
`BLOCKED` 上传；`BLOCKED` 和 Core/Profile `FAIL` 都会令该 job 失败。请求的 PCAP 缺失
不能让 scenario PASS。普通 PR 不依赖公网 VPS。

### S6EPE、真实 WAN 和 Android 边界

Test Lab 目前复用 `Control-Center/privacy_envelope.py` 的 compatibility 源码，生成合法的
S6EPE Core/Profile/Carrier 行；四 Carrier raw/TLS 1.3/SCTP/WebRTC 的真实 endpoint PCAP 与
baseline 可区分性实验尚未接入。当前 compatibility matrix 代表源码组合声明，不是运行实证。
`standard-tls13` 不代表与浏览器 TLS 无法区分；`standard-webrtc-datachannel` 不代表浏览器
无法区分、anti-DPI 或 censorship resistance。

SSH/VPS 远程编排、远程抓包、NAT observation、按 capture/run 分组的数据集 split Detector
实验也尚未接入。不要把凭据放进命令行或提交到仓库。未来真实 WAN 必须显式启用，并标记
操作员提供的 endpoint/region/network-kind；netns 模拟不能替代这些实测。

Android APK 的 13 个 Profile 描述符由 `Crosed/native_profiles.py` 直接生成。界面显示全部
十二 Core，并把当前 APK 实际打包且存在 controller 的四个 Core 标为可运行。在 Client Profile
按下 **Connect Core** 后，应用等待 Core 输出结构化 `shadow6.ready`。**运行 4 KiB 应用回显正确性
探测**会经本机 Client ApplicationBoundary 发送有界数据，核验回显字节与 SHA-256；请先把远端
Agent target 配置为受控 echo service。复制的 Android Test Lab JSON 会记录 Profile、transport、
boundary、readiness 与能力限制，不包含配置秘密。设备侧 PCAP、桌面 supervisor、S6EPE、S6SG1
和桌面 LLM Lifecycle 明确为 `unavailable`；Android 不增加统一平台 ABI，也不内嵌 Python
Control Center。
