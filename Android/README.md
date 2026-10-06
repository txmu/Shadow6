# Shadow6 Android

This is a native Android 16 / API 36 Jetpack Compose application using Material
3 components, accessible touch targets, light/dark palettes, and adaptive
five-item navigation: bottom tabs on compact screens and a labelled rail on
wide screens. Content is centered and capped for wide displays. English is the default locale and every string resource has a
Simplified Chinese translation.

The default build includes multiple independently implemented Core engines plus
ShadowChat, search, signed-package/version views, an independently implemented
built-in Android game, external
OpenAI-compatible Responses API chat, and fixed read-only tool integration.
Users configure Broker, Agent, or Client and select a packaged Core. The Core
runs inside the app sandbox; the Android application does not expose a Root
mode or features that require raw packets, namespaces, or privileged ports.
For the Client role, the app parses the authenticated Core's loopback proxy
endpoint, displays it live, and provides a direct button to open it in the
system browser; Termux is not required.

The Settings screen accepts a 40-character Public6 join code. IPv4 codes fetch
a bounded profile over system-verified HTTPS to the encoded IP and port;
directory codes use an operator-configured HTTPS directory; manual codes need
a profile plus a separately verified full Gate public key. The code is an
individual client credential stored with Android Keystore protection, never a
shared Broker private key. After import, a compatible Client or Agent can
select **Use saved public node**. The app starts Gate with the profile's fixed
authenticated port, a bounded loopback Virtual Peer, then the selected native
Core. The Broker and Agent must already authorize the Core identity. Ed25519
native Client/Agent identities are derived separately from the code, so the
operator can preauthorize their public keys without sharing server secrets.
Ed25519
admission signing needs a platform provider (standard on Android 13+); older
systems without one reject activation. APK Core availability still depends on
the selected build and ABI.

Build modules can be excluded with Gradle properties such as
`-Pshadow6.includeGames=false`; both cores default to true. Cross-build native
cores first with `build_android_cores.py --ndk /absolute/path/to/ndk`, then use
Android Studio or a compatible JDK 17/Gradle installation to build the APK.
The repository intentionally does not include downloaded SDKs, NDKs, Gradle
caches, signing keys, or prebuilt binaries for the wrong ABI.

Core-D is enabled by default in the Android UI. Its OpenSSL and libsodium
dependencies must be built for each Android ABI; host development packages
cannot be used. CI provisions pinned OpenSSL 3.5.8 and libsodium 1.0.20 sources.
For local builds, supply existing, unconfigured source trees (libsodium needs
its generated `configure` script), then run:

```sh
.venv/bin/python Android/build_android_crypto.py --ndk "$ANDROID_NDK" \
  --openssl-source /absolute/path/to/openssl \
  --sodium-source /absolute/path/to/libsodium --output .tmp/android-crypto
.venv/bin/python Android/build_android_cores.py --ndk "$ANDROID_NDK" --core-d-only
```

The crypto builder performs no downloads. `--core-d-only` verifies D separately;
omit it to build all cores. `--crypto-prefix` selects a different dependency
output directory. Both builders accept `--abi` for one architecture and respect
`SHADOW6_ANDROID_BUILD_JOBS`. Core-D is a PIE executable packaged as
`libshadow6_d.so` and launched by the existing process-based runtime, with crypto
archives linked statically. Device execution and Android certificate trust
store behavior still require device testing.

Core-Nim also needs libdatachannel, libjuice and usrsctp for each Android ABI.
CI provisions libdatachannel commit `9e6a13abbb6846c003d817d0387b6706466e2b03`
and its pinned submodules before building the cores. Locally, use an existing
checkout with initialized submodules after building crypto:

```sh
.venv/bin/python Android/build_android_rtc.py --ndk "$ANDROID_NDK" \
  --source /absolute/path/to/libdatachannel
.venv/bin/python Android/build_android_cores.py --ndk "$ANDROID_NDK"
```

The RTC builder uses CMake and performs no downloads. WebRTC data channels and
WebSockets are enabled; unused audio/video media support is disabled. It installs
static libraries under `.tmp/android-rtc/<abi>`; `--rtc-prefix` selects another
root in the core builder. Nim uses the ABI-specific NDK clang for C compilation
and clang++ for linking with static libc++, producing a PIE executable named
`libshadow6_nim.so` for the existing Android UI/runtime.

External AI accepts only credential-free HTTPS base URLs, stores the API key
with Android Keystore AES-GCM, bounds requests/responses and tool-call rounds,
maintains Responses API context, and exposes four fixed read-only Android tools.
An optional remote Control Center MCP endpoint always requires approval; Android
never automatically approves remote actions.

## Minimum build environment and disk budget

The smallest practical headless setup is JDK 17, Android SDK command-line
tools, Platform 36, Build Tools 36, one side-by-side NDK, Gradle/AGP's resolved
dependency cache, Go, Rust, LDC, Nim, CMake, and the Rust Android targets.
LLDB is not needed. `platform-tools` is
optional when only producing an APK and required for installing/testing it on
a physical device. No emulator is required.

On the current development host the repository uses about 6.1 GiB (including a
4.4 GiB Rust target tree and 1.3 GiB Python environment), the Android sources
use about 116 KiB, and the filesystem has about 11 GiB free. Budget roughly
5–8 GiB for a headless SDK + one NDK + Gradle/Maven caches and native outputs,
so a command-line physical-device workflow should fit with 3–6 GiB remaining.
Android Studio plus an emulator is not a good fit for this disk: an AVD alone
can require up to 6 GiB. Keep SDK/NDK versions single and avoid emulator images
on this host.

The pinned tool contract for AGP 9.2.0 is JDK 17, Gradle 9.4.1, Build Tools
36.0.0, and NDK 28.2.13676358. `sdk-packages.txt` can be passed to
`sdkmanager --package_file=...` after the operator has installed command-line
tools and accepted the Android licenses. Rust additionally needs the
`aarch64-linux-android` and/or `x86_64-linux-android` standard-library targets.

Headless builds deliberately default to one Go/Rust/Gradle worker and a bounded
Gradle JVM, expose only two processors to JVM-internal pools, use the low-
overhead serial collector, and run the Kotlin compiler in-process.  This keeps a 2 GiB remote
host responsive; it trades build speed for a predictable failure instead of a
host-wide OOM.  `make android-apk` also refuses to start below its minimum
available-memory or disk thresholds.  Larger hosts may explicitly set
`SHADOW6_ANDROID_BUILD_JOBS` (maximum 16) for the native-core phase, but the
Gradle phase remains single-worker because this application has only one module.

## S6NA VPN adapter

The APK includes an optional, non-exported `VpnService` and a wire-compatible
S6NA data-frame codec. Android creates the TUN descriptor only after the normal
system VPN consent flow; it does not require root, Termux, route commands or a
second VPN application. The session key, peer and side are fixed when the
service starts and cannot be hot-reconfigured. Stopping and explicitly
starting a new session is required for every configuration change.

The Android service is still an optional companion: every bundled Core keeps
its native data path. The app shows the selected shared Native Profile ID and
transport beside Core status, exposes textual running/stopped state for assistive
technology, and reports authenticated S6NA packet and payload-byte counters for
both directions while the tunnel runs. The VPN carrier authenticates packets before writing
them to the Android TUN descriptor, pins one UDP peer, and applies a 1400-byte
MTU. It remains a single-peer IP tunnel; the counters describe accepted tunnel
payload packets, not proof of peer reachability. Android's supported Core set
is still Go, Rust, D, and Nim. The cross-platform read-only Control Center
dashboard is available on systems that run its local Python service; it is not
embedded in the Android APK.

## Android Native Profile and Test Lab observations

At build time, `app/build.gradle.kts` runs `Android/export_native_profiles.py`;
that exporter reads the authoritative `Crosed/native_profiles.py` registry and
embeds all current Profile descriptors. The app inventory shows each of the
twelve Cores and every registered Profile with `RUNNABLE`, `ARTIFACT-UNBOUND`,
or `NOT-PACKAGED` state for the installed APK/ABI. The four current Android
Core engines are Go/KCP, Rust/QUIC, D/secure-stream, and Nim/WebRTC.

For a Client Profile, the action is **Connect Core**. Android waits for the
Core's structured `shadow6.ready` event instead of treating a live process as
ready. Once the local ApplicationBoundary listener is reported, **Run 4 KiB
application echo correctness probe** sends deterministic bounded bytes through
that endpoint and checks the full echo and SHA-256. Configure the remote
Agent's target port to a controlled echo service first. The probe reports
application readiness only after the data check passes. The JSON copied by
**Copy redacted runtime/Test Lab observation JSON** contains the Profile,
transport, boundary, lifecycle/readiness and explicit capability limits; it
does not include configuration or credentials.

The Android app sandbox does not capture device PCAP. Capture on a host you
control using the [WAN / PCAP Test Lab guide](../docs/wan-pcap-test-lab.md), and
label source/destination captures as remote evidence. Android supervisor,
S6EPE, S6SG1, desktop LLM Lifecycle and device-side PCAP are reported as
unavailable; they are not emulated through a shared ABI or a Python control
service.

### Android Test Lab（中文）

构建 APK 时，`app/build.gradle.kts` 调用 `Android/export_native_profiles.py`，直接从权威
`Crosed/native_profiles.py` 导出所有 Profile 描述符。应用能力清单显示全部十二 Core 和全部
已注册 Profile，并针对当前 APK/ABI 标记 `RUNNABLE`、`ARTIFACT-UNBOUND` 或 `NOT-PACKAGED`。
当前 Android 可运行 Core 为 Go/KCP、Rust/QUIC、D/secure-stream 和 Nim/WebRTC。

选择 Client Profile 后，按钮为 **Connect Core**。Android 等待 Core 输出结构化
`shadow6.ready` event；进程仍存活不会被误报成已就绪。出现本机 ApplicationBoundary listener
后，可运行 **Run 4 KiB application echo correctness probe**，它经由本机 endpoint 发送确定性
有界数据并验证完整回显和 SHA-256。请先把远端 Agent target port 配置成受控 echo service。
只有数据校验通过后才报告 application-ready。**Copy redacted runtime/Test Lab observation
JSON** 会复制 Profile、transport、boundary、生命周期/就绪状态及明确的能力限制，不含配置和凭据。

Android app sandbox 无法抓取设备 PCAP。请通过[WAN / PCAP Test Lab 指南](../docs/wan-pcap-test-lab.md)
在自己控制的主机抓包，并把源端/目的端捕获标为远端证据。Android supervisor、S6EPE、S6SG1、
桌面 LLM Lifecycle 与设备内 PCAP 都明确显示 unavailable；应用不会通过统一 ABI 或 Python 控制服务伪造这些能力。
