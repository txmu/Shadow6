# Shadow6 Android

This is a native Android 16 / API 36 Jetpack Compose application using Material
3 components, accessible touch targets, light/dark palettes, and five-item
bottom navigation. English is the default locale and every string resource has a
Simplified Chinese translation.

The default build includes both alternative complete Core engines plus
ShadowChat, search, signed-package/version views, an independently implemented
built-in Android game, external
OpenAI-compatible Responses API chat, and fixed read-only tool integration.
Users configure Broker, Agent, or Client; select Go or Rust; and choose Root or
non-Root mode at runtime. Non-Root mode runs the selected Core inside the app
sandbox; features that genuinely
need raw packets, namespaces, or privileged ports are exposed only in Root mode.
For the Client role, the app parses the authenticated Core's loopback proxy
endpoint, displays it live, and provides a direct button to open it in the
system browser; Termux is not required.

Build modules can be excluded with Gradle properties such as
`-Pshadow6.includeGames=false`; both cores default to true. Cross-build native
cores first with `build_android_cores.py --ndk /absolute/path/to/ndk`, then use
Android Studio or a compatible JDK 17/Gradle installation to build the APK.
The repository intentionally does not include downloaded SDKs, NDKs, Gradle
caches, signing keys, or prebuilt binaries for the wrong ABI.

External AI accepts only credential-free HTTPS base URLs, stores the API key
with Android Keystore AES-GCM, bounds requests/responses and tool-call rounds,
maintains Responses API context, and exposes four fixed read-only Android tools.
An optional remote Control Center MCP endpoint always requires approval; Android
never automatically approves remote actions.

## Minimum build environment and disk budget

The smallest practical headless setup is JDK 17, Android SDK command-line
tools, Platform 36, Build Tools 36, one side-by-side NDK, Gradle/AGP's resolved
dependency cache, Go, Rust, and the Rust Android targets. CMake and LLDB are not
needed by this project's current core cross-build script. `platform-tools` is
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
