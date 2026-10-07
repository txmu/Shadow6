# Shadow6 project history update

## 2026-10-06: artifact-backed WAN/PCAP lab, Android Profile catalog, CI bundle

The repository now contains a `Test-Lab/` entry point driven by the existing
Crosed Native Profile Registry and the real `integration/stack_test.py`
three-role echo workload. Artifact manifests bind source commit, Profile
contract digest, executable mode and each Core binary SHA-256. The shared
runner writes versioned JSON and Markdown with PCAP metadata, flow
fingerprints, bounded simulated network scenarios, and fixture tests. GitHub
Actions run `37425155442` at commit
`9b7cced4ca474982555964a95d63cd4dbe08bed3` supplied the prebuilt binaries used
for local verification; no Core was rebuilt for the matrix. The Linux
producer writes the manifest and a downstream job consumes its same-run
artifact. Public WAN access is not a PR prerequisite. The current impairment
runner uses isolated netns loopback, so directional settings become a
conservative symmetric qdisc bound; the veth pair helper is not yet connected
to the complete matrix.

The Android build generates its Profile catalog from
`Crosed/native_profiles.py`. The UI lists all twelve Cores and registered
Profiles, distinguishes packaged artifacts from runnable Android bindings,
waits for a structured Core listener event, and offers a bounded 4 KiB Client
application echo check. Runtime output keeps the canonical Deployment
`RuntimeObservation` field set; a process is not marked application-ready until
the payload echo is correct. Its copied diagnostic JSON excludes configuration
secrets. The app does not introduce a platform ABI or embed the Python
Control Center.

Once platform producer jobs finish, CI groups same-run artifacts by target
platform and architecture and publishes `shadow6-artifacts-all`. Each group
is independently verifiable and contains its payload, local manifest,
installation notes, shell/PowerShell helper and shared installer. The bundle
root also carries the combined provenance manifest and SHA-256 sidecar. Linux
x86_64 uses the existing prebuilt installer when a complete release is
present; Android uses adb; component-only targets are staged under the current
user's directory without activating services. The job waits for the platform
summary, which depends on all artifact-producing platform jobs.

This is an implementation record, not a claim that the entire requested
acceptance suite passed. The current Test Lab does not yet run S6EPE four
carrier PCAP endpoint tests, remote SSH/VPS orchestration/capture, a complete
veth-separated endpoint matrix, Android device PCAP, or capture-group-safe
Detector experiments. With the downloaded Actions binaries, all 12 primary
Native Profiles and all 13 registered Profiles passed clean local correctness
smoke. The same host lacks `CAP_NET_ADMIN` and `tc`, so requested netem cases
were `BLOCKED` and all 52 requested PCAP rows were `SKIP`; these are not WAN or
PCAP passes. S6EPE's existing Python tests reported 39 passed and one optional
WebRTC observer test skipped because its development headers are unavailable;
the Control Center envelope tests reported 10 passed. Four-carrier PCAP
evidence remains outstanding. The combined platform-bundle workflow has not
yet run on this revision, and remote WAN orchestration remains outstanding.

For the detailed bilingual operator guide, see
[`wan-pcap-test-lab.md`](wan-pcap-test-lab.md). The longer historical account
is currently maintained in Chinese at [`project-history.zh-CN.md`](project-history.zh-CN.md).

## 2026-10-07: canonical configuration and application handle lifecycle

This change extends the existing Control Center/Deployment/Named Service
authority: typed native forms, recursive secret-safe review/diff, managed
content-addressed materials, reviewed plan/apply/relock and explicit removal/
reclamation. It adds no arbitrary file editor, shell or parallel deployment
architecture. SCM_RIGHTS FD handoff, Python fallback, bounded cancellation/
timeout cleanup, credited S6NA sockets and explicit same-policy PeerConnection
fallback/reconnect are integrated. macOS has a Unix stream transfer backend;
Windows uses actual WSADuplicateSocket with same-user token, credential, nonce
and expiry checks. Linux pidfd supervision is still platform-specific.

Portable JSON ingestion now delegates to the existing bounded parser, with
native/Node reader hardening and dependency-free NFC tables generated from
one Unicode database. Latest Actions run 37596070786 supplied successful native
producer artifacts. Its peer.py install omission, sudo Python dependency,
capture ownership and application-sdk bundle mapping failures were fixed.

Local verification includes Deployment 150, SDK/FD/Peer/config 43, Control
Center 67, Security 24, Infrastructure 3 and native Unicode/parser 3 checks,
plus the related component/CLI/Detector/Tools/Node suites. Real Go/KCP Web HTTP
configuration lifecycle and Python/C transfer passed; the real Test Lab worker
verified C-ABI/SCM_RIGHTS, exact echo, 60Hz updates/control records and cleanup.
Offline source audit: 7 passed, 0 failed, 1 explicitly skipped binary stage;
shellcheck passed. No twelve-Core local rebuild or new release archives ran.
Earlier failed attempts are retained separately and are not counted as PASS.

CI now requires Chromium typed-form/save/apply execution, three-platform kernel
handle tests and the same-run application SDK in all native/legal S6EPE worker
paths. Chromium, non-Linux kernels and the full WAN/netns/PCAP matrix remain
unverified locally; this commit requires a new CI run before claiming those
stages passed. No seamless migration, SDK ICE or portable supervisor is claimed.
