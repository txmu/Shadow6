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
