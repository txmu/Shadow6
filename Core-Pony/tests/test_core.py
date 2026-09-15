import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SRC = (ROOT / "main.pony").read_text()
assert "NetAuth" in SRC and "FileAuth" in SRC
assert "--check-config" in SRC and "--feature-report" in SRC
SESSION = (ROOT / "session.pony").read_text()
assert "class val OCapToken" in SESSION and "iso" in SESSION
PROTO = (ROOT / "protocol.pony").read_text()
assert "HandshakeTranscript" in PROTO and "ReplayWindow" in PROTO
assert "class val PluginRequest" in PROTO and "PluginLimits" in PROTO
assert "class ref PluginTable" in PROTO
assert "candidate > previous" in PROTO
assert "accept_receive" in PROTO and "_received" in PROTO
assert "sample_rtt" in PROTO and "rto()" in PROTO
assert "_sent" in PROTO and "max_pending" in PROTO
CROSED = (ROOT / "crosed.pony").read_text()
assert "class val CrosedGrant" in CROSED
assert "signed and (build_level == 5)" in CROSED
assert "level(grant.capability) <= grant.request_level" in CROSED
RUNTIME = (ROOT / "runtime.pony").read_text()
assert "kind == 3" in RUNTIME and "_last_wire" in RUNTIME and "_last_sent" in RUNTIME
assert "token.seal(consume ack, sequence, 3)" in RUNTIME
PLUGIN = (ROOT / "plugin_rpc.pony").read_text()
assert "StartProcess" in PLUGIN and "PluginRPCNotify" in PLUGIN
assert "Plugin-System/shadow6_plugins.py" in PLUGIN
CONFIG = (ROOT / "config.pony").read_text()
assert "broker: Bool" in CONFIG and "role > 2" in CONFIG
assert "allow_external" in CONFIG and "peer_host" in CONFIG

if "--binary" in sys.argv:
    p = subprocess.run([str(ROOT / "shadow6-pony"), "--feature-report"], check=True, capture_output=True, text=True)
    report = json.loads(p.stdout)
    assert report["core"] == "shadow6-pony" and report["crosed_max_level"] == 0
    assert report["crosed_capabilities"] == [] and not report["crosed_compiled"]
    assert report["transport"] == "udp"
print("Core-Pony contract tests passed")
