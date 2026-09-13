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
assert "candidate > previous" in PROTO

if "--binary" in sys.argv:
    p = subprocess.run([str(ROOT / "shadow6-pony"), "--feature-report"], check=True, capture_output=True, text=True)
    report = json.loads(p.stdout)
    assert report["core"] == "shadow6-pony" and report["crosed_max_level"] == 0
    assert report["crosed_capabilities"] == [] and not report["crosed_compiled"]
print("Core-Pony contract tests passed")
