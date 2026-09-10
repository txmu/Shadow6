#!/usr/bin/env python3
import json, os, pathlib, stat, subprocess, sys, tempfile

binary = pathlib.Path(sys.argv[1]).resolve()

def run(*args):
    return subprocess.run([binary, *args], text=True, capture_output=True, timeout=10)

report = run("--feature-report")
assert report.returncode == 0, report.stderr
value = json.loads(report.stdout)
assert value["core"] == "shadow6-gleam" and value["transport"] == "micro-mux"

keys = run("--gen-key")
assert keys.returncode == 0 and "Private Key (Hex):" in keys.stdout
denied = run("--crosed-request", "/nonexistent/request", "--crosed-trust", "/nonexistent/trust")
assert denied.returncode == 0 and json.loads(denied.stdout)["status"] == "denied"

with tempfile.TemporaryDirectory(prefix="shadow6-gleam-test.") as directory:
    root = pathlib.Path(directory)
    config = root / "config.json"
    config.write_text(json.dumps({"role":"broker","broker":{"listen_addr":"127.0.0.1:4433",
      "private_key":"00"*32,"agents":[],"clients":[],"webhook_url":"","stealth_mode":False},
      "agent":None,"client":None}))
    config.chmod(0o600)
    valid = run("--config", str(config), "--check-config")
    assert valid.returncode == 0, valid.stderr
    config.write_text(config.read_text().replace('"role": "broker"', '"role": "broker", "extra": 1.5'))
    invalid = run("--config", str(config), "--check-config")
    assert invalid.returncode != 0
    link = root / "link.json"
    link.symlink_to(config)
    assert run("--config", str(link), "--check-config").returncode != 0

mode = stat.S_IMODE(binary.stat().st_mode)
assert mode & 0o022 == 0
print("Core-Gleam contract tests passed")
