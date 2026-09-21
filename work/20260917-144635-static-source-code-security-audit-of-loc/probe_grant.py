import hashlib, json, os, subprocess, time, tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT = Path("/home/admin/Shadow6")

def w(p, b):
    fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)
    try: os.write(fd, b)
    finally: os.close(fd)

def sign(req, key):
    pb = json.dumps(req["payload"], sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()
    m = "\n".join([str(req["version"]), req["mod_id"], req["nonce"], str(req["issued_at"]),
                   str(req["requested_level"]), ",".join(sorted(req["capabilities"])),
                   hashlib.sha256(pb).hexdigest(), req["source_domain"], req["target_domain"]]).encode()
    return key.sign(m).hex()

d = Path(tempfile.mkdtemp(prefix="grant-probe-", dir="/tmp"))
key = Ed25519PrivateKey.generate()
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
# Mod policy: max_level 5, but ONLY grants observe.version
trust = {"mods": {"probe-mod": {"pubkey": pub, "max_level": 5,
         "capabilities": ["observe.version"], "allowed_domains": []}}}
tp = d/"trust.json"; w(tp, json.dumps(trust, sort_keys=True, separators=(",",":")).encode())

def mk(level, caps):
    r = {"version":1,"mod_id":"probe-mod","nonce":os.urandom(16).hex(),"issued_at":int(time.time()),
         "requested_level":level,"capabilities":caps,"source_domain":"","target_domain":"",
         "payload":{"k":"v"}}
    r["signature"] = sign(r, key); return r

def run(core, req, label):
    rp = d/"request.json"
    w(rp, json.dumps(req, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode())
    r = subprocess.run([str(ROOT/core),"--crosed-request",str(rp),"--crosed-trust",str(tp)],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0: print(f"  {label:22s} {core:24s} REJECTED {r.stderr.strip()[:70]}"); return None
    o = json.loads(r.stdout)
    print(f"  {label:22s} {core:24s} status={o['status']:8s} level={o['granted_level']} caps={o['granted_capabilities']} reason={o.get('reason','')[:40]}")
    return o

CORES = ["Core-Go/shadow6-go-crosed", "Core-Rust/shadow6-rust-crosed"]
print("\n[A] level 5 requested with EMPTY capability list (policy grants only observe.version)")
for c in CORES: run(c, mk(5, []), "no-capabilities")

print("\n[B] level 5 requested, capability actually allowed (control)")
for c in CORES: run(c, mk(5, ["observe.version"]), "allowed-cap")

print("\n[C] capability NOT in Mod policy at requested level")
for c in CORES: run(c, mk(5, ["core.hook"]), "unauthorized-cap")

print("\n[D] replay: IDENTICAL signed request submitted twice")
req = mk(1, ["observe.version"])
for c in CORES:
    run(c, req, "replay#1"); run(c, req, "replay#2")
