import hashlib, json, os, subprocess, sys, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path("/home/admin/Shadow6")
TMP  = Path(os.environ["PROBE_DIR"]); TMP.mkdir(parents=True, exist_ok=True)

def write0600(p, data: bytes):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try: os.write(fd, data)
    finally: os.close(fd)

def manual_sign(req, key):
    pb = json.dumps(req["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    msg = "\n".join([str(req["version"]), req["mod_id"], req["nonce"], str(req["issued_at"]),
                     str(req["requested_level"]), ",".join(sorted(req["capabilities"])),
                     hashlib.sha256(pb).hexdigest(), req["source_domain"], req["target_domain"]]).encode()
    return key.sign(msg).hex()

def build(payload):
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    req = {"version": 1, "mod_id": "probe-mod", "nonce": os.urandom(16).hex(),
           "issued_at": int(time.time()), "requested_level": 1,
           "capabilities": ["observe.version"], "source_domain": "", "target_domain": "",
           "payload": payload}
    req["signature"] = manual_sign(req, key)
    return json.dumps({"mods": {"probe-mod": {"pubkey": pub, "max_level": 1,
            "capabilities": ["observe.version"], "allowed_domains": []}}},
            sort_keys=True, separators=(",", ":")).encode(), \
           json.dumps(req, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def run(core, trust, request):
    tp, rp = TMP/"trust.json", TMP/"request.json"
    write0600(tp, trust); write0600(rp, request)
    r = subprocess.run([str(core), "--crosed-request", str(rp), "--crosed-trust", str(tp)],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return f"REJECTED(rc={r.returncode}) {r.stderr.strip()[:110]}"
    d = json.loads(r.stdout)
    return f"{d['status'].upper()} level={d['granted_level']} caps={d['granted_capabilities']}"

CORES = {"go": ROOT/"Core-Go/shadow6-go-crosed", "rust": ROOT/"Core-Rust/shadow6-rust-crosed"}
CASES = [
    ("control: integer payload",        {"n": 1}),
    ("float in signed payload",         {"ratio": 1.5}),
    ("high-precision float fingerprint",{"ratio": 0.30000000000000004}),
    ("float nested in array",           {"xs": [1.0]}),
    ("integer above 2^53",              {"big": 9007199254740993}),
    ("oversized integer",               {"big": 10**40}),
]
for label, payload in CASES:
    trust, request = build(payload)
    print(f"\n[{label}]  payload={json.dumps(payload)}")
    for name, core in CORES.items():
        print(f"   {name:5s} -> {run(core, trust, request)}")
