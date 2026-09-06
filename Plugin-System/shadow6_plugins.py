#!/usr/bin/env python3
"""Signed, capability-scoped plugin runner for Shadow6.

Plugins communicate over one-request/one-response JSON on stdin/stdout.  The
runner verifies their manifest, code digest and Ed25519 signer before starting
a resource-bounded child process.  Host capabilities remain deny-by-default.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import resource
import signal
import stat
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCRIPT_PATH = Path(__file__).resolve()
PROJECT_ROOT = SCRIPT_PATH.parents[1]
if (PROJECT_ROOT / "plugins").is_dir():
    DEFAULT_PLUGIN_ROOT = PROJECT_ROOT / "plugins"
    DEFAULT_TRUST_STORE = SCRIPT_PATH.with_name("trusted_signers.json")
else:
    INSTALL_PREFIX = SCRIPT_PATH.parent.parent
    DEFAULT_PLUGIN_ROOT = INSTALL_PREFIX / "share" / "shadow6" / "plugins"
    DEFAULT_TRUST_STORE = INSTALL_PREFIX / "share" / "shadow6" / "trusted_signers.json"
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$")
KNOWN_CAPABILITIES = frozenset(
    {
        "game.local",
        "hook.mtd.before",
        "hook.mtd.after",
        "rpc.target.authorize",
        "telemetry.read",
        "slot.lifecycle.before-start", "slot.lifecycle.after-stop", "slot.config.validate",
        "slot.transport.observe", "slot.transport.transform", "slot.protocol.factory",
        "slot.chat.filter", "slot.identity.verify", "slot.security.policy",
        "slot.telemetry.sink", "slot.assistant.eye", "slot.assistant.hand",
        "slot.init.decorate", "slot.ui.panel",
    }
)


class PluginError(RuntimeError):
    """A plugin failed validation or execution."""


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    entrypoint: Path
    capabilities: frozenset[str]
    hooks: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    signer: str
    code: bytes


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PluginError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, limit: int = 1024 * 1024) -> dict[str, Any]:
    if len(data) > limit:
        raise PluginError("JSON document exceeds size limit")
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        reject_number = lambda _: (_ for _ in ()).throw(PluginError("floats/nonfinite numbers are forbidden"))
        value = json.loads(text, object_pairs_hook=_reject_duplicate, parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PluginError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PluginError("JSON document must be an object")
    canonical(value)
    return value


def canonical(value: Any) -> bytes:
    budget = 0
    def check(item: Any, depth: int = 0) -> None:
        nonlocal budget
        budget += 1
        if budget > 1_048_576:
            raise PluginError("JSON document exceeds size limit")
        if depth > 32 or isinstance(item, float):
            raise PluginError("manifest nesting is excessive or contains a float")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 256:
                    raise PluginError("invalid manifest key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise PluginError("invalid Unicode scalar") from exc
            if size > 65_536 or "\x00" in item:
                raise PluginError("JSON string exceeds safety or size limit")
            budget += size
        elif type(item) is int and abs(item) > 9_007_199_254_740_991:
            raise PluginError("integer is not exactly portable")
        elif not isinstance(item, (int, bool, type(None))):
            raise PluginError("unsupported manifest value")
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(encoded) > 1_048_576:
        raise PluginError("JSON document exceeds size limit")
    return encoded


def secure_read(path: Path, limit: int, *, secret: bool = False, dir_fd: int | None = None) -> bytes:
    """Validate the opened inode, not merely the pathname checked earlier."""
    def check(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise PluginError("file must be bounded and regular")
        if info.st_uid not in ({os.geteuid()} if secret else {0, os.geteuid()}) or info.st_mode & 0o022:
            raise PluginError("file must be owner-controlled and not group/other writable")
        if secret and stat.S_IMODE(info.st_mode) != 0o600:
            raise PluginError("private key must have mode 0600")
    before = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    check(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        check(opened)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PluginError("file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        check(after)
        if len(data) > limit or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise PluginError("file grew or changed during read")
        return data
    finally:
        os.close(descriptor)



def _regular_owner_file(path: Path) -> os.stat_result:
    before = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise PluginError(f"plugin path must be a regular non-symlink file: {path}")
    if before.st_uid != os.geteuid():
        raise PluginError(f"plugin file is not owned by the effective user: {path}")
    if before.st_mode & 0o022:
        raise PluginError(f"plugin file must not be group/other writable: {path}")
    return before


def _read_bounded(path: Path, limit: int) -> bytes:
    return secure_read(path, limit)


def _signed_payload(document: dict[str, Any]) -> bytes:
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical(unsigned)


def _load_trust_store(path: Path) -> dict[str, bytes]:
    document = strict_json(_read_bounded(path, 65_536), 65_536)
    signers = document.get("signers")
    if set(document) != {"signers"} or not isinstance(signers, dict) or not 1 <= len(signers) <= 256:
        raise PluginError("trust store must contain at least one signer")
    result = {}
    for name, public_hex in signers.items():
        if not isinstance(name, str) or not ID_RE.fullmatch(name):
            raise PluginError("trust store contains an invalid signer name")
        try:
            if not isinstance(public_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", public_hex):
                raise ValueError("invalid key encoding")
            public_key = bytes.fromhex(public_hex)
        except (TypeError, ValueError) as exc:
            raise PluginError(f"invalid public key for signer {name}") from exc
        if len(public_key) != 32:
            raise PluginError(f"invalid Ed25519 public key length for signer {name}")
        result[name] = public_key
    return result


class PluginRegistry:
    def __init__(
        self,
        plugin_root: Path = DEFAULT_PLUGIN_ROOT,
        trust_store: Path = DEFAULT_TRUST_STORE,
        granted_capabilities: frozenset[str] = KNOWN_CAPABILITIES,
    ) -> None:
        if plugin_root.is_symlink():
            raise PluginError("plugin root must not be a symlink")
        self.plugin_root = plugin_root.resolve(strict=True)
        metadata = self.plugin_root.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o002:
            raise PluginError("plugin root must be an owner-controlled directory")
        self.trusted_signers = _load_trust_store(trust_store)
        unknown = granted_capabilities - KNOWN_CAPABILITIES
        if unknown:
            raise PluginError(f"unknown granted capabilities: {sorted(unknown)}")
        self.granted_capabilities = granted_capabilities

    def discover(self) -> list[str]:
        plugins = []
        for child in sorted(self.plugin_root.iterdir()):
            if child.is_dir() and not child.is_symlink() and (child / "plugin.json").is_file():
                plugins.append(child.name)
        return plugins

    def load(self, plugin_id: str) -> PluginManifest:
        if not ID_RE.fullmatch(plugin_id):
            raise PluginError("invalid plugin id")
        unresolved_directory = self.plugin_root / plugin_id
        if unresolved_directory.is_symlink():
            raise PluginError("plugin directory must not be a symlink")
        directory = unresolved_directory.resolve(strict=True)
        if directory.parent != self.plugin_root:
            raise PluginError("plugin directory escapes the configured root")
        raw_manifest = _read_bounded(directory / "plugin.json", 65_536)
        try:
            document = strict_json(raw_manifest, 65_536)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginError("invalid plugin manifest JSON") from exc
        required = {
            "schema_version", "id", "name", "version", "runtime", "entrypoint",
            "capabilities", "hooks", "timeout_seconds", "max_output_bytes", "sha256",
            "signer", "signature",
        }
        if set(document) != required:
            raise PluginError(f"manifest fields differ from schema: {sorted(set(document) ^ required)}")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1 or document["runtime"] != "python3":
            raise PluginError("unsupported plugin schema or runtime")
        if document["id"] != plugin_id or not ID_RE.fullmatch(document["id"]):
            raise PluginError("manifest id does not match its directory")
        if not isinstance(document["name"], str) or not 1 <= len(document["name"]) <= 100:
            raise PluginError("invalid plugin display name")
        if not isinstance(document["version"], str) or not VERSION_RE.fullmatch(document["version"]):
            raise PluginError("invalid plugin version")
        entry_name = document["entrypoint"]
        if not isinstance(entry_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.py", entry_name):
            raise PluginError("entrypoint must be a local Python filename")
        entrypoint = directory / entry_name
        if entrypoint.parent != directory:
            raise PluginError("entrypoint escapes the plugin directory")
        code = _read_bounded(entrypoint, 1_048_576)
        if not isinstance(document["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", document["sha256"]):
            raise PluginError("invalid plugin code digest")
        if not hashlib.sha256(code).hexdigest() == document["sha256"]:
            raise PluginError("plugin code digest mismatch")
        capabilities = document["capabilities"]
        if not isinstance(capabilities, list) or len(capabilities) > 32 or any(
            not isinstance(item, str) or not CAPABILITY_RE.fullmatch(item) for item in capabilities
        ):
            raise PluginError("invalid capability list")
        capability_set = frozenset(capabilities)
        if len(capability_set) != len(capabilities):
            raise PluginError("duplicate plugin capability")
        if not capability_set <= KNOWN_CAPABILITIES:
            raise PluginError(f"unknown plugin capabilities: {sorted(capability_set - KNOWN_CAPABILITIES)}")
        if not capability_set <= self.granted_capabilities:
            raise PluginError(f"plugin capabilities were not granted: {sorted(capability_set - self.granted_capabilities)}")
        hooks = document["hooks"]
        if not isinstance(hooks, list) or len(hooks) > 32 or any(
            not isinstance(item, str) or not CAPABILITY_RE.fullmatch(item) for item in hooks
        ):
            raise PluginError("invalid hook list")
        if len(set(hooks)) != len(hooks) or not set(hooks) <= capability_set:
            raise PluginError("hooks must be unique and have matching signed capabilities")
        timeout = document["timeout_seconds"]
        output_limit = document["max_output_bytes"]
        if type(timeout) is not int or not 1 <= timeout <= 30:
            raise PluginError("plugin timeout must be between 1 and 30 seconds")
        if type(output_limit) is not int or not 1024 <= output_limit <= 1_048_576:
            raise PluginError("plugin output limit is out of range")
        signer = document["signer"]
        if not isinstance(signer, str) or not ID_RE.fullmatch(signer):
            raise PluginError("invalid signer")
        public_key = self.trusted_signers.get(signer)
        if public_key is None:
            raise PluginError(f"untrusted plugin signer: {signer}")
        try:
            if not isinstance(document["signature"], str) or not re.fullmatch(r"[0-9a-f]{128}", document["signature"]):
                raise ValueError("invalid signature encoding")
            signature = bytes.fromhex(document["signature"])
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, _signed_payload(document))
        except (TypeError, ValueError, InvalidSignature) as exc:
            raise PluginError("plugin manifest signature verification failed") from exc
        return PluginManifest(
            plugin_id=plugin_id,
            name=document["name"],
            version=document["version"],
            entrypoint=entrypoint,
            capabilities=capability_set,
            hooks=tuple(hooks),
            timeout_seconds=timeout,
            max_output_bytes=output_limit,
            signer=signer,
            code=code,
        )


def _child_limits() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    pr_set_no_new_privs = 38
    if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot enable no_new_privs")
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1_048_576, 1_048_576))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    # RLIMIT_NPROC counts all host processes mapped to this uid, including
    # service/sandbox helpers outside the visible process tree. 256 remains a
    # hard bound while leaving room for unshare to create its single helper.
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))


def run_plugin(manifest: PluginManifest, request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise PluginError("plugin request must be an object")
    encoded = canonical(request)
    if len(encoded) > 65_536:
        raise PluginError("plugin request exceeds 65536 bytes")
    with tempfile.TemporaryDirectory(prefix=f"shadow6-plugin-{manifest.plugin_id}-") as workdir:
        unshare = shutil.which("unshare")
        if unshare is None:
            raise PluginError("OS network namespace isolation is unavailable (unshare not found)")
        command = [
            unshare, "--user", "--map-current-user", "--net", "--ipc", "--uts", "--pid", "--fork", "--kill-child",
            sys.executable, "-I", "-S", str(Path(workdir) / "plugin.py"),
        ]
        # Execute the bytes verified by the registry, never reopen the source.
        (Path(workdir) / "plugin.py").write_bytes(manifest.code)
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd=workdir,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8"},
                preexec_fn=_child_limits,
                start_new_session=True,
            )
            try:
                process.communicate(encoded + b"\n", timeout=manifest.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                raise PluginError(f"plugin exceeded its {manifest.timeout_seconds}s timeout") from exc
            stdout_file.seek(0)
            output = stdout_file.read(manifest.max_output_bytes + 1)
            stderr_file.seek(0)
            errors = stderr_file.read(4097)
    if process.returncode != 0:
        error = errors[:4096].decode("utf-8", errors="replace")
        raise PluginError(f"plugin exited with status {process.returncode}: {error}")
    if len(output) > manifest.max_output_bytes:
        raise PluginError("plugin output exceeds its manifest limit")
    if errors:
        raise PluginError("plugin wrote unexpected diagnostic output")
    try:
        response = strict_json(output, manifest.max_output_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginError("plugin returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise PluginError("plugin response must be a JSON object")
    return response


def dispatch_hook(
    registry: PluginRegistry, hook: str, payload: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Dispatch a versioned event to every signed plugin that declares a hook."""
    if not CAPABILITY_RE.fullmatch(hook) or not hook.startswith("hook."):
        raise PluginError("invalid hook name")
    results = {}
    for plugin_id in registry.discover():
        manifest = registry.load(plugin_id)
        if hook in manifest.hooks:
            if hook not in manifest.capabilities:
                raise PluginError(f"plugin {plugin_id} declared hook without matching capability")
            results[plugin_id] = run_plugin(
                manifest,
                {"protocol": "shadow6.plugin.v1", "event": hook, "payload": payload},
            )
    return results


def _interactive_game(registry: PluginRegistry, plugin_id: str, locale: str) -> None:
    manifest = registry.load(plugin_id)
    if "game.local" not in manifest.capabilities:
        raise PluginError("selected plugin is not a local game")
    state: dict[str, Any] = {}
    action = "new"
    while True:
        response = run_plugin(manifest, {"action": action, "state": state, "locale": locale})
        print(response.get("message", ""))
        state = response.get("state", {})
        if response.get("done"):
            return
        answer = input(response.get("prompt", "> ")).strip()
        if answer.lower() in {"q", "quit", "exit"}:
            return
        state["input"] = answer
        action = "play"


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 signed plugin manager")
    parser.add_argument("--plugin-root", type=Path, default=DEFAULT_PLUGIN_ROOT)
    parser.add_argument("--trust-store", type=Path, default=DEFAULT_TRUST_STORE)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    verify = subparsers.add_parser("verify")
    verify.add_argument("plugin_id")
    run = subparsers.add_parser("run")
    run.add_argument("plugin_id")
    run.add_argument("request", help="JSON object passed to the plugin")
    game = subparsers.add_parser("game")
    game.add_argument("plugin_id")
    game.add_argument("--locale", choices=("en", "zh-CN"), default=os.environ.get("SHADOW6_LOCALE", "en"))
    dispatch = subparsers.add_parser("dispatch")
    dispatch.add_argument("hook")
    dispatch.add_argument("payload", help="JSON object supplied as the event payload")
    args = parser.parse_args()
    registry = PluginRegistry(args.plugin_root, args.trust_store)
    if args.command == "list":
        for plugin_id in registry.discover():
            try:
                manifest = registry.load(plugin_id)
                print(f"{plugin_id}\t{manifest.version}\t{','.join(sorted(manifest.capabilities))}")
            except PluginError as exc:
                print(f"{plugin_id}\tINVALID\t{exc}")
        return 0
    if args.command == "dispatch":
        print(json.dumps(dispatch_hook(registry, args.hook, strict_json(args.payload, 65_536)), ensure_ascii=False))
        return 0
    manifest = registry.load(args.plugin_id)
    if args.command == "verify":
        print(f"verified {manifest.plugin_id} {manifest.version} signer={manifest.signer}")
    elif args.command == "run":
        request = strict_json(args.request, 65_536)
        if not isinstance(request, dict):
            raise PluginError("request must be a JSON object")
        print(json.dumps(run_plugin(manifest, request), ensure_ascii=False))
    elif args.command == "game":
        _interactive_game(registry, args.plugin_id, args.locale)
    elif args.command == "dispatch":
        payload = json.loads(args.payload)
        if not isinstance(payload, dict):
            raise PluginError("hook payload must be a JSON object")
        print(json.dumps(dispatch_hook(registry, args.hook, payload), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PluginError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
