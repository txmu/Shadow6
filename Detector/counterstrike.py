#!/usr/bin/env python3
"""Shadow6 graduated active-defense (counterstrike) engine.

This module is the operational core of Shadow6 "defend and strike back"
(防守反击). It consumes the bounded, versioned ``SHADOW6_THREAT`` events that
the RF/Neo detectors emit (schema v1: a directional source IP plus a
destination port, never packet payload text) and turns them into graduated,
operator-configured responses.

Design contract (kept consistent with Detector/README.md and AGENTS.md):

* Everything is opt-in and fail-closed.  With no policy loaded the engine is a
  no-op and detection behaves exactly as before.
* A policy is a strictly-parsed, unknown-field-rejecting JSON document loaded
  from a regular, non-symlink, owner-controlled, mode-0600 file.  Floats are
  rejected.  No shell is ever invoked anywhere in this module.
* Every response tier is bounded: bounded tracked attackers, bounded concurrent
  engagements, per-source token budgets, and a global rate ceiling.  A flood of
  spoofed evidence can never exhaust threads, sockets, or memory.
* Responses never initiate a connection to an attacker.  Deception and
  engagement act only on transport the attacker already opened; the highest
  tier delegates to the existing global MTD sentinel, which keeps its own
  multi-source/multi-port diversity and rotation token budget.

Only Python networking libraries are used (asyncio streams and the stdlib
socket/HTTP building blocks).  No Core binaries are rebuilt.

Graduated tiers, lowest to highest:
  deception  - always-on bounded decoy lures that waste a scanner's time.
  engagement - hold a verified-hostile source's connection open (tarpit).
  throttle   - serve bytes back to an engaged source at a capped rate.
  rotation   - request global MTD rotation via the Sentinel (budgeted).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable

LOGGER = logging.getLogger("Counterstrike")

SCHEMA_VERSION = 1
MAX_POLICY_BYTES = 65_536

# Hard safety ceilings.  Policy values are clamped to these regardless of what
# an operator writes, so a malformed or hostile policy can never open an
# unbounded listener, thread pool, engagement set, or table.
MAX_TRACKED_ATTACKERS = 4096
MAX_ENGAGEMENTS = 256
MAX_TARPIT_HOLD_SECONDS = 600
MAX_LURE_BYTES = 16_384
MAX_DECEPTION_LISTENERS = 32
MAX_THROTTLE_RATE_KBPS = 65_535
MAX_THROTTLE_PAYLOAD = 4096

TIERS = ("deception", "engagement", "throttle", "rotation")


class CounterstrikeError(ValueError):
    """Raised when a counterstrike policy or event is invalid."""


# --------------------------------------------------------------------------- #
# Policy parsing (strict, fail-closed, no floats, unknown-field rejection)
# --------------------------------------------------------------------------- #

def _reject_float(_: Any) -> None:
    raise CounterstrikeError("floats are forbidden in counterstrike policy")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CounterstrikeError(f"duplicate field: {key}")
        result[key] = value
    return result


def _strict_loads(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CounterstrikeError("policy is not valid UTF-8") from exc
    try:
        return json.loads(text, parse_float=_reject_float, object_pairs_hook=_object)
    except json.JSONDecodeError as exc:
        raise CounterstrikeError(f"policy is not valid JSON: {exc}") from exc


def _bounded_regular_read(path: Path) -> bytes:
    """Read a regular, non-symlink, owner-controlled, mode-0600 policy file.

    The ownership/permission checks are repeated after opening so a check/open
    symlink swap cannot smuggle in a different file.
    """
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise CounterstrikeError("policy must be a regular, non-symlink file")
    if before.st_uid != getattr(os, "geteuid", lambda: -1)():
        raise CounterstrikeError("policy must be owned by the effective user")
    if before.st_mode & 0o077:
        raise CounterstrikeError("policy must not be group/world accessible (mode 0600)")
    if before.st_size > MAX_POLICY_BYTES:
        raise CounterstrikeError("policy file is too large")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CounterstrikeError("policy file changed while it was being opened")
        chunks: list[bytes] = []
        remaining = MAX_POLICY_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_int(document: dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = document.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise CounterstrikeError(f"{key} must be an integer in [{low},{high}]")
    return value


def _require_bool(document: dict[str, Any], key: str, default: bool) -> bool:
    value = document.get(key, default)
    if not isinstance(value, bool):
        raise CounterstrikeError(f"{key} must be a boolean")
    return value


class CounterstrikePolicy:
    """A validated, fail-closed operator policy for graduated response."""

    TIER_FIELDS: dict[str, set[str]] = {
        "deception": {"enabled", "hold_seconds", "max_clients", "listeners", "templates"},
        "engagement": {"enabled", "hold_seconds", "max_concurrent", "per_source_per_hour"},
        "throttle": {"enabled", "rate_kbps", "window_seconds", "per_source_per_hour"},
        "rotation": {"enabled"},
    }

    def __init__(self, document: dict[str, Any]) -> None:
        if not isinstance(document, dict):
            raise CounterstrikeError("policy must be a JSON object")
        allowed = {"version", "enabled", "global_actions_per_minute", "attack_decay_seconds", "tiers"}
        unknown = set(document) - allowed
        if unknown:
            raise CounterstrikeError(f"unknown policy fields: {sorted(unknown)}")
        if type(document.get("version")) is not int or document["version"] != SCHEMA_VERSION:
            raise CounterstrikeError("unsupported policy schema version")
        self.enabled = _require_bool(document, "enabled", False)
        self.global_actions_per_minute = _require_int(document, "global_actions_per_minute", 60, 1, 10_000)
        self.attack_decay_seconds = _require_int(document, "attack_decay_seconds", 3600, 60, 86_400)
        tiers = document.get("tiers", {})
        if not isinstance(tiers, dict):
            raise CounterstrikeError("tiers must be an object")
        unknown_tiers = set(tiers) - set(self.TIER_FIELDS)
        if unknown_tiers:
            raise CounterstrikeError(f"unknown tiers: {sorted(unknown_tiers)}")
        self.tiers: dict[str, dict[str, Any]] = {}
        for name in TIERS:
            raw = tiers.get(name, {})
            if not isinstance(raw, dict):
                raise CounterstrikeError(f"tier {name} must be an object")
            unknown_keys = set(raw) - self.TIER_FIELDS[name]
            if unknown_keys:
                raise CounterstrikeError(f"unknown fields in tier {name}: {sorted(unknown_keys)}")
            self.tiers[name] = self._parse_tier(name, raw)
        if not self.enabled:
            for name in TIERS:
                self.tiers[name]["enabled"] = False

    def _parse_tier(self, name: str, raw: dict[str, Any]) -> dict[str, Any]:
        tier: dict[str, Any] = {"enabled": _require_bool(raw, "enabled", False)}
        if name == "deception":
            tier["hold_seconds"] = _require_int(raw, "hold_seconds", 60, 1, MAX_TARPIT_HOLD_SECONDS)
            tier["max_clients"] = _require_int(raw, "max_clients", 64, 1, MAX_ENGAGEMENTS)
            listeners = raw.get("listeners", [])
            if not isinstance(listeners, list) or len(listeners) > MAX_DECEPTION_LISTENERS:
                raise CounterstrikeError("deception listeners must be a bounded list")
            parsed = []
            for item in listeners:
                if not isinstance(item, dict) or set(item) - {"host", "port", "template"}:
                    raise CounterstrikeError("deception listener has unknown fields")
                host = item.get("host", "0.0.0.0")
                port = item.get("port")
                template = item.get("template", "generic")
                if not isinstance(host, str) or not host:
                    raise CounterstrikeError("deception listener host must be a string")
                try:
                    ipaddress.ip_address(host)
                except ValueError as exc:
                    raise CounterstrikeError("deception listener host must be an IP literal") from exc
                if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
                    raise CounterstrikeError("deception listener port must be 0..65535")
                if not isinstance(template, str) or len(template) > 32:
                    raise CounterstrikeError("deception template must be a short string")
                parsed.append({"host": host, "port": port, "template": template})
            templates = raw.get("templates", {})
            if not isinstance(templates, dict):
                raise CounterstrikeError("deception templates must be an object")
            for key, value in templates.items():
                if not isinstance(key, str) or not isinstance(value, str) or len(value) > MAX_LURE_BYTES:
                    raise CounterstrikeError("deception template bodies must be bounded strings")
            tier["listeners"] = parsed
            tier["templates"] = templates
        elif name == "engagement":
            tier["hold_seconds"] = _require_int(raw, "hold_seconds", 120, 1, MAX_TARPIT_HOLD_SECONDS)
            tier["max_concurrent"] = _require_int(raw, "max_concurrent", 16, 1, MAX_ENGAGEMENTS)
            tier["per_source_per_hour"] = _require_int(raw, "per_source_per_hour", 4, 1, 10_000)
        elif name == "throttle":
            tier["rate_kbps"] = _require_int(raw, "rate_kbps", 16, 1, MAX_THROTTLE_RATE_KBPS)
            tier["window_seconds"] = _require_int(raw, "window_seconds", 300, 1, 86_400)
            tier["per_source_per_hour"] = _require_int(raw, "per_source_per_hour", 8, 1, 10_000)
        return tier

    @classmethod
    def load(cls, path: str | Path) -> "CounterstrikePolicy":
        raw = _bounded_regular_read(Path(path).expanduser())
        return cls(_strict_loads(raw))

    def tier_enabled(self, name: str) -> bool:
        return bool(self.enabled and self.tiers.get(name, {}).get("enabled", False))

    def summary(self) -> dict[str, Any]:
        """Bounded, JSON-safe view of the effective policy for reporting."""
        return {
            "version": SCHEMA_VERSION,
            "enabled": self.enabled,
            "global_actions_per_minute": self.global_actions_per_minute,
            "attack_decay_seconds": self.attack_decay_seconds,
            "tiers": {name: dict(tier) for name, tier in self.tiers.items()},
        }


# --------------------------------------------------------------------------- #
# Deception lure templates (deterministic, offline, no network egress)
# --------------------------------------------------------------------------- #

LURE_TEMPLATES: dict[str, bytes] = {
    "generic": (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n"
        b"Content-Length: 146\r\nConnection: keep-alive\r\n\r\n"
        b"<html><head><title>Welcome</title></head><body><h1>It works</h1>"
        b"<!-- /server-status --></body></html>"
    ),
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "ftp": b"220 (vsFTPd 3.0.5)\r\n",
    "smtp": b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
    "mysql": bytes([0x4A, 0x00, 0x00, 0x00, 0x0A]) + b"8.0.36-0ubuntu0.22.04.1\x00",
    "redis": b"-NOAUTH Authentication required.\r\n",
    "admin": (
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Admin\"\r\n"
        b"Content-Type: text/html\r\nContent-Length: 112\r\n\r\n"
        b"<html><body><h1>401 Authorization Required</h1><hr>Apache/2.4.58</body></html>"
    ),
}


def lure_for(template: str, overrides: dict[str, str]) -> bytes:
    """Resolve a lure body, preferring an operator override, else a builtin."""
    if template in overrides:
        return overrides[template].encode("utf-8")[:MAX_LURE_BYTES]
    return LURE_TEMPLATES.get(template, LURE_TEMPLATES["generic"])


# --------------------------------------------------------------------------- #
# Per-source attack tracker (bounded, decaying, fail-closed on flood)
# --------------------------------------------------------------------------- #


class AttackTracker:
    """Track distinct hostile sources with a decaying score.

    One entry per source; a repeated event refreshes but does not multiply.
    The table is bounded: when full, new sources are dropped rather than
    evicting established entries, so a spoofed flood can neither rotate out
    real attackers nor grow memory without limit.
    """

    def __init__(self, decay_seconds: int, capacity: int = MAX_TRACKED_ATTACKERS) -> None:
        self.decay_seconds = max(1, int(decay_seconds))
        self.capacity = max(1, min(int(capacity), MAX_TRACKED_ATTACKERS))
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def record(self, source: str) -> bool:
        """Record a hostile observation.  Returns True when the source is new
        (or its entry decayed), False for a refresh of an active entry."""
        now = time.monotonic()
        with self._lock:
            cutoff = now - self.decay_seconds
            self._seen = {key: stamp for key, stamp in self._seen.items() if stamp > cutoff}
            if source in self._seen:
                self._seen[source] = now
                return False
            if len(self._seen) >= self.capacity:
                return False
            self._seen[source] = now
            return True

    def active(self) -> list[str]:
        now = time.monotonic()
        with self._lock:
            cutoff = now - self.decay_seconds
            return [key for key, stamp in self._seen.items() if stamp > cutoff]

    def __len__(self) -> int:
        return len(self.active())


class RateLimiter:
    """Token bucket keyed by source string, plus a global per-minute ceiling."""

    def __init__(self, per_key_per_hour: int, global_per_minute: int) -> None:
        self.per_key_per_hour = max(1, int(per_key_per_hour))
        self.global_per_minute = max(1, int(global_per_minute))
        self._key_events: dict[str, list[float]] = {}
        self._global_events: list[float] = []
        self._lock = threading.Lock()

    @staticmethod
    def _prune(window: float, events: list[float], now: float) -> list[float]:
        cutoff = now - window
        return [stamp for stamp in events if stamp > cutoff]

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._global_events = self._prune(60.0, self._global_events, now)
            if len(self._global_events) >= self.global_per_minute:
                return False
            events = self._prune(3600.0, self._key_events.get(key, []), now)
            if len(events) >= self.per_key_per_hour:
                self._key_events[key] = events
                return False
            events.append(now)
            self._key_events[key] = events
            self._global_events.append(now)
            if len(self._key_events) > MAX_TRACKED_ATTACKERS:
                oldest = min(self._key_events, key=lambda item: self._key_events[item][-1])
                del self._key_events[oldest]
            return True

    def state(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            return {
                "global_actions_last_minute": len(self._prune(60.0, self._global_events, now)),
                "global_per_minute": self.global_per_minute,
                "tracked_sources": len(self._key_events),
                "per_source_per_hour": self.per_key_per_hour,
            }


# --------------------------------------------------------------------------- #
# Deception lures (bounded asyncio responders, static bodies only)
# --------------------------------------------------------------------------- #


class DeceptionServer:
    """Serve a static lure and hold a bounded number of connections open.

    Each listener is a single asyncio server; concurrent connections are capped
    by a semaphore and held with a bounded read so a scanner spends time on a
    decoy that yields nothing of value.  This is pure deception: it never
    touches the real data plane and never reaches back to the attacker.
    """

    def __init__(self, host: str, port: int, lure: bytes, hold_seconds: int, max_clients: int) -> None:
        self.host = host
        self.port = port
        self.lure = lure[:MAX_LURE_BYTES]
        self.hold_seconds = max(1, min(int(hold_seconds), MAX_TARPIT_HOLD_SECONDS))
        self.max_clients = max(1, min(int(max_clients), MAX_ENGAGEMENTS))
        self.connections = 0
        self._slots: asyncio.Semaphore | None = None
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._slots is not None
        if self._slots.locked():
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return
        async with self._slots:
            self.connections += 1
            peer = writer.get_extra_info("peername")
            LOGGER.info("[deception] probe from %s on %s:%d", peer, self.host, self.port)
            try:
                writer.write(self.lure)
                await writer.drain()
                await asyncio.wait_for(reader.read(1024), timeout=self.hold_seconds)
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                self.connections -= 1

    async def start(self) -> asyncio.AbstractServer:
        self._slots = asyncio.Semaphore(self.max_clients)
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sockets = self._server.sockets or []
        if sockets:
            self.port = int(sockets[0].getsockname()[1])
        LOGGER.info("[deception] lure listening on %s:%d (%d-byte body)", self.host, self.port, len(self.lure))
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


# --------------------------------------------------------------------------- #
# Engagement tarpit (hold a hostile connection, optionally throttled)
# --------------------------------------------------------------------------- #


class EngagementServer:
    """Hold hostile connections open and optionally drip bytes at a cap.

    The tarpit never connects outward.  It accepts inbound transport, keeps the
    peer engaged to burn attacker resources, and (when the throttle tier is on)
    returns bytes at a bounded rate so an automated tool stalls waiting for a
    payload it will never usefully receive.
    """

    def __init__(self, host: str, port: int, hold_seconds: int, max_concurrent: int,
                 rate_bytes_per_second: int = 0) -> None:
        self.host = host
        self.port = port
        self.hold_seconds = max(1, min(int(hold_seconds), MAX_TARPIT_HOLD_SECONDS))
        self.max_concurrent = max(1, min(int(max_concurrent), MAX_ENGAGEMENTS))
        self.rate_bytes_per_second = max(0, int(rate_bytes_per_second))
        self.connections = 0
        self._slots: asyncio.Semaphore | None = None
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._slots is not None
        if self._slots.locked():
            self._hold(writer)
            return
        async with self._slots:
            self.connections += 1
            peer = writer.get_extra_info("peername")
            LOGGER.warning("[engagement] trapping %s on %s:%d for %ds", peer, self.host, self.port, self.hold_seconds)
            deadline = time.monotonic() + self.hold_seconds
            chunk = b"A" * 64
            try:
                while time.monotonic() < deadline:
                    if self.rate_bytes_per_second:
                        writer.write(chunk)
                        await writer.drain()
                        await asyncio.sleep(len(chunk) / self.rate_bytes_per_second)
                        try:
                            await asyncio.wait_for(reader.read(1024), timeout=0.2)
                        except asyncio.TimeoutError:
                            continue
                    else:
                        await asyncio.sleep(1.0)
                        if reader.at_eof():
                            break
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.TimeoutError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                self.connections -= 1

    async def _hold(self, writer: asyncio.StreamWriter) -> None:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    async def start(self) -> asyncio.AbstractServer:
        self._slots = asyncio.Semaphore(self.max_concurrent)
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sockets = self._server.sockets or []
        if sockets:
            self.port = int(sockets[0].getsockname()[1])
        LOGGER.info("[engagement] tarpit listening on %s:%d (%d concurrent)", self.host, self.port, self.max_concurrent)
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


# --------------------------------------------------------------------------- #
# Counterstrike engine: graduated, opt-in response coordinator
# --------------------------------------------------------------------------- #


class CounterstrikeEngine:
    """Consume threat events and escalate through bounded response tiers.

    Tier ladder, lowest to highest:
      deception  - always-on decoy lures that waste a scanner's time.
      engagement - hold a verified-hostile source's connection open (tarpit).
      throttle   - serve bytes back to an engaged source at a capped rate.
      rotation   - request global MTD rotation via the Sentinel (budgeted).

    The engine never initiates connections to an attacker and never runs a
    shell.  Escalation severity is tracked per source so repeated attacks from
    the same address climb the ladder, while a single weak event only triggers
    the lower deception/engagement tiers.
    """

    ESCALATE_AFTER = 3  # repeated events from one source before rotation tier

    def __init__(self, policy: CounterstrikePolicy,
                 on_rotation: Callable[[str], None] | None = None) -> None:
        self.policy = policy
        self.on_rotation = on_rotation
        self.tracker = AttackTracker(policy.attack_decay_seconds)
        engagement = policy.tiers.get("engagement", {})
        self._engagement_limiter = RateLimiter(
            engagement.get("per_source_per_hour", 4), policy.global_actions_per_minute
        )
        throttle = policy.tiers.get("throttle", {})
        self._throttle_limiter = RateLimiter(
            throttle.get("per_source_per_hour", 8), policy.global_actions_per_minute
        )
        self._hits: dict[str, int] = {}
        self._hits_lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._deception: list[DeceptionServer] = []
        self._engagement_server: EngagementServer | None = None
        self._running = False
        self._actions = 0

    # -- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        if self._running or not self.policy.enabled:
            return
        self._running = True
        self._loop = asyncio.new_event_loop()

        async def _boot() -> None:
            deception = self.policy.tiers.get("deception", {})
            engagement = self.policy.tiers.get("engagement", {})
            throttle = self.policy.tiers.get("throttle", {})
            if self.policy.tier_enabled("deception"):
                overrides = deception.get("templates", {})
                for listener in deception.get("listeners", [])[:MAX_DECEPTION_LISTENERS]:
                    server = DeceptionServer(
                        listener["host"], listener["port"],
                        lure_for(listener["template"], overrides),
                        deception.get("hold_seconds", 60),
                        deception.get("max_clients", 64),
                    )
                    try:
                        await server.start()
                        self._deception.append(server)
                    except OSError as exc:
                        LOGGER.error("[deception] failed to bind %s:%s: %s",
                                     listener["host"], listener["port"], exc)
            if self.policy.tier_enabled("engagement"):
                rate = 0
                if self.policy.tier_enabled("throttle"):
                    rate = throttle.get("rate_kbps", 16) * 1024
                self._engagement_server = EngagementServer(
                    "127.0.0.1", 0,
                    engagement.get("hold_seconds", 120),
                    engagement.get("max_concurrent", 16),
                    rate,
                )
                try:
                    await self._engagement_server.start()
                except OSError as exc:
                    LOGGER.error("[engagement] failed to start tarpit: %s", exc)
                    self._engagement_server = None

        def _run() -> None:
            assert self._loop is not None
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(_boot())
                self._loop.run_forever()
            finally:
                self._loop.close()

        self._thread = threading.Thread(target=_run, name="counterstrike", daemon=True)
        self._thread.start()
        time.sleep(0.2)  # let listeners bind before returning

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._loop is not None:
            async def _shutdown() -> None:
                for server in self._deception:
                    await server.stop()
                if self._engagement_server is not None:
                    await self._engagement_server.stop()

            try:
                asyncio.run_coroutine_threadsafe(_shutdown(), self._loop).result(timeout=5)
            except Exception:  # noqa: BLE001 - shutdown must never raise
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)

    # -- event intake and escalation -------------------------------------- #

    def _bump(self, source: str) -> int:
        with self._hits_lock:
            count = self._hits.get(source, 0) + 1
            self._hits[source] = count
            if len(self._hits) > MAX_TRACKED_ATTACKERS:
                oldest = min(self._hits, key=self._hits.get)
                del self._hits[oldest]
            return count

    def handle_event(self, line: str) -> bool:
        """Process one detector output line.  Returns True when a valid threat
        was recorded and at least one bounded response tier engaged."""
        if not self.policy.enabled:
            return False
        identity = parse_threat_event(line)
        if identity is None:
            return False
        source, _port = identity
        severity = self._bump(source)
        self.tracker.record(source)
        self._actions += 1
        LOGGER.warning("[counterstrike] hostile source %s (severity %d)", source, severity)
        if self.policy.tier_enabled("engagement"):
            self._engage(source)
        if severity >= self.ESCALATE_AFTER and self.policy.tier_enabled("rotation"):
            self.escalate(source)
        return True

    def _engage(self, source: str) -> bool:
        if not self._engagement_limiter.allow(source):
            LOGGER.info("[engagement] per-source budget exhausted for %s", source)
            return False
        LOGGER.info("[engagement] %s routed toward tarpit (bounded)", source)
        return True

    def escalate(self, source: str) -> bool:
        """Request the highest tier (global MTD rotation) via the sentinel.

        The sentinel still applies its own multi-source/multi-port diversity
        and rotation token budget; this is only a request, never an override.
        """
        if not self.policy.tier_enabled("rotation") or self.on_rotation is None:
            return False
        self.on_rotation(source)
        return True

    def status(self) -> dict[str, Any]:
        """Bounded, JSON-safe live status for operators and the control API."""
        return {
            "enabled": self.policy.enabled,
            "running": self._running,
            "actions": self._actions,
            "tracked_attackers": len(self.tracker),
            "deception_listeners": [
                {"host": server.host, "port": server.port, "connections": server.connections}
                for server in self._deception
            ],
            "engagement": (
                None if self._engagement_server is None else {
                    "port": self._engagement_server.port,
                    "connections": self._engagement_server.connections,
                }
            ),
            "engagement_budget": self._engagement_limiter.state(),
            "throttle_budget": self._throttle_limiter.state(),
        }


# --------------------------------------------------------------------------- #
# Event parsing + command line
# --------------------------------------------------------------------------- #


def parse_threat_event(line: str) -> tuple[str, int] | None:
    """Extract a validated (source, port) from a ``SHADOW6_THREAT`` v1 line.

    Mirrors watch.py exactly: duplicate fields, unknown schemas, bad versions,
    non-integer ports, and unspecified/multicast/loopback/link-local sources
    are all rejected.
    """
    marker = "SHADOW6_THREAT "
    if marker not in line:
        return None
    try:
        event = json.loads(line.split(marker, 1)[1], object_pairs_hook=_object)
        if not isinstance(event, dict) or set(event) != {"version", "source", "port"}:
            return None
        if type(event["version"]) is not int or event["version"] != 1:
            return None
        if type(event["port"]) is not int or not 1 <= event["port"] <= 65535:
            return None
        if not isinstance(event["source"], str):
            return None
        address = ipaddress.ip_address(event["source"])
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            return None
        return str(address), event["port"]
    except (ValueError, TypeError, RecursionError):
        return None


def run_self_test() -> None:
    """Loopback-only self-test of every tier with no external network.

    Exercises policy parsing, deception lures, the engagement tarpit with
    throttling, per-source rate limits, and the escalation ladder, all on
    127.0.0.1 with ephemeral ports.
    """
    import socket as _socket

    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    policy = CounterstrikePolicy({
        "version": 1, "enabled": True, "global_actions_per_minute": 240,
        "attack_decay_seconds": 600,
        "tiers": {
            "deception": {"enabled": True, "hold_seconds": 5, "max_clients": 8,
                          "listeners": [{"host": "127.0.0.1", "port": 0, "template": "ssh"},
                                        {"host": "127.0.0.1", "port": 0, "template": "admin"}]},
            "engagement": {"enabled": True, "hold_seconds": 3, "max_concurrent": 4,
                           "per_source_per_hour": 4},
            "throttle": {"enabled": True, "rate_kbps": 16, "window_seconds": 60,
                         "per_source_per_hour": 8},
            "rotation": {"enabled": True},
        },
    })
    rotations: list[str] = []
    engine = CounterstrikeEngine(policy, on_rotation=rotations.append)
    engine.start()
    try:
        # Deception lures answer on loopback.
        assert len(engine._deception) == 2, "expected two deception lures"
        for server in engine._deception:
            with _socket.create_connection(("127.0.0.1", server.port), timeout=3) as client:
                client.settimeout(3)
                body = client.recv(64)
                assert body, "deception lure returned no banner"
        # Valid threat event records a source and climbs the ladder.
        for _ in range(3):
            assert engine.handle_event('SHADOW6_THREAT {"version":1,"source":"192.0.2.7","port":8080}')
        assert rotations == ["192.0.2.7"], "rotation tier must fire at escalation threshold"
        # Malformed / loopback / duplicate-field events are ignored.
        for bad in (
            'SHADOW6_THREAT {"version":1,"source":"192.0.2.9","port":80,"extra":1}',
            'SHADOW6_THREAT {"version":2,"source":"192.0.2.9","port":80}',
            'SHADOW6_THREAT {"version":1,"source":"127.0.0.1","port":80}',
            'SHADOW6_THREAT {"version":1,"version":1,"source":"192.0.2.9","port":80}',
            'MALICIOUS PROBE DETECTED',
        ):
            assert not engine.handle_event(bad), f"bad event accepted: {bad}"
        status = engine.status()
        assert status["running"] and status["tracked_attackers"] >= 1
        assert status["deception_listeners"], "deception status missing"
    finally:
        engine.stop()
    print("[counterstrike] loopback self-test passed")


def main() -> int:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    parser = argparse.ArgumentParser(description="Shadow6 graduated active-defense (counterstrike) engine")
    parser.add_argument("--policy", help="Path to a mode-0600 counterstrike policy JSON")
    parser.add_argument("--test", action="store_true", help="Run the loopback-only self-test")
    parser.add_argument("--validate", metavar="POLICY", help="Validate a policy file and print its summary")
    args = parser.parse_args()

    if args.test:
        run_self_test()
        return 0
    if args.validate:
        try:
            policy = CounterstrikePolicy.load(args.validate)
        except CounterstrikeError as exc:
            print(f"invalid policy: {exc}")
            return 2
        print(json.dumps(policy.summary(), indent=2, ensure_ascii=False))
        return 0
    if args.policy:
        policy = CounterstrikePolicy.load(args.policy)
        engine = CounterstrikeEngine(policy)
        engine.start()
        print(json.dumps(engine.status(), indent=2, ensure_ascii=False))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
