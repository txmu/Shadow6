"""Loopback-only unit tests for the Shadow6 counterstrike engine."""

from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from counterstrike import (
    AttackTracker,
    CounterstrikeEngine,
    CounterstrikeError,
    CounterstrikePolicy,
    LURE_TEMPLATES,
    MAX_TRACKED_ATTACKERS,
    RateLimiter,
    lure_for,
    parse_threat_event,
)


def base_policy(**overrides):
    document = {
        "version": 1,
        "enabled": True,
        "global_actions_per_minute": 240,
        "attack_decay_seconds": 600,
        "tiers": {
            "deception": {"enabled": True, "hold_seconds": 5, "max_clients": 8,
                          "listeners": [{"host": "127.0.0.1", "port": 0, "template": "ssh"}]},
            "engagement": {"enabled": True, "hold_seconds": 3, "max_concurrent": 4,
                           "per_source_per_hour": 4},
            "throttle": {"enabled": True, "rate_kbps": 16, "window_seconds": 60,
                         "per_source_per_hour": 8},
            "rotation": {"enabled": True},
        },
    }
    document.update(overrides)
    return document


def threat(source="192.0.2.7", port=8080):
    return "SHADOW6_THREAT " + json.dumps({"version": 1, "source": source, "port": port},
                                          separators=(",", ":"))


class PolicyTests(unittest.TestCase):
    def test_valid_policy_loads(self):
        policy = CounterstrikePolicy(base_policy())
        self.assertTrue(policy.enabled)
        self.assertTrue(policy.tier_enabled("deception"))
        self.assertEqual(policy.tiers["throttle"]["rate_kbps"], 16)

    def test_master_disabled_force_disables_all_tiers(self):
        policy = CounterstrikePolicy(base_policy(enabled=False))
        self.assertFalse(policy.enabled)
        for name in ("deception", "engagement", "throttle", "rotation"):
            self.assertFalse(policy.tier_enabled(name))

    def test_absent_policy_is_fail_closed(self):
        policy = CounterstrikePolicy({"version": 1})
        self.assertFalse(policy.enabled)
        self.assertFalse(policy.tier_enabled("engagement"))

    def test_unknown_top_level_field_rejected(self):
        with self.assertRaises(CounterstrikeError):
            CounterstrikePolicy(base_policy(backdoor=True))

    def test_unknown_tier_rejected(self):
        document = base_policy()
        document["tiers"]["offense"] = {"enabled": True}
        with self.assertRaises(CounterstrikeError):
            CounterstrikePolicy(document)

    def test_unknown_tier_field_rejected(self):
        document = base_policy()
        document["tiers"]["engagement"]["shell"] = "rm -rf /"
        with self.assertRaises(CounterstrikeError):
            CounterstrikePolicy(document)

    def test_float_rejected(self):
        with self.assertRaises(CounterstrikeError):
            CounterstrikePolicy({"version": 1.0})

    def test_bad_version_rejected(self):
        with self.assertRaises(CounterstrikeError):
            CounterstrikePolicy({"version": 2})

    def test_non_int_port_rejected(self):
        document = base_policy()
        document["tiers"]["deception"]["listeners"] = [
            {"host": "127.0.0.1", "port": "8080", "template": "ssh"}]
        with self.assertRaises(CounterstrikeError):
            CounterstrikePolicy(document)

    def test_load_requires_0600_owner_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(base_policy()), encoding="utf-8")
            os.chmod(path, 0o644)
            with self.assertRaises(CounterstrikeError):
                CounterstrikePolicy.load(path)
            os.chmod(path, 0o600)
            self.assertTrue(CounterstrikePolicy.load(path).enabled)

    def test_load_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real.json"
            real.write_text(json.dumps(base_policy()), encoding="utf-8")
            os.chmod(real, 0o600)
            link = Path(directory) / "link.json"
            link.symlink_to(real)
            with self.assertRaises(CounterstrikeError):
                CounterstrikePolicy.load(link)


class EventParseTests(unittest.TestCase):
    def test_valid_event(self):
        self.assertEqual(parse_threat_event(threat("192.0.2.7", 8080)), ("192.0.2.7", 8080))

    def test_rejects_bad_schema_version_floats_unknown_dup(self):
        for bad in (
            threat("192.0.2.7", 80)[:-1] + ',"extra":1}',
            '{"version":1}',
            'SHADOW6_THREAT {"version":2,"source":"192.0.2.7","port":80}',
            'SHADOW6_THREAT {"version":1,"version":1,"source":"192.0.2.7","port":80}',
            'SHADOW6_THREAT {"version":1,"source":"192.0.2.7","port":"80"}',
            'SHADOW6_THREAT {"version":1,"source":"127.0.0.1","port":80}',
            'SHADOW6_THREAT {"version":1,"source":"192.0.2.7","port":70000}',
            'MALICIOUS PROBE DETECTED',
            'random garbage',
        ):
            self.assertIsNone(parse_threat_event(bad), bad)

    def test_multicast_and_unspecified_rejected(self):
        self.assertIsNone(parse_threat_event(threat("0.0.0.0", 80)))
        self.assertIsNone(parse_threat_event(threat("224.0.0.1", 80)))


class TrackerTests(unittest.TestCase):
    def test_new_then_refresh(self):
        tracker = AttackTracker(600)
        self.assertTrue(tracker.record("192.0.2.1"))
        self.assertFalse(tracker.record("192.0.2.1"))
        self.assertIn("192.0.2.1", tracker.active())

    def test_capacity_bounded_drop_on_flood(self):
        tracker = AttackTracker(600, capacity=8)
        for index in range(8):
            self.assertTrue(tracker.record(f"192.0.2.{index}"))
        self.assertFalse(tracker.record("192.0.2.99"))
        self.assertLessEqual(len(tracker._seen), 8)


class RateLimiterTests(unittest.TestCase):
    def test_per_key_budget(self):
        limiter = RateLimiter(per_key_per_hour=2, global_per_minute=10)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))

    def test_global_ceiling(self):
        limiter = RateLimiter(per_key_per_hour=100, global_per_minute=3)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))
        self.assertTrue(limiter.allow("c"))
        self.assertFalse(limiter.allow("d"))


class LureTests(unittest.TestCase):
    def test_builtin_lures_nonempty(self):
        for name in ("generic", "ssh", "ftp", "smtp", "mysql", "redis", "admin"):
            self.assertTrue(LURE_TEMPLATES[name])

    def test_override_preferred_and_bounded(self):
        body = lure_for("ssh", {"ssh": "custom-banner"})
        self.assertEqual(body, b"custom-banner")


class EngineTests(unittest.TestCase):
    def _start(self, **overrides):
        rotations = []
        engine = CounterstrikeEngine(CounterstrikePolicy(base_policy(**overrides)),
                                     on_rotation=rotations.append)
        engine.start()
        self.addCleanup(engine.stop)
        return engine, rotations

    def test_disabled_engine_is_noop(self):
        engine = CounterstrikeEngine(CounterstrikePolicy(base_policy(enabled=False)))
        engine.start()
        self.assertFalse(engine.handle_event(threat()))

    def test_deception_lure_serves_banner_on_loopback(self):
        engine, _ = self._start()
        self.assertEqual(len(engine._deception), 1)
        server = engine._deception[0]
        with socket.create_connection(("127.0.0.1", server.port), timeout=3) as client:
            client.settimeout(3)
            self.assertTrue(client.recv(64))

    def test_event_records_source(self):
        engine, _ = self._start()
        self.assertTrue(engine.handle_event(threat("192.0.2.7")))
        self.assertIn("192.0.2.7", engine.tracker.active())

    def test_malformed_events_ignored(self):
        engine, _ = self._start()
        self.assertFalse(engine.handle_event("MALICIOUS PROBE DETECTED"))
        self.assertFalse(engine.handle_event(threat("127.0.0.1", 80)))
        self.assertEqual(engine._actions, 0)

    def test_escalation_ladder_requests_rotation(self):
        engine, rotations = self._start()
        for _ in range(CounterstrikeEngine.ESCALATE_AFTER):
            engine.handle_event(threat("192.0.2.7"))
        self.assertEqual(rotations, ["192.0.2.7"])

    def test_no_rotation_below_threshold(self):
        engine, rotations = self._start()
        engine.handle_event(threat("192.0.2.7"))
        self.assertEqual(rotations, [])

    def test_engagement_budget_exhaustion(self):
        engine, _ = self._start()
        limiter = engine._engagement_limiter
        engine._engagement_limiter = RateLimiter(per_key_per_hour=1, global_per_minute=100)
        self.assertTrue(engine._engagement_limiter.allow("192.0.2.7"))
        self.assertFalse(engine._engagement_limiter.allow("192.0.2.7"))
        engine._engagement_limiter = limiter

    def test_status_is_bounded_and_serializable(self):
        engine, _ = self._start()
        engine.handle_event(threat("192.0.2.7"))
        status = engine.status()
        json.dumps(status)
        self.assertTrue(status["running"])
        self.assertEqual(len(status["deception_listeners"]), 1)

    def test_start_is_idempotent_and_stop_clean(self):
        engine = CounterstrikeEngine(CounterstrikePolicy(base_policy()))
        engine.start()
        engine.start()
        engine.stop()
        engine.stop()


class BoundsInvariantTests(unittest.TestCase):
    def test_tracker_never_exceeds_hard_cap(self):
        tracker = AttackTracker(600, capacity=10_000_000)
        self.assertLessEqual(tracker.capacity, MAX_TRACKED_ATTACKERS)


if __name__ == "__main__":
    unittest.main()
