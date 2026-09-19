#!/usr/bin/env python3
"""
Shadow6 MTD Sentinel (watch.py)
--------------------------------------------------
Description:
    Bridges the Detection and Orchestration layers. 
    Monitors Detector logs (Standard RF or Neo LSTM) and triggers 
    bounded probe evidence. Global MTD requires multiple sources and ports,
    a threat threshold, and an independent rotation budget.

Workflow:
    Detector -> stdout -> Sentinel (watch.py) -> Orchestrator (apply)
"""

import os
import sys
import time
import signal
import argparse
import re
import subprocess
import threading
import ipaddress
import json
from datetime import datetime

# Optional graduated active-defense layer.  Imported lazily so a checkout
# without counterstrike.py keeps the previous bounded-sentinel behavior.
try:
    from counterstrike import CounterstrikeEngine, CounterstrikeError, CounterstrikePolicy
except ImportError:  # pragma: no cover - defensive import guard
    CounterstrikeEngine = CounterstrikePolicy = None

    class CounterstrikeError(ValueError):
        pass

# --- Tree resolution ---------------------------------------------------------
def _tree_root():
    """Return the Shadow6 tree this watcher should drive.

    A source checkout keeps the watcher inside the tree, while "make install"
    places it in <prefix>/bin next to the tree at <prefix>/share/shadow6/tree.
    SHADOW6_ROOT overrides both so an operator can pin an explicit tree.
    """
    override = os.environ.get("SHADOW6_ROOT", "").strip()
    if override:
        return os.path.abspath(os.path.expanduser(override))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if os.path.isdir(os.path.join(here, "..", "Auto-Orchestrator")):
        candidates.append(os.path.join(here, ".."))
    prefix = os.path.dirname(here)
    candidates.append(os.path.join(prefix, "share", "shadow6", "tree"))
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "Makefile")):
            return os.path.abspath(candidate)
    return os.path.abspath(candidates[0])


# --- Configuration & Styling ---
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'

# Detection keywords defined in shadow6_detector.py and C11Relay
ATTACK_KEYWORDS = [
    "MALICIOUS PROBE DETECTED",
    "DPI PROBING DETECTED",
    "PROBE SEQUENCE DETECTED",   # Neo-Detector LSTM specific
    "MALFORMED_RUST_CRASH_TEST"  # Heuristic trigger
]
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def clean_output(value, limit=4096):
    value = ANSI_ESCAPE.sub("", value)
    value = "".join(character if character.isprintable() or character == "\t" else " " for character in value)
    return value[:limit].strip()

class ShadowSentinel:
    def __init__(
        self,
        detector_cmd,
        orchestrator_path,
        topo_path,
        cooldown,
        score_threshold=3,
        score_window=60,
        rotation_interval=3600,
    ):
        self.detector_cmd = detector_cmd
        self.orchestrator_path = orchestrator_path
        self.topo_path = topo_path
        self.cooldown = cooldown
        self.last_rotation = float("-inf")
        self.last_attempt = float("-inf")
        self.failure_backoff = 0.0
        self.score_threshold = max(1, int(score_threshold))
        self.score_window = max(1, int(score_window))
        self.alert_history = {}
        self.rotation_tokens = 1
        self.rotation_interval = max(self.cooldown, int(rotation_interval))
        self.last_token_refill = time.monotonic()
        self.detector_proc = None
        self.rotation_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.alert_pending = threading.Event()
        self.stop_event = threading.Event()
        self.counterstrike = None

    def log(self, message, color=NC):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{color}[{timestamp}] [SENTINEL] {message}{NC}")

    def trigger_rotation(self, reason):
        """Executes the Moving Target Defense rotation."""
        if not self.rotation_lock.acquire(blocking=False):
            self.log("Rotation already in progress; coalescing this alert.", YELLOW)
            self.alert_pending.clear()
            return
        try:
            current_time = time.monotonic()
            with self.state_lock:
                retry_delay = max(self.cooldown, self.failure_backoff)
                if current_time - self.last_attempt < retry_delay:
                    self.log("Rotation attempt is rate-limited; coalescing this alert.", YELLOW)
                    return
                # Charge the attempt before invoking the orchestrator. Failed
                # subprocesses must not permit an immediate retry storm.
                self.last_attempt = current_time
            if current_time - self.last_rotation < self.cooldown:
                self.log("Detection alert received during cooldown; ignoring.", YELLOW)
                return
            self.log(f"!!! CRITICAL ALERT: {reason} !!!", RED)
            self.log("Initiating full network identity rotation (MTD)...", CYAN)
            # Construct command: python3 <orchestrator> apply -f <topo>
            cmd = [sys.executable, self.orchestrator_path, "apply", "-f", self.topo_path]
            
            # Run the orchestrator as a subprocess
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                cwd=os.path.dirname(self.orchestrator_path),
                check=False,
            )
            
            if result.returncode == 0:
                self.log("MTD Rotation successful. Fingerprints updated across all nodes.", GREEN)
                with self.state_lock:
                    self.last_rotation = current_time
                    self.failure_backoff = 0.0
            else:
                self.log(f"Orchestrator failed with exit status {result.returncode}.", RED)
                with self.state_lock:
                    self.failure_backoff = min(
                        max(self.cooldown, self.failure_backoff * 2 or self.cooldown),
                        self.cooldown * 8,
                    )
        except subprocess.TimeoutExpired:
            self.log("Orchestrator timed out after 120 seconds.", RED)
            with self.state_lock:
                self.failure_backoff = min(
                    max(self.cooldown, self.failure_backoff * 2 or self.cooldown),
                    self.cooldown * 8,
                )
        except Exception as e:
            self.log(f"Error during rotation execution: {e}", RED)
            with self.state_lock:
                self.failure_backoff = min(
                    max(self.cooldown, self.failure_backoff * 2 or self.cooldown),
                    self.cooldown * 8,
                )
        finally:
            self.rotation_lock.release()
            self.alert_pending.clear()

    @staticmethod
    def _alert_identity(reason):
        """Only bounded versioned detector events count toward global MTD."""
        marker = "SHADOW6_THREAT "
        if marker not in reason:
            return None
        try:
            def unique_fields(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate field")
                    result[key] = value
                return result

            event = json.loads(reason.split(marker, 1)[1], object_pairs_hook=unique_fields)
            if not isinstance(event, dict) or set(event) != {"version", "source", "port"}:
                return None
            if type(event["version"]) is not int or event["version"] != 1:
                return None
            if type(event["port"]) is not int or not 1 <= event["port"] <= 65535:
                return None
            if not isinstance(event["source"], str):
                return None
            address = ipaddress.ip_address(event["source"])
            if address.is_unspecified or address.is_multicast:
                return None
            return str(address), event["port"]
        except (ValueError, TypeError, RecursionError):
            return None

    def _allow_rotation(self, reason):
        """Apply a bounded threat score and token bucket before full MTD."""
        now = time.monotonic()
        identity = self._alert_identity(reason)
        if identity is None:
            return False
        with self.state_lock:
            cutoff = now - self.score_window
            self.alert_history = {
                key: seen for key, seen in self.alert_history.items() if seen > cutoff
            }
            # One vote per source/port pair per window, bounded under a flood.
            if identity not in self.alert_history and len(self.alert_history) >= 4096:
                return False
            self.alert_history.setdefault(identity, now)
            sources = {key[0] for key in self.alert_history}
            ports = {key[1] for key in self.alert_history}
            elapsed = now - self.last_token_refill
            if elapsed >= self.rotation_interval:
                self.rotation_tokens = 1
                self.last_token_refill = now
            if len(self.alert_history) < self.score_threshold or len(sources) < 3 or len(ports) < 3:
                return False
            if self.rotation_tokens < 1 or self.alert_pending.is_set():
                return False
            if now - self.last_attempt < max(self.cooldown, self.failure_backoff):
                return False
            self.rotation_tokens -= 1
            self.last_token_refill = now
            self.alert_history.clear()
            self.alert_pending.set()
            return True

    def attach_counterstrike(self, policy_path):
        """Opt in to the graduated active-defense engine from a policy file.

        With no policy the sentinel behaves exactly as before.  The engine's
        highest tier only *requests* rotation through schedule_rotation, which
        still enforces multi-source/port diversity and the rotation budget.
        """
        if CounterstrikePolicy is None:
            self.log("Counterstrike module unavailable; continuing with MTD only.", YELLOW)
            return
        policy = CounterstrikePolicy.load(policy_path)
        self.counterstrike = CounterstrikeEngine(policy, on_rotation=self.schedule_rotation)
        self.counterstrike.start()
        self.log(
            f"Counterstrike armed (decay={policy.attack_decay_seconds}s, "
            f"tiers={[name for name in ('deception', 'engagement', 'throttle', 'rotation') if policy.tier_enabled(name)]}).",
            CYAN,
        )

    def schedule_rotation(self, reason):
        """Aggregate alerts and coalesce bursts into one rotation worker."""
        reason = clean_output(reason)
        if not self._allow_rotation(reason):
            self.log("Detection recorded; threat threshold or rotation budget not met.", YELLOW)
            return
        threading.Thread(target=self.trigger_rotation, args=(reason,), daemon=True).start()

    def start_monitoring(self):
        """Starts the detector and monitors its output stream."""
        self.log(f"Starting Detector: {' '.join(self.detector_cmd)}", GREEN)
        
        # Merge stderr into stdout to catch all levels of alerts
        def signal_handler(sig, frame):
            self.log("Shutdown signal received. Terminating detector...", YELLOW)
            self.stop_event.set()
            if self.detector_proc:
                self.detector_proc.terminate()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        while not self.stop_event.is_set():
            self.detector_proc = subprocess.Popen(
                self.detector_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert self.detector_proc.stdout is not None
            while not self.stop_event.is_set():
                line = self.detector_proc.stdout.readline(4097)
                if not line:
                    break
                clean_line = clean_output(line)
                if not clean_line:
                    continue
                print(f"  [DETECTOR] {clean_line}")
                if self.counterstrike is not None and "SHADOW6_THREAT " in clean_line:
                    self.counterstrike.handle_event(clean_line)
                if "SHADOW6_THREAT " in clean_line or any(key in clean_line for key in ATTACK_KEYWORDS):
                    self.schedule_rotation(clean_line)
            return_code = self.detector_proc.wait()
            if self.stop_event.is_set():
                break
            self.log(f"Detector exited with status {return_code}; restarting in 5 seconds.", RED)
            self.stop_event.wait(5)

def main():
    parser = argparse.ArgumentParser(description="Shadow6 MTD Sentinel - Event-driven Defense Bridge")
    
    # Environment discovery to avoid hardcoding
    default_detector = os.path.join(os.path.dirname(__file__), "shadow6_detector.py")
    # An installed watcher lives in <prefix>/bin while the orchestrator ships in
    # the installed tree, so resolve the tree instead of walking "..".
    tree = _tree_root()
    default_orchestrator = os.path.join(tree, "Auto-Orchestrator", "shadow6_auto.py")

    parser.add_argument("--detector", default=default_detector, help="Path to the detector script")
    parser.add_argument("--auto", default=default_orchestrator, help="Path to the shadow6_auto.py script")
    parser.add_argument("--topo", required=True, help="Path to the topology YAML file")
    parser.add_argument("--cooldown", type=int, default=300, help="Minimum seconds between rotations (default: 300)")
    parser.add_argument("--score-threshold", type=int, default=3, help="Alerts required within the score window (default: 3)")
    parser.add_argument("--score-window", type=int, default=60, help="Threat score window in seconds (default: 60)")
    parser.add_argument("--rotation-interval", type=int, default=3600, help="One global rotation attempt per interval in seconds (default: 3600)")
    parser.add_argument("--interface", default="any", help="Sniffing interface")
    parser.add_argument("--model", default="dpi_model.json", help="Path to RF JSON or Neo LSTM model")
    parser.add_argument("--neo", action="store_true", help="Use the new experimental LSTM detector")
    parser.add_argument("--counterstrike-policy", default=None,
                        help="Path to a mode-0600 graduated active-defense policy JSON (opt-in)")

    args = parser.parse_args()

    # Determine which detector to run
    detector_script = args.detector
    if args.cooldown < 1:
        parser.error("--cooldown must be positive")
    if args.score_threshold < 3 or args.score_window < 1 or args.rotation_interval < args.cooldown:
        parser.error("threshold must be >=3, score window positive, rotation interval >= cooldown")
    for label, path in (("detector", args.detector), ("orchestrator", args.auto), ("topology", args.topo)):
        if not os.path.isfile(path):
            parser.error(f"{label} file does not exist: {path}")
    if args.counterstrike_policy is not None:
        if not os.path.isfile(args.counterstrike_policy):
            parser.error(f"counterstrike policy file does not exist: {args.counterstrike_policy}")

    if args.neo:
        # Check if new version exists in same dir
        neo_script = os.path.join(os.path.dirname(__file__), "shadow6_detector_neo.py")
        if os.path.exists(neo_script):
            detector_script = neo_script

    # Construct the command for the detector
    detector_cmd = [sys.executable, detector_script, "--detect", "--interface", args.interface]
    if args.neo:
        if not os.path.isfile(args.model):
            parser.error("--neo requires an existing --model file")
        detector_cmd.extend(["--model-path", args.model, "--model-type", "lstm"])
    elif os.path.isfile(args.model):
        detector_cmd.extend(["--model-path", args.model])
    
    sentinel = ShadowSentinel(
        detector_cmd=detector_cmd,
        orchestrator_path=os.path.abspath(args.auto),
        topo_path=os.path.abspath(args.topo),
        cooldown=args.cooldown,
        score_threshold=args.score_threshold,
        score_window=args.score_window,
        rotation_interval=args.rotation_interval,
    )

    if args.counterstrike_policy is not None:
        try:
            sentinel.attach_counterstrike(args.counterstrike_policy)
        except CounterstrikeError as exc:
            parser.error(f"invalid counterstrike policy: {exc}")
    try:
        sentinel.start_monitoring()
    finally:
        if sentinel.counterstrike is not None:
            sentinel.counterstrike.stop()

if __name__ == "__main__":
    main()
