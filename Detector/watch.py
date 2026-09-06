#!/usr/bin/env python3
"""
Shadow6 MTD Sentinel (watch.py)
--------------------------------------------------
Description:
    Bridges the Detection and Orchestration layers. 
    Monitors Detector logs (Standard RF or Neo LSTM) and triggers 
    an immediate MTD (Moving Target Defense) rotation upon 
    sensing active probing or sequence anomalies.

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
from datetime import datetime

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
    def __init__(self, detector_cmd, orchestrator_path, topo_path, cooldown):
        self.detector_cmd = detector_cmd
        self.orchestrator_path = orchestrator_path
        self.topo_path = topo_path
        self.cooldown = cooldown
        self.last_rotation = 0
        self.detector_proc = None
        self.rotation_lock = threading.Lock()
        self.alert_pending = threading.Event()
        self.stop_event = threading.Event()

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
                capture_output=True,
                text=True,
                timeout=120,
                cwd=os.path.dirname(self.orchestrator_path),
                check=False,
            )
            
            if result.returncode == 0:
                self.log("MTD Rotation successful. Fingerprints updated across all nodes.", GREEN)
                self.last_rotation = current_time
            else:
                detail = (result.stderr or result.stdout).strip()
                self.log(f"Orchestrator failed: {detail}", RED)
        except subprocess.TimeoutExpired:
            self.log("Orchestrator timed out after 120 seconds.", RED)
        except Exception as e:
            self.log(f"Error during rotation execution: {e}", RED)
        finally:
            self.rotation_lock.release()
            self.alert_pending.clear()

    def schedule_rotation(self, reason):
        """Coalesce bursts into at most one pending rotation worker."""
        if self.alert_pending.is_set():
            return
        self.alert_pending.set()
        threading.Thread(target=self.trigger_rotation, args=(clean_output(reason),), daemon=True).start()

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
                if any(key in clean_line for key in ATTACK_KEYWORDS):
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
    default_orchestrator = os.path.join(os.path.dirname(__file__), "..", "Auto-Orchestrator", "shadow6_auto.py")

    parser.add_argument("--detector", default=default_detector, help="Path to the detector script")
    parser.add_argument("--auto", default=default_orchestrator, help="Path to the shadow6_auto.py script")
    parser.add_argument("--topo", required=True, help="Path to the topology YAML file")
    parser.add_argument("--cooldown", type=int, default=300, help="Minimum seconds between rotations (default: 300)")
    parser.add_argument("--interface", default="any", help="Sniffing interface")
    parser.add_argument("--model", default="dpi_model.json", help="Path to RF JSON or Neo LSTM model")
    parser.add_argument("--neo", action="store_true", help="Use the new experimental LSTM detector")

    args = parser.parse_args()

    # Determine which detector to run
    detector_script = args.detector
    if args.cooldown < 1:
        parser.error("--cooldown must be positive")
    for label, path in (("detector", args.detector), ("orchestrator", args.auto), ("topology", args.topo)):
        if not os.path.isfile(path):
            parser.error(f"{label} file does not exist: {path}")

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
        cooldown=args.cooldown
    )

    sentinel.start_monitoring()

if __name__ == "__main__":
    main()
