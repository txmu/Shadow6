#!/usr/bin/env python3
"""Artifact-backed, Core-explicit Native Profile WAN/PCAP test entry point."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "Crosed"), str(ROOT / "Deployment"), str(ROOT / "Control-Center")]
from native_profiles import CORE_IDS, profile_digest, profiles, select_profile
from feature_contract import validate_feature_report
from service_runtime import feature_report
from service_storage import strict_json
from artifacts import (MANIFEST, create_manifest, fetch_artifacts, find_manifest,
                       load_fetch_provenance, locate_binary, locate_linux_idris_artifact,
                       merge_runtime_companions, sha256_file,
                       verify_inventory, write_manifest)
from fingerprint import analyze
from network import Namespace, SCENARIOS, capabilities as network_capabilities, symmetric_loopback_settings

SCHEMA = "shadow6.wan-pcap-test-report.v2"
DEFAULT_SCENARIOS = ("clean", "good-wan", "high-jitter", "failure-recovery")
MAX_REPORT_BYTES = 8 * 1024 * 1024


def _write_json(path: Path, value):
    data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Test Lab JSON report exceeds 8 MiB")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, timeout=3, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _profile_report(root: Path, profile: dict, binary: Path):
    result = {"core": profile["core"], "profile": profile["id"],
              "nativeTransport": profile["nativeTransport"],
              "applicationBoundary": profile["applicationBoundary"],
              "artifact": profile["artifact"], "artifactSha256": None,
              "profileDigest": profile_digest(profile), "availability": "BLOCKED",
              "featureReport": None, "runtimeRequirements": profile["requirements"],
              "reason": None}
    try:
        result["artifactSha256"] = "sha256:" + sha256_file(binary)
        report = feature_report(str(binary))
        validate_feature_report(report, "shadow6-" + profile["core"])
        if profile["applicationBoundary"] not in report["application_boundaries"]:
            raise ValueError("binary feature report does not declare selected application boundary")
        result["featureReport"] = report
        result["availability"] = "AVAILABLE"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["reason"] = f"{type(error).__name__}: {error}"
    return result


def _current_feature_report(profile: dict, binary: Path):
    return _profile_report(binary.parents[1], profile, binary)


def _check_os_requirement(profile, artifact_root: Path):
    unavailable = []
    if platform.system() != "Linux":
        unavailable.append("Native trio workload is currently implemented for Linux test hosts")
    for feature in profile["requirements"].get("kernelFeatures", []):
        if feature == "sctp":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP):
                    pass
            except OSError as error:
                unavailable.append(f"kernel SCTP unavailable: {error}")
    for library in profile["requirements"].get("libraries", []):
        if library == "libdatachannel":
            candidates = list((Path(artifact_root) / "Core-Nim").glob("libdatachannel.so*"))
            if not candidates:
                unavailable.append("registered Nim artifact is missing its ABI-matched libdatachannel runtime")
    if profile["core"] == "idris" and not shutil.which("chezscheme"):
        unavailable.append("Chez Scheme runtime (chezscheme) is required by the downloaded Idris launcher")
    return unavailable


class Capture:
    def __init__(self, output: Path, *, namespace: Namespace | None, interface='lo', snaplen=1600):
        if interface not in {'lo', 's6tl-a', 's6tl-b'} or type(snaplen) is not int or not 1600 <= snaplen <= 8192:
            raise ValueError('capture interface/snaplen outside owned Lab bounds')
        if namespace is None:
            raise ValueError('capture requires an owned namespace')
        self.output = output
        self.interface, self.snaplen = interface, snaplen
        self.namespace = namespace
        self.process = None
        self.stderr = None
        self.started_at = None
        self.ended_at = None
        self.reason = None
        self.process_identity = None
        self.namespace_identity = None
        self.capture_pid = None

    def start(self):
        import pwd
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            self.reason = "tcpdump not installed"
            return False
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.stderr = tempfile.TemporaryFile()
        argv = [tcpdump, '-Z', pwd.getpwuid(os.geteuid()).pw_name,
                '--immediate-mode', '-U', "-i", self.interface, "-nn", "-s", str(self.snaplen), "-C", "4", "-W", "1",
                "-w", str(self.output), "tcp or udp or sctp"]
        if self.namespace is not None:
            argv = self.namespace.exec(argv)
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=self.stderr, close_fds=True,
                start_new_session=(os.name == "posix"), umask=0o077)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    self.reason = self._error_text() or 'tcpdump exited during startup'
                    self.process = None
                    return False
                if 'listening on ' + self.interface in self._error_text():
                    from service_runtime import identity
                    self.capture_pid = self.process.pid
                    self.process_identity = identity(self.process.pid)
                    self.namespace_identity = os.readlink(f'/proc/{self.process.pid}/ns/net')
                    if not self.process_identity: raise ValueError('capture process identity unavailable')
                    expected_namespace = f'net:[{Path("/run/netns", self.namespace.name).stat().st_ino}]'
                    if self.namespace_identity != expected_namespace: raise ValueError('capture namespace ownership mismatch')
                    self.started_at = time.time()
                    return True
                time.sleep(.05)
            self.reason = 'tcpdump structured listening notification deadline'
            self.stop()
            return False
        except OSError as error:
            self.reason = f"{type(error).__name__}: {error}"
            return False

    def _error_text(self):
        if self.stderr is None:
            return ""
        self.stderr.seek(0)
        return self.stderr.read(2048).decode("utf-8", "replace").strip()

    def stop(self):
        if self.process is not None:
            try:
                self.process.send_signal(signal.SIGINT)
                self.process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=2)
            self.ended_at = time.time()
            if self.process.returncode not in (0, -signal.SIGINT):
                self.reason = self._error_text() or f"tcpdump exit {self.process.returncode}"
            self.process = None
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None
        candidates = [self.output, self.output.with_name(self.output.name + ".1")]
        captured = next((item for item in candidates if item.is_file() and not item.is_symlink()), None)
        if captured is None:
            return None
        if captured.stat().st_size > 4 * 1024 * 1024:
            captured.unlink()
            self.reason = "capture exceeded 4 MiB rotation bound and was removed"
            return None
        return captured


def _worker(profile: dict, binary: Path, *, payload_bytes: int, requests: int,
            namespace: Namespace | None, timeout: int = 90, rtt_ms: int = 0, on_ready=None, target_port=None):
    argv = [sys.executable, str(HERE / "worker.py"), "--core", profile["core"],
            "--profile", profile["id"], "--binary", str(binary),
            "--payload-bytes", str(payload_bytes), "--requests", str(requests), "--rtt-ms", str(rtt_ms)]
    if target_port is not None:
        if type(target_port) is not int or not 1 <= target_port <= 65535:
            raise ValueError('invalid owned carrier attachment port')
        argv.extend(['--target-port', str(target_port)])
    if namespace is not None:
        source_owner = ROOT.stat()
        if os.geteuid() == 0 and source_owner.st_uid != 0:
            argv = ['/usr/bin/setpriv', '--reuid', str(source_owner.st_uid),
                    '--regid', str(source_owner.st_gid), '--init-groups', *argv]
        argv = namespace.exec(argv)
    output = bytearray()
    pending = bytearray()
    ready_seen = False
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=errors,
            stdin=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise subprocess.TimeoutExpired(argv, timeout)
                readable, _, _ = select.select([process.stdout], [], [], min(remaining, 0.25))
                if not readable: continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk: break
                output.extend(chunk); pending.extend(chunk)
                if len(output) > 1024 * 1024: raise ValueError('worker output exceeds 1 MiB')
                while b'\n' in pending:
                    line, _, rest = pending.partition(b'\n'); pending = bytearray(rest)
                    if line.startswith(b'{'):
                        event = strict_json(line, allow_measurement_floats=True)
                        if event.get('event') == 'shadow6.test-lab-workload-ready.v1':
                            if (ready_seen or set(event) != {'event', 'core', 'profile'} or
                                    event['core'] != profile['core'] or event['profile'] != profile['id']):
                                raise ValueError('invalid/duplicate worker readiness event')
                            ready_seen = True
                            if on_ready is not None: on_ready()
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=3)
            process.stdout.close()
        errors.seek(0, os.SEEK_END)
        errors.seek(max(0, errors.tell() - 4096))
        stderr = errors.read(4096).decode('utf-8', 'replace')
    stdout = output.decode("utf-8", "replace")
    last = next((line for line in reversed(stdout.splitlines()) if line.startswith("{")), None)
    if last is None:
        return {"status": "FAIL", "core": profile["core"], "profile": profile["id"],
                "reason": f"worker exited {process.returncode} without structured result: {stderr}"}
    try:
        value = strict_json(last, allow_measurement_floats=True)
    except ValueError as error:
        return {"status": "FAIL", "core": profile["core"], "profile": profile["id"],
                "reason": f"worker returned invalid JSON: {error}"}
    if process.returncode and value.get("status") != "FAIL":
        value["status"] = "FAIL"
        value["reason"] = f"worker exit {process.returncode}"
    if value.get('status') == 'PASS' and not ready_seen:
        raise ValueError('worker PASS lacks a structured workload readiness event')
    return value


def _scenario_case(profile, binary, scenario, output_dir, run_id, *, capture_enabled,
                   payload_bytes, requests):
    spec = SCENARIOS[scenario]
    row = {"core": profile["core"], "profile": profile["id"],
           "nativeTransport": profile["nativeTransport"],
           "applicationBoundary": profile["applicationBoundary"],
           "adapter": None, "carrier": "native", "scenario": scenario,
           "networkKind": "local" if spec["kind"] == "local" else "simulated",
           "status": "BLOCKED", "correctness": None, "metrics": None,
            "runtimeObservation": {"status": "unavailable", "reason": "Named Service lifecycle has not completed"},
           "capture": {"status": "not-requested", "pcap": None}, "fingerprint": None,
           "wireClassification": ["unknown/custom"], "reason": None}
    namespace = None
    if scenario != "clean" or capture_enabled:
        try:
            namespace = Namespace().create()
        except (PermissionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
            if scenario != "clean":
                row["reason"] = f"simulated WAN requires isolated Linux network namespace: {type(error).__name__}: {error}"
                row["status"] = "BLOCKED"
                if capture_enabled:
                    row["capture"] = {"status": "SKIP", "reason": row["reason"], "pcap": None}
                return row
            namespace = None
    if capture_enabled and namespace is None:
        row["capture"] = {"status": "SKIP", "reason": "PCAP is restricted to an isolated test namespace; host-interface capture is disabled", "pcap": None}
    capture = None
    captured = None
    worker_result = None
    phase_errors = []
    phase_threads = []
    effective_impairments = []
    phase_start = time.monotonic()
    try:
        if scenario not in ("clean", "failure-recovery"):
            settings = symmetric_loopback_settings(spec["a_to_b"], spec["b_to_a"])
            namespace.apply(settings)
            effective_impairments.append({"stage": "steady", "settings": settings,
                "appliedAtElapsedSeconds": 0.0,
                "directionality": "single-loopback conservative symmetric approximation"})
        elif scenario == "failure-recovery":
            settings = symmetric_loopback_settings(spec["phases"][0]["a_to_b"], spec["phases"][0]["b_to_a"])
            namespace.apply(settings)
            effective_impairments.append({"stage": "baseline", "settings": settings,
                "appliedAtElapsedSeconds": 0.0,
                "directionality": "single-loopback conservative symmetric approximation"})
        if capture_enabled and namespace is not None:
            capture_path = output_dir / "pcap" / profile["core"] / profile["id"] / f"{scenario}.pcap"
            capture = Capture(capture_path, namespace=namespace)
            started = capture.start()
            row["capture"] = {"status": "RUNNING" if started else "SKIP",
                "reason": capture.reason, "pcap": None,
                "interface": "lo", "namespace": namespace.name}
        def on_workload_ready():
            nonlocal phase_start
            if scenario != 'failure-recovery' or namespace is None: return
            phase_start = time.monotonic()
            def change_after(delay, stage, settings):
                time.sleep(delay)
                try:
                    namespace.apply(settings)
                    effective_impairments.append({"stage": stage, "settings": settings,
                        "appliedAtElapsedSeconds": round(time.monotonic() - phase_start, 6),
                        "directionality": "single-loopback conservative symmetric approximation"})
                except Exception as error:
                    phase_errors.append(f"{type(error).__name__}: {error}")
            for delay, stage, phase in ((spec['phases'][0]['seconds'], "degraded", spec["phases"][1]),
                                        (spec['phases'][0]['seconds'] + spec['phases'][1]['seconds'], "restored", spec["phases"][2])):
                settings = symmetric_loopback_settings(phase["a_to_b"], phase["b_to_a"])
                thread = threading.Thread(target=change_after,
                    args=(delay, stage, settings), daemon=True)
                thread.start(); phase_threads.append(thread)
        started_at = time.time()
        workload_requests = max(requests, 12) if scenario == "failure-recovery" else requests
        worker_result = _worker(profile, binary, payload_bytes=payload_bytes,
                                 requests=workload_requests, namespace=namespace,
                                 rtt_ms=250 if scenario == "failure-recovery" else 0,
                                 on_ready=on_workload_ready)
        row["durationSeconds"] = round(time.time() - started_at, 6)
        row["status"] = worker_result.get("status", "FAIL")
        row["correctness"] = worker_result.get("correctness")
        row["metrics"] = worker_result.get("metrics")
        row['runtimeObservation'] = worker_result.get('runtimeObservation')
        row['applicationGame'] = worker_result.get('applicationGame')
        row["reason"] = worker_result.get("reason")
        row["workload"] = "stream-or-message contract selected by Native Profile; exact echo comparison"
    except subprocess.TimeoutExpired:
        row.update(status="FAIL", reason="bounded native workload timed out")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        row.update(status="FAIL", reason=f"{type(error).__name__}: {error}")
    finally:
        for thread in phase_threads:
            thread.join(timeout=3)
        if capture is not None:
            captured = capture.stop()
        if namespace is not None:
            namespace.close()
    if effective_impairments:
        row["effectiveImpairments"] = effective_impairments
    if scenario == "failure-recovery":
        applied = {item["stage"] for item in effective_impairments}
        complete = {"baseline", "degraded", "restored"}.issubset(applied) and not phase_errors
        row["failureInjection"] = {"status": "applied" if complete else "incomplete",
            "requestedPhases": ["baseline impairment", "bounded increased delay", "restored baseline"],
            "appliedPhaseCount": len(effective_impairments),
            "phaseErrors": phase_errors,
            "reconnectClaim": "not inferred; each scenario creates a fresh ephemeral trio"}
        if not complete and row.get("status") == "PASS":
            row["status"] = "FAIL"
            row["reason"] = "failure/recovery impairment phases did not all apply"
    if captured is not None:
        metadata = {"schema": "shadow6.test-lab-capture.v1", "runId": run_id,
            "core": profile["core"], "profile": profile["id"],
            "linkType": "native", "scenario": scenario,
            "startedAtUnix": capture.started_at, "endedAtUnix": capture.ended_at,
            "interface": "lo", "namespace": row["capture"].get("namespace"),
            "file": captured.name, "bytes": captured.stat().st_size,
            "sha256": hashlib.sha256(captured.read_bytes()).hexdigest(),
            "secretBearingConfigsUploaded": False}
        _write_json(captured.with_suffix(".capture.json"), metadata)
        row["capture"] = {**row["capture"], "status": "PASS", "pcap": str(captured),
                           "metadata": str(captured.with_suffix(".capture.json")),
                           "bytes": captured.stat().st_size, "sha256": metadata["sha256"]}
        try:
            fingerprint = analyze(captured, run_id=run_id, core=profile["core"],
                profile=profile["id"], link_type="native", scenario=scenario)
            fingerprint_path = captured.with_suffix(".fingerprint.json")
            _write_json(fingerprint_path, fingerprint)
            row["fingerprint"] = str(fingerprint_path)
            row["wireClassification"] = fingerprint["classification"]["observed"]
            row["leakScan"] = fingerprint["leakScan"]
        except (OSError, ValueError) as error:
            row["capture"]["analysisStatus"] = "FAIL"
            row["capture"]["analysisReason"] = f"{type(error).__name__}: {error}"
            row["status"] = "FAIL"
            row["reason"] = "captured PCAP could not be analyzed: " + row["capture"]["analysisReason"]
    elif capture_enabled and row["capture"]["status"] == "RUNNING":
        row["capture"]["status"] = "FAIL"
        row["capture"]["reason"] = capture.reason if capture else "capture output unavailable"
    if capture_enabled and row['status'] == 'PASS' and row['capture']['status'] != 'PASS':
        row.update(status='BLOCKED', reason=row['capture'].get('reason') or
                   'requested namespace PCAP evidence is unavailable')
    return row


def _selected_profiles(args):
    available = profiles()
    if args.profile:
        selected = []
        for item in args.profile:
            matches = [profile for profile in available if profile["id"] == item]
            if not matches:
                raise ValueError(f"unknown Native Profile: {item}")
            selected.extend(matches)
    elif args.core:
        selected = [profile for profile in available if profile["core"] in set(args.core)]
    else:
        selected = list(available if args.all_profiles else [p for p in available if p["primary"]])
    if args.all_cores:
        selected = [p for p in available if p["primary"]]
    if args.all_profiles:
        selected = list(available)
    if args.core:
        unknown = set(args.core) - set(CORE_IDS)
        if unknown:
            raise ValueError("unknown Core: " + ", ".join(sorted(unknown)))
        if args.all_profiles:
            selected = [p for p in selected if p["core"] in set(args.core)]
        elif args.profile:
            selected = [p for p in selected if p["core"] in set(args.core)]
    unique = {(p["core"], p["id"]): p for p in selected}
    return list(unique.values())


def _s6epe_matrix(availability=()):
    from privacy_envelope import compatibility
    result = []
    installed = {(row['core'], row['profile']): row for row in availability}
    for profile in profiles():
        mapping = compatibility(profile["core"])
        for carrier in mapping["carriers"]:
            artifact = installed.get((profile['core'], profile['id']), {})
            result.append({"core": profile["core"], "profile": profile["id"],
                'profileDigest': profile_digest(profile),
                'nativeTransport': profile['nativeTransport'],
                'applicationBoundary': profile['applicationBoundary'],
                "mode": mapping["mode"], "carrier": carrier,
                "legal": True, "status": "source-legal",
                'stages': {'sourceLegal': {'status': 'source-legal', 'authority': 'Control-Center/privacy_envelope.py'},
                    'nativeArtifact': {'status': artifact.get('availability', 'ARTIFACT-UNBOUND'),
                        'sha256': artifact.get('artifactSha256'), 'reason': artifact.get('reason')},
                    **{stage: {'status': 'BLOCKED', 'reason': 'source mapping contains no runtime evidence'}
                       for stage in ('carrierArtifact', 'runtimeReady', 'correctness', 'WAN', 'PCAP', 'wireClassification', 'leakScan')}},
                "evidence": mapping["evidence"], "reason": "source-only compatibility query; execute the endpoint matrix for runtime evidence"})
    return result


def _core_coverage(selected, rows, inventory):
    primary_rows = {row["core"]: row for row in rows if row.get("profile") == select_profile(row["core"])["id"]}
    inventory_by_core = {row["core"]: row for row in inventory["cores"]}
    cores = []
    for core in CORE_IDS:
        profile = select_profile(core)
        found = [row for row in rows if row.get("core") == core and row.get("profile") == profile["id"]]
        tests_ran = [row for row in found if row.get("scenario") == "clean" and
                     (row.get('correctness') or {}).get('status') in {'PASS', 'FAIL'}]
        scenario_fail = any(row.get("status") == "FAIL" for row in found)
        expected_scenarios = {row.get("scenario") for row in found}
        blocked = any(row.get("status") == "BLOCKED" for row in found)
        skipped = any(row.get("status") == "SKIP" for row in found)
        if scenario_fail:
            status = "FAIL"
        elif blocked:
            status = "BLOCKED"
        elif not tests_ran:
            status = "BLOCKED" if inventory_by_core.get(core, {}).get("available") is False else "SKIP"
        elif skipped:
            status = "SKIP"
        else:
            status = "PASS"
        cores.append({"core": core, "profile": profile["id"],
            "nativeTransport": profile["nativeTransport"],
            "applicationBoundary": profile["applicationBoundary"],
            "artifact": inventory_by_core.get(core), "status": status,
            "executed": bool(tests_ran), "scenarioCount": len(expected_scenarios),
            "testResult": [row.get("status") for row in found],
            "pcapResult": [row.get("capture", {}).get("status") for row in found],
            "wireClassification": [label for row in found for label in row.get("wireClassification", [])],
            "correctness": [row.get("correctness") for row in found if row.get("correctness")],
            "wanScenarios": sorted(expected_scenarios - {"clean"})})
    counts = {status: sum(item["status"] == status for item in cores)
              for status in ("PASS", "FAIL", "SKIP", "BLOCKED")}
    executed = sum(item["executed"] for item in cores)
    return {"denominator": len(CORE_IDS), "executed": executed,
            "counts": counts, "cores": cores}


def _render_markdown(report):
    coverage = report["nativeCoreCoverage"]
    c = coverage["counts"]
    lines = ["# WAN/PCAP Test Report", "",
        f"**Native Core coverage: {coverage['executed']}/12 executed, {c['PASS']} PASS, {c['FAIL']} FAIL, {c['SKIP']} SKIP, {c['BLOCKED']} BLOCKED.**", "",
        f"Run `{report['runId']}` · source commit `{report['environment']['sourceCommit']}` · artifact commit `{report['environment']['artifact']['commit'] or 'unknown'}`.", "",
        f"Network environment: {report['environment']['networkMode']}. Simulated netem measurements are not real WAN measurements.", "",
        "| Core | Profile | Native transport | Application boundary | Artifact | Result | PCAP | Wire classification | Correctness | WAN scenario |",
        "|---|---|---|---|---|---|---|---|---|---|"]
    for row in coverage["cores"]:
        artifact = row.get("artifact") or {}
        pcap = ", ".join(sorted({x for x in row["pcapResult"] if x})) or "not-run"
        wire = ", ".join(sorted(set(row["wireClassification"]))) or "unknown/custom"
        correct = "PASS" if row["correctness"] and all(x.get("status") == "PASS" for x in row["correctness"]) else "unavailable"
        lines.append(f"| {row['core']} | {row['profile']} | {row['nativeTransport']} | {row['applicationBoundary']['kind']}/{row['applicationBoundary']['mode']} | {artifact.get('integrity', 'missing')} | {row['status']} | {pcap} | {wire} | {correct} | {', '.join(row['wanScenarios']) or 'none'} |")
    lines += ['', '## Profile artifact admission', '',
        '| Core/Profile | Artifact status | Profile digest | Runtime requirements |',
        '|---|---|---|---|']
    for row in report['profileAvailability']:
        lines.append(f"| {row['core']}/{row['profile']} | {row['availability']} | `{row['profileDigest']}` | {row.get('reason') or 'declared prerequisites satisfied; runtime execution is separate'} |")
    lines += ["", "## Scenario rows", "", "| Core/Profile | Scenario | Network kind | Result | PCAP | Detail |", "|---|---|---|---|---|---|"]
    for row in report["results"]:
        lines.append(f"| {row.get('core')}/{row.get('profile')} | {row.get('scenario')} | {row.get('networkKind')} | {row.get('status')} | {row.get('capture',{}).get('status')} | {(row.get('reason') or '')[:220]} |")
    lines += ["", "## S6EPE endpoint matrix", "", "Legal combinations come from Control Center; runtime status requires actual endpoints, application correctness and dual carrier PCAP. Placement is after the real Native Agent application target; native Core control/data sockets remain private in A.", "", "| Core/Profile | Mode | Legal carrier | Status |", "|---|---|---|---|"]
    for row in report["s6epeCompatibility"]:
        lines.append(f"| {row['core']}/{row['profile']} | {row['mode']} | {row['carrier']} | {row['status']} |")
    lines += ['', '| Core/Profile/Carrier | Scenario | Runtime | Correctness | WAN | PCAP | Wire | Leak scan | Result |',
              '|---|---|---|---|---|---|---|---|---|']
    for row in report['s6epeCompatibility']:
        for result in row.get('results', []):
            stages = result['stages']
            lines.append('| ' + '/'.join((row['core'], row['profile'], row['carrier'])) + ' | ' + result['scenario'] + ' | ' +
                ' | '.join(stages[stage]['status'] for stage in ('runtimeReady', 'correctness', 'WAN', 'PCAP', 'wireClassification', 'leakScan')) +
                ' | ' + result['status'] + ' |')
    lines += ["", "Runtime observations come from the locked Named Service lifecycle. Process liveness is not treated as application readiness.", ""]
    if report.get('limitations'):
        lines += ['## Limitations', ''] + ['- ' + item for item in report['limitations']] + ['']
    return "\n".join(lines)


def run(args):
    selected = _selected_profiles(args)
    artifact_provenance = {"source": "local", "runId": None, "commit": args.commit,
                           "artifact": None, "artifactDigest": None}
    artifact_root = args.artifacts_dir or ROOT
    if args.fetch_artifacts:
        destination = args.download_dir or ROOT / ".tmp" / "test-lab-artifacts" / (args.run_id or "latest-" + uuid.uuid4().hex[:8])
        artifact_provenance = fetch_artifacts(destination, run_id=args.run_id,
                                               commit=args.commit, tag=args.tag)
        artifact_root = destination
    elif args.companion_artifacts_dir:
        companion_root = args.companion_artifacts_dir
        idris_companion = locate_linux_idris_artifact(companion_root)
        missing = merge_runtime_companions(artifact_root,
            idris_artifact=idris_companion,
            s6epe_artifact=companion_root / "shadow6-s6epe-linux-runtime")
        artifact_provenance["companions"] = {
            "directory": str(companion_root), "missing": missing,
            "idrisArtifact": idris_companion.name,
            "idrisRuntimeSha256": ("sha256:" + sha256_file(idris_companion / "core-idris-runtime.tar.gz")
                if (idris_companion / "core-idris-runtime.tar.gz").is_file() else None),
            "s6epeDatachannelSha256": ("sha256:" + sha256_file(companion_root / "shadow6-s6epe-linux-runtime" / "lib" / "libdatachannel.so.0.23")
                if (companion_root / "shadow6-s6epe-linux-runtime" / "lib" / "libdatachannel.so.0.23").is_file() else None)}
    fetch_provenance_path = artifact_root / "shadow6-test-lab-fetch-provenance.json"
    fetch_provenance = load_fetch_provenance(artifact_root) if fetch_provenance_path.is_file() else None
    if fetch_provenance is not None:
        artifact_provenance.update({"source": "github-actions", "repository": fetch_provenance["repository"],
            "runId": fetch_provenance["runId"], "commit": fetch_provenance["commit"],
            "artifacts": fetch_provenance["artifacts"], "missingArtifacts": fetch_provenance["missingArtifacts"],
            "binaries": fetch_provenance["binaries"], "runtimeFiles": fetch_provenance["runtimeFiles"],
            "fetchProvenance": str(fetch_provenance_path)})
    if platform.system() == "Linux":
        runtime_paths = [artifact_root / "Core-Nim", artifact_root / "Core-Idris",
                         artifact_root / "Core-Idris" / "shadow6-idris_app",
                         artifact_root / "Core-Idris" / "ffi"]
        existing = [str(path) for path in runtime_paths if path.is_dir()]
        if existing:
            existing.extend(os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep))
            os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(path for path in existing if path)
    manifest_path = find_manifest(artifact_root)
    inventory = verify_inventory(artifact_root, manifest_path=manifest_path,
        expected_commit=(fetch_provenance["commit"] if fetch_provenance else args.commit),
        expected_workflow=args.workflow,
        expected_run_id=fetch_provenance['runId'] if fetch_provenance else os.environ.get('GITHUB_RUN_ID'),
        expected_run_attempt=args.run_attempt if fetch_provenance else os.environ.get('GITHUB_RUN_ATTEMPT'),
        expected_platform='macos' if platform.system() == 'Darwin' else platform.system().lower(),
        expected_architecture=platform.machine())
    if fetch_provenance is not None and not inventory["manifest"]:
        for row in inventory["cores"]:
            if row["available"]:
                row["integrity"] = "github-artifact-and-file-digest-verified"
    if inventory["manifest"]:
        manifest = inventory["manifest"]
        artifact_provenance.update({"manifest": str(manifest_path), "runId": manifest.get("runId"),
            "commit": manifest.get("commit"), "artifact": "shadow6-linux-release"})
    if args.fetch_artifacts:
        inventory = verify_inventory(artifact_root, manifest_path=find_manifest(artifact_root),
                                     expected_commit=artifact_provenance["commit"])
        if fetch_provenance is not None and not inventory["manifest"]:
            for row in inventory["cores"]:
                if row["available"]:
                    row["integrity"] = "github-artifact-and-file-digest-verified"
    feature_rows = []
    by_profile = {}
    admitted_cores = {row['core']: row for row in inventory['cores']}
    for profile in profiles():
        binary = locate_binary(artifact_root, profile)
        if binary is None:
            item = {"core": profile["core"], "profile": profile["id"],
                    "nativeTransport": profile["nativeTransport"],
                    "applicationBoundary": profile["applicationBoundary"],
                    "artifact": profile["artifact"], "profileDigest": profile_digest(profile),
                    "availability": "BLOCKED", "reason": "artifact unavailable"}
        else:
            item = _current_feature_report(profile, binary)
            if not admitted_cores[profile['core']]['available']:
                item.update(availability='BLOCKED', reason='release artifact inventory integrity admission failed')
            requirements = _check_os_requirement(profile, artifact_root) if item["availability"] == "AVAILABLE" else []
            if requirements:
                item["availability"] = "BLOCKED"
                item["reason"] = "; ".join(requirements)
        feature_rows.append(item)
        by_profile[(profile["core"], profile["id"])] = (binary, item)
    if args.check:
        from s6epe import matrix
        carrier_preflight = matrix(feature_rows, by_profile, artifact_root, args.scenario or ['clean'],
            Path('.'), args.run_id or 'check', payload_bytes=args.payload_bytes, requests=args.requests, execute=False)
        caps = network_capabilities()
        requested_scenarios = args.scenario or ['clean']
        environment_requirements = []
        if not caps['netnsNetem']:
            environment_requirements.append(caps['reason'])
        if not caps['namespaceCapture']:
            environment_requirements.append('namespace capture requires ip/tc, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_NET_RAW and tcpdump')
        environment_requirements.extend(row['core'] + '/' + row['profile'] + '/' + row['carrier'] + ': ' + row.get('reason', '')
            for row in carrier_preflight if row['status'] == 'BLOCKED')
        return {"schema": SCHEMA, "runId": args.run_id or "check-" + uuid.uuid4().hex[:12],
            "environment": {"sourceCommit": _git_commit(), "artifact": artifact_provenance,
                "platform": platform.platform(), "machine": platform.machine(),
                "networkMode": "capability-check-only", "networkTools": network_capabilities(),
                "captureTools": {name: shutil.which(name) for name in ("tcpdump", "dumpcap", "tshark", "zeek", "ndpiReader")}},
            'preflight': {'status': 'BLOCKED' if environment_requirements else 'READY',
                'reasons': environment_requirements, 'scenarios': requested_scenarios,
                'captureRequested': True, 'runtimeExecutionVerified': False},
            "inventory": inventory, "profileAvailability": feature_rows,
            "nativeCoreCoverage": _core_coverage(selected, [], inventory),
            "results": [], "s6epeCompatibility": carrier_preflight,
            "notes": ["--check does not start Core processes or alter networking."]}
    scenarios = args.scenario or ["clean"]
    output_dir = args.output_dir or ROOT / ".tmp" / "wan-pcap" / (args.run_id or uuid.uuid4().hex[:16])
    run_id = args.run_id or uuid.uuid4().hex
    results = []
    for profile in ([] if args.s6epe_only else selected):
        binary, availability = by_profile[(profile["core"], profile["id"])]
        for scenario in scenarios:
            if availability["availability"] != "AVAILABLE" or binary is None:
                results.append({"core": profile["core"], "profile": profile["id"],
                    "nativeTransport": profile["nativeTransport"],
                    "applicationBoundary": profile["applicationBoundary"],
                    "scenario": scenario, "networkKind": SCENARIOS[scenario]["kind"],
                    "status": "BLOCKED", "reason": availability.get("reason") or "artifact or runtime dependency unavailable",
                    "capture": {"status": "SKIP", "reason": "native binary cannot be executed", "pcap": None}})
                continue
            from native_pair import case as native_pair_case
            results.append(native_pair_case(profile, binary, scenario, output_dir, run_id,
                capture_enabled=args.capture, payload_bytes=args.payload_bytes,
                requests=args.requests))
    from s6epe import matrix
    carrier_rows = matrix(feature_rows, by_profile, artifact_root, args.s6epe_scenario or scenarios,
        output_dir, run_id, payload_bytes=args.payload_bytes, requests=args.requests,
        selected={(p['core'], p['id']) for p in selected} if args.core or args.profile else None)
    report = {"schema": SCHEMA, "runId": run_id,
        "environment": {"sourceCommit": _git_commit(), "artifact": artifact_provenance,
            "platform": platform.platform(), "machine": platform.machine(),
            "networkMode": "simulated directional NamespacePair/veth",
            "networkTools": network_capabilities(),
            "captureTools": {name: shutil.which(name) for name in ("tcpdump", "dumpcap", "tshark", "zeek", "ndpiReader")},
            "scenarios": scenarios, "endpointLabels": {"A": "complete private Native Core trio and Agent-target attachment", "B": "owned WAN application target / S6EPE endpoint"}},
        "inventory": inventory, "profileAvailability": feature_rows,
        "nativeCoreCoverage": _core_coverage(selected, results, inventory),
        "results": results, "s6epeCompatibility": carrier_rows,
        "s6epeCoverage": {"denominator": len(carrier_rows), "counts": {
            status: sum(row['status'] == status for row in carrier_rows) for status in ('PASS', 'FAIL', 'BLOCKED', 'SKIP')}},
            "limitations": ["This runner uses ephemeral Named Services and the existing locked supervisor and Profile application attachment APIs.",
            "Native and S6EPE executions use directional NamespacePair/veth impairment. Native trio sockets remain private in A; the WAN hop is the Agent application target. Core wire fingerprint is taken from inner-A, not the application WAN hop.",
            "Failure/recovery phases change qdisc while each scenario uses a fresh trio; native reconnect/migration is not inferred.",
            "S6EPE runs after the real Native Agent application target using explicit bounded Lab attachments. This verifies business traffic through the carrier, not native Core wire camouflage or production adapter availability.",
            "S6EPE veth WAN is directional and simulated. Physical cross-host/Internet WAN requires remote endpoint execution.",
            "Remote SSH endpoints, Android device orchestration and remote PCAP remain unavailable."]}
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "report.json", report)
    (output_dir / "SUMMARY.md").write_text(_render_markdown(report), encoding="utf-8")
    return report


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all-cores", action="store_true", help="run each Core's primary Native Profile")
    group.add_argument("--all-profiles", action="store_true", help="run all Profiles registered in Native Profile Registry")
    group.add_argument("--list-profiles", action="store_true")
    group.add_argument("--list-scenarios", action="store_true")
    group.add_argument("--write-manifest", action="store_true", help="write a CI binary artifact manifest")
    parser.add_argument("--core", action="append", choices=CORE_IDS)
    parser.add_argument("--profile", action="append")
    parser.add_argument("--scenario", action="append", choices=tuple(SCENARIOS))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--s6epe-only", action="store_true", help="execute all sixteen carrier combinations without the separate native baseline matrix")
    parser.add_argument("--s6epe-scenario", action="append", choices=tuple(SCENARIOS), help="explicit carrier scenarios; defaults to the requested native scenarios")
    parser.add_argument("--fetch-artifacts", action="store_true")
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--companion-artifacts-dir", type=Path,
                        help="same-run Idris and S6EPE runtime artifacts downloaded by CI")
    parser.add_argument("--download-dir", type=Path)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--run-id")
    source.add_argument("--commit")
    source.add_argument("--tag")
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--requests", type=int, default=4)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--manifest-output", type=Path)
    parser.add_argument("--run-attempt")
    parser.add_argument("--workflow", default="multiplatform")
    parser.add_argument("--platform", default="linux")
    parser.add_argument("--architecture")
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.list_profiles:
        print(json.dumps({"schema": "shadow6.test-lab-profile-list.v1", "profiles": profiles()}, sort_keys=True, indent=2))
        return 0
    if args.list_scenarios:
        print(json.dumps({"schema": "shadow6.test-lab-scenario-list.v1", "scenarios": SCENARIOS}, sort_keys=True, indent=2))
        return 0
    if args.write_manifest:
        output = args.manifest_output or (args.artifacts_dir or ROOT) / MANIFEST
        value = write_manifest(args.artifacts_dir or ROOT, output,
            run_id=os.environ.get("GITHUB_RUN_ID"), run_attempt=args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT"),
            commit=args.commit or os.environ.get("GITHUB_SHA"), workflow=args.workflow,
            platform=args.platform, architecture=args.architecture)
        print(json.dumps({"schema": value["schema"], "commit": value["commit"],
            "files": len(value["files"]), "output": str(output)}, sort_keys=True))
        return 0
    if args.payload_bytes < 1 or args.payload_bytes > 65536 or args.requests < 1 or args.requests > 100:
        parser.error("bounded workload requires payload 1..65536 bytes and requests 1..100")
    if args.fetch_artifacts and args.artifacts_dir:
        parser.error("use either --fetch-artifacts or --artifacts-dir")
    if args.fetch_artifacts and args.companion_artifacts_dir:
        parser.error("GitHub artifact fetch already downloads registered runtime companions")
    if not args.check and args.core is None and args.profile is None and not args.all_profiles:
        args.all_cores = True
    try:
        result = run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "error", "error": f"{type(error).__name__}: {error}"}, indent=2))
        return 2
    if args.check:
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result['preflight']['status'] == 'READY' and result["inventory"]["available"] == result["inventory"]["denominator"] and all(
            row["availability"] == "AVAILABLE" for row in result["profileAvailability"] if row.get("core") in CORE_IDS) else 1
    print(_render_markdown(result))
    print(f"JSON: {args.output_dir or ROOT / '.tmp' / 'wan-pcap' / result['runId']}/report.json")
    return 0 if not any(row.get('status') in {'FAIL', 'BLOCKED'} for row in
        result['results'] + result['s6epeCompatibility']) else 1


if __name__ == "__main__":
    raise SystemExit(main())
