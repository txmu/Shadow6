"""Replay the exact Zig/raw WAN evidence gate using existing Actions products.

The controller checkout and binary provenance are recorded separately. Native
and envelope binaries must share their original run/commit/attempt passports.
"""
import argparse
from pathlib import Path
import subprocess
import uuid

from shadow6_test_lab import ROOT, _write_json, _current_feature_report, _scenario_case
from artifacts import verify_inventory, merge_runtime_companions, admit_s6epe_runtime, sha256_file
from profile_registry import select_profile
from service_runtime import feature_report
from privacy_envelope import feature_availability
from s6epe import RawCarrier, TLSCarrier, case


def evidence_errors(row, *, expected_loss=False):
    errors = []
    for stage in ('PCAP', 'wireClassification', 'leakScan'):
        if row.get('stages', {}).get(stage, {}).get('status') != 'PASS': errors.append(stage)
    if row.get('noBypass', {}).get('status') != 'PASS': errors.append('noBypass')
    if expected_loss:
        injection = row.get('faultInjection', {})
        if injection.get('status') != 'PASS' or injection.get('observedDroppedPackets') != '1': errors.append('firstDrop')
        correctness = row.get('stages', {}).get('correctness', {})
        if row.get('status') != 'FAIL' or correctness.get('status') != 'FAIL': errors.append('lostBytesMustFail')
        if not any(marker in (correctness.get('reason') or '') for marker in ('TimeoutError:', 'EOFError:')):
            errors.append('unexpectedWorkloadFailure')
    elif row.get('status') != 'PASS': errors.append('correctness')
    return errors


def reproduce(args):
    output = args.output_dir; output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'shadow6.wan-evidence-repro.v1', 'status': 'BLOCKED',
        'controllerCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
            text=True, timeout=5).strip(), 'profile': args.profile, 'carrier': 'tls' if args.profile == 'gleam-micro-mux' else 'raw',
        'results': [], 'reason': None}
    try:
        merge_runtime_companions(args.artifacts_dir, idris_artifact=None, s6epe_artifact=args.envelope_dir)
        inventory = verify_inventory(args.artifacts_dir, expected_commit=args.source_commit,
            expected_run_id=args.source_run_id, expected_run_attempt=args.source_attempt)
        profile = select_profile(args.profile.split('-')[0], args.profile)
        admitted = next(row for row in inventory['cores'] if row['core'] == profile['core'])
        if not admitted['available']: raise ValueError(admitted.get('reason'))
        binary = args.artifacts_dir / profile['artifact']
        native = _current_feature_report(profile, binary)
        if native['availability'] != 'AVAILABLE': raise ValueError(native.get('reason'))
        runtime = args.artifacts_dir / 'runtime-artifacts/shadow6-s6epe-linux-runtime'
        passport = admit_s6epe_runtime(runtime, args.artifacts_dir)
        envelope = runtime / 'shadow6-privacy-envelope'
        features = feature_report(str(envelope), require_core=False)
        if not feature_availability(features)['available']: raise ValueError('encrypted S6EPE contract unavailable')
        adapter = TLSCarrier('stream') if args.profile == 'gleam-micro-mux' else RawCarrier('stream' if args.profile == 'gleam-secure-stream' else 'datagram')
        adapter.admit(features, runtime)
        report['binaryProvenance'] = {'core': admitted, 'envelope': passport,
            'sourceCommit': args.source_commit, 'sourceRunId': args.source_run_id,
            'sourceRunAttempt': args.source_attempt, 'nativeFeatureReport': native,
            'recompiled': False}
        digest = 'sha256:' + sha256_file(envelope)
        plan = [('baseline', 'clean', None), ('first-drop', 'clean', 'drop-first-carrier-datagram')]
        plan += [(f'mobile-{i}', 'mobile', None) for i in range(1, args.repeats + 1)]
        if args.profile.startswith('gleam-'):
            plan = [('baseline', 'clean', None)] + [(f'high-jitter-{i}', 'high-jitter', None) for i in range(1, args.repeats + 1)]
        report['status'] = 'RUNNING'
        if args.profile.startswith('gleam-'):
            for i in range(1, args.repeats + 1):
                row = _scenario_case(profile, binary, 'clean', output / f'native-clean-{i}',
                    uuid.uuid4().hex, capture_enabled=True, payload_bytes=4096, requests=2)
                errors = [key for key in ('capture', 'noBypass', 'correctness')
                          if row.get(key, {}).get('status') != 'PASS']
                if row['status'] != 'PASS': errors.append('nativeCorrectness')
                row.update(label=f'native-clean-{i}', gateErrors=errors, gateStatus='FAIL' if errors else 'PASS')
                report['results'].append(row)
                print(f"{row['label']}: measurement={row['status']} gate={row['gateStatus']} {row.get('reason')}", flush=True)
                _write_json(output / 'report.json', report)
                if errors: raise RuntimeError('native clean admission failed')
        for label, scenario, fault in plan:
            row = case(profile, binary, envelope, adapter, scenario, output / label,
                uuid.uuid4().hex, payload_bytes=4096, requests=2, expected_artifact_digest=digest,
                worker_timeout=90, fault=fault)
            if label.startswith('mobile-'):
                # Same full-workflow policy: real loss is retained as FAIL, but
                # owned PCAP/privacy evidence must still be present.
                errors = [stage for stage in ('PCAP', 'wireClassification', 'leakScan')
                    if row['stages'][stage]['status'] != 'PASS']
                if row.get('noBypass', {}).get('status') != 'PASS': errors.append('noBypass')
                if row['status'] in ('BLOCKED', 'SKIP'): errors.append('notExecuted')
            else: errors = evidence_errors(row, expected_loss=bool(fault))
            row.update(label=label, gateErrors=errors, gateStatus='FAIL' if errors else 'PASS')
            report['results'].append(row)
            print(f"{label}: measurement={row['status']} evidence-gate={row['gateStatus']} {errors}", flush=True)
            print(row.get('reason') or '', flush=True)
            print(row.get('workerDiagnostics') or '', flush=True)
            _write_json(output / 'report.json', report)
            if errors: break
        report['status'] = 'FAIL' if any(row['gateErrors'] for row in report['results']) else 'PASS'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(status='BLOCKED', reason=f'{type(error).__name__}: {error}')
        print(report['reason'], flush=True)
    _write_json(output / 'report.json', report)
    lines = [f'# {args.profile}/raw WAN evidence专项', '', f"Gate: {report['status']}", '',
        f"Controller commit: `{report['controllerCommit']}`", f"Binary source run: `{args.source_run_id}`", '',
        '| Case | Measurement | Exact evidence gate |', '|---|---|---|']
    for row in report['results']: lines.append(f"| {row['label']} | {row['status']} | {row['gateStatus']} |")
    if report['reason']: lines.extend(['', report['reason']])
    lines.extend(['', 'A dropped business record must remain FAIL. The专项 passes only when its owned PCAP/privacy evidence is complete.',
        'Native/envelope binaries are unchanged artifacts from the recorded source run; no all-Core or physical Internet coverage claim.'])
    (output / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts-dir', type=Path, required=True)
    parser.add_argument('--envelope-dir', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-run-id', required=True)
    parser.add_argument('--source-attempt', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--profile', choices=('zig-enet', 'gleam-secure-stream', 'gleam-micro-mux'), default='zig-enet')
    parser.add_argument('--repeats', type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()
    return 0 if reproduce(args)['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
