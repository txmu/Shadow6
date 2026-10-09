"""Fixed C++/SCTP WAN reproducer, independent of the all-Core release matrix.

Builds belong to the CI job. This driver uses the same locked Native trio,
typed attachments, owned namespaces and dual PCAP case as the full Test Lab.
"""
import argparse
import os
from pathlib import Path
import subprocess
import uuid

from shadow6_test_lab import ROOT, _current_feature_report, _write_json
from artifacts import sha256_file
from feature_contract import validate_feature_report
from network import capabilities
from privacy_envelope import feature_availability
from profile_registry import select_profile
from service_runtime import feature_report
from s6epe import SCTPCarrier, case

WAN_SCENARIOS = ('lan', 'good-wan', 'failure-recovery')


def eof_detected(row):
    # Capture/ownership failures can overwrite the outer reason. Preserve the
    # original structured workload result when deciding whether EOF occurred.
    reason = row.get('reason') or ''
    correctness = row.get('stages', {}).get('correctness', {})
    return any('EOFError:' in text for text in (reason, correctness.get('reason') or ''))


def reproduce(output, repeats):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'shadow6.sctp-fastjob.v1', 'status': 'BLOCKED',
        'sourceCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
            timeout=5, text=True).strip(),
        'runId': os.environ.get('GITHUB_RUN_ID'), 'repeats': repeats,
        'profile': 'cpp-sctp-tls13', 'carrier': 'sctp', 'eofReproduced': False,
        'results': [], 'reason': None,
        'scope': 'directional simulated veth WAN after the real Native Agent target'}
    try:
        if type(repeats) is not int or not 1 <= repeats <= 5:
            raise ValueError('repeats must be between one and five')
        profile = select_profile('cpp', 'cpp-sctp-tls13')
        binary = ROOT / profile['artifact']
        envelope = ROOT / 'OCaml/privacy_envelope/_build/default/src/main.exe'
        native = _current_feature_report(profile, binary)
        if native['availability'] != 'AVAILABLE': raise ValueError(native['reason'])
        validate_feature_report(native['featureReport'], 'shadow6-cpp')
        features = native['featureReport']
        if features['crosed_max_level'] != 0 or features['app_transport'] or features['qubes_isolation']:
            raise ValueError('FastJob requires a default least-privileged Core')
        envelope_features = feature_report(str(envelope), require_core=False)
        if not feature_availability(envelope_features)['available']:
            raise ValueError('current encrypted S6EPE contract unavailable')
        adapter = SCTPCarrier('message')
        adapter.admit(envelope_features, ROOT)
        caps = capabilities()
        if not caps['netnsNetem'] or not caps['namespaceCapture']:
            raise PermissionError(caps['reason'] or 'owned namespace capture unavailable')
        digest = 'sha256:' + sha256_file(envelope)
        report['build'] = {'native': native, 'envelopeFeatureReport': envelope_features,
            'envelopeSha256': digest, 'origin': 'compiled from this checkout in this job'}
        report['status'] = 'RUNNING'
        sequence = [(0, 'clean')] + [(attempt, scenario) for attempt in range(1, repeats + 1)
            for scenario in WAN_SCENARIOS]
        run_id = uuid.uuid4().hex
        for attempt, scenario in sequence:
            row = case(profile, binary, envelope, adapter, scenario,
                output / f'attempt-{attempt:02d}', run_id,
                payload_bytes=4096, requests=2, expected_artifact_digest=digest, worker_timeout=90)
            row['attempt'] = attempt
            row['eofDetected'] = eof_detected(row)
            report['results'].append(row)
            report['eofReproduced'] |= row['eofDetected']
            print(f"attempt={attempt} scenario={scenario} status={row['status']} "
                  f"EOF={row['eofDetected']} reason={row.get('reason')}", flush=True)
            if row['status'] != 'PASS':
                print('workload:', row.get('stages', {}).get('correctness', {}).get('reason'), flush=True)
                for endpoint, diagnostic in row.get('endpointDiagnostics', {}).items():
                    print(f'{endpoint}: {diagnostic}', flush=True)
            # Checkpoint each completed case before the next bounded workload.
            _write_json(output / 'report.json', report)
            if row['eofDetected'] or row['status'] == 'BLOCKED': break
        report['status'] = ('FAIL' if any(row['status'] == 'FAIL' for row in report['results'])
            else 'BLOCKED' if any(row['status'] == 'BLOCKED' for row in report['results']) else 'PASS')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report['reason'] = f'{type(error).__name__}: {error}'
        report['status'] = 'BLOCKED'
    _write_json(output / 'report.json', report)
    lines = ['# SCTP FastJob', '', f"Result: {report['status']}; EOF reproduced: {report['eofReproduced']}",
        '', f"Commit: `{report['sourceCommit']}`", '',
        'Scope: simulated directional WAN; complete private C++ Native trio.', '',
        '| Attempt | Scenario | Result | EOF |', '|---|---|---|---|']
    for row in report['results']:
        lines.append(f"| {row['attempt']} | {row['scenario']} | {row['status']} | {row['eofDetected']} |")
    if report['reason']: lines.extend(['', report['reason']])
    lines.extend(['', 'Inspect report.json, per-case PCAPs and endpoint-diagnostics.json for failures.',
        'A PASS means EOF was not observed in these bounded attempts; it does not rule out intermittent WAN failures.'])
    (output / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, choices=range(1, 6), default=2)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    report = reproduce(args.output_dir, args.repeats)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
