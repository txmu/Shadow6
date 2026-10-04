#!/usr/bin/env python3
"""Foreground canonical component runner for native service managers."""
import argparse
import json
import os
import platform
import time
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent if HERE.name != 'bin' else HERE.parent/'share/shadow6/tree'
sys.path.insert(0,str(ROOT))
from Deployment.service_runtime import supervise, verify_launch_material
from Deployment.service_storage import private_read, strict_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--check-config',action='store_true')
    parser.add_argument('--capabilities',action='store_true')
    args=parser.parse_args()
    verify_launch_material(strict_json(private_read(args.config)))
    if args.capabilities:
        print(json.dumps({'schema':'shadow6.native-runner.v1','platform':platform.system(),
                          'processIdentity':'available' if sys.platform == 'linux' else 'degraded',
                          'ownedSocketObservation':'available' if sys.platform == 'linux' else 'unavailable',
                          'readyEvent':'required','readiness':'never-inferred-from-process-alive'},sort_keys=True))
        return 0
    if args.check_config:return 0
    if sys.platform == 'linux':
        supervise(args.config,-1)
    else:
        # Native managers own activation and restart policy. The foreground
        # runner keeps exact launch material checks and never synthesizes ready.
        plan = strict_json(private_read(args.config))
        raise ValueError('capability unavailable: native process and socket observation backend on ' + platform.system())
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError) as error:
        print(f'service runner failed: {type(error).__name__}',file=sys.stderr)
        raise SystemExit(2)
