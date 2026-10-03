#!/usr/bin/env python3
"""Foreground canonical component runner for native service managers."""
import argparse
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
    args=parser.parse_args()
    verify_launch_material(strict_json(private_read(args.config)))
    if args.check_config:return 0
    if sys.platform != 'linux':
        raise ValueError('capability unavailable: native component runner OS observation backend')
    supervise(args.config,-1)
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError) as error:
        print(f'service runner failed: {type(error).__name__}',file=sys.stderr)
        raise SystemExit(2)
