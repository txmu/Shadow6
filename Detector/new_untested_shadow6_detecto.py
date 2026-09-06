#!/usr/bin/env python3
"""Compatibility launcher; use shadow6_detector_neo.py for new deployments."""

from shadow6_detector_neo import main


if __name__ == "__main__":
    raise SystemExit(main())
