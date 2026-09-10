#!/usr/bin/env python3
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
level = int(sys.argv[2])
app = sys.argv[3] == "1"
qubes = sys.argv[4] == "1"
if level not in (0, 5) or app != (level == 5) or qubes != (level == 5):
    raise SystemExit("invalid Core-Gleam build feature combination")
path.write_text(
    "-module(shadow6_build).\n"
    "-export([crosed_level/0, app_transport/0, qubes_isolation/0]).\n"
    f"crosed_level() -> {level}.\n"
    f"app_transport() -> {str(app).lower()}.\n"
    f"qubes_isolation() -> {str(qubes).lower()}.\n",
    encoding="ascii",
)

