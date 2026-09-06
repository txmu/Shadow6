#!/usr/bin/env python3
"""Fail safely before an Android build can exhaust a small remote host."""

from __future__ import annotations

import os
from pathlib import Path


MIB = 1024 * 1024
MIN_TOTAL_MEMORY = 1536 * MIB
MIN_AVAILABLE_MEMORY = 896 * MIB
MIN_FREE_DISK = 1024 * MIB
ROOT = Path(__file__).resolve().parents[1]


def meminfo(path: Path = Path("/proc/meminfo")) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, raw = line.split(":", 1)
        fields = raw.split()
        if fields:
            values[key] = int(fields[0]) * 1024
    return values


def cgroup_available(root: Path = Path("/sys/fs/cgroup")) -> tuple[int, int] | None:
    """Return a finite cgroup-v2 total/available budget when one is active."""
    try:
        memory_max = (root / "memory.max").read_text(encoding="ascii").strip()
        if memory_max == "max":
            return None
        memory_limit = int(memory_max)
        memory_used = int((root / "memory.current").read_text(encoding="ascii").strip())
        swap_max = (root / "memory.swap.max").read_text(encoding="ascii").strip()
        swap_limit = 0 if swap_max == "max" else int(swap_max)
        swap_used_path = root / "memory.swap.current"
        swap_used = int(swap_used_path.read_text(encoding="ascii").strip()) if swap_used_path.exists() else 0
    except (FileNotFoundError, PermissionError, ValueError):
        return None
    return memory_limit + swap_limit, max(0, memory_limit - memory_used) + max(0, swap_limit - swap_used)


def main() -> int:
    memory = meminfo()
    total = memory.get("MemTotal", 0) + memory.get("SwapTotal", 0)
    available = memory.get("MemAvailable", memory.get("MemFree", 0)) + memory.get("SwapFree", 0)
    cgroup = cgroup_available()
    if cgroup is not None:
        total = min(total, cgroup[0])
        available = min(available, cgroup[1])
    disk = os.statvfs(ROOT)
    free_disk = disk.f_bavail * disk.f_frsize
    problems: list[str] = []
    if total < MIN_TOTAL_MEMORY:
        problems.append(f"RAM + swap is {total // MIB} MiB; at least {MIN_TOTAL_MEMORY // MIB} MiB is required")
    if available < MIN_AVAILABLE_MEMORY:
        problems.append(f"available RAM + free swap is {available // MIB} MiB; at least {MIN_AVAILABLE_MEMORY // MIB} MiB is required")
    if free_disk < MIN_FREE_DISK:
        problems.append(f"free project-disk space is {free_disk // MIB} MiB; at least {MIN_FREE_DISK // MIB} MiB is required")
    if problems:
        raise SystemExit("Android build preflight refused to start:\n- " + "\n- ".join(problems))
    print(
        "Android resource preflight: "
        f"{total // MIB} MiB RAM+swap, {available // MIB} MiB available, "
        f"{free_disk // MIB} MiB disk free; safe low-memory settings enabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
