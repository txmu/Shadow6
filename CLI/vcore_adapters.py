"""Native CLI adapters with a generic feature-report fallback.

Known Cores retain their precise config spelling; separately shipped Cores can
participate in Core-Blind discovery through the common read-only contract.
"""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Adapter:
    check_style: str
    description: str

    def argv(self, operation, config):
        if operation in ("feature-report", "version", "status"):
            if config is not None:
                raise ValueError("probe operation does not accept config")
            return ["--feature-report"]
        if operation != "check-config" or self.check_style == "unsupported":
            raise ValueError("operation unsupported by native core")
        if not isinstance(config, str) or not config or len(config.encode()) > 4096 or "\0" in config:
            raise ValueError("check-config requires a bounded path")
        path = str(Path(config).absolute())
        return (["--check-config", path] if self.check_style == "prefix" else
                ["--config", path, "--check-config"])


ADAPTERS = {
    "go": Adapter("suffix", "complete Go KCP stack"),
    "rust": Adapter("suffix", "complete Rust QUIC stack"),
    "zig": Adapter("suffix", "Zig ENet stack with existing dual-mode interoperability"),
    "ada": Adapter("suffix", "Ada fixed-cell relay"),
    "d": Adapter("prefix", "D bounded RLE UDP driver"),
    "nim": Adapter("suffix", "Nim WebRTC stack"),
    "cpp": Adapter("suffix", "C++ SCTP/TLS stack"),
    "pony": Adapter("prefix", "Pony pinned-peer UDP transport"),
    "hare": Adapter("prefix", "Hare single-peer UDP emergency proxy"),
    "carp": Adapter("prefix", "Carp authenticated loopback UDP codec"),
    "gleam": Adapter("suffix", "Gleam secure-stream stack"),
    "idris": Adapter("unsupported", "Idris feature probe and loopback self-test; no config CLI"),
}


def translate(core, operation, config=None):
    adapter = ADAPTERS.get(core)
    if adapter is None:
        if operation in ("feature-report", "version", "status") and config is None:
            return ["--feature-report"]
        raise ValueError("external Core does not declare a safe config adapter")
    return adapter.argv(operation, config)


def description(core):
    return ADAPTERS.get(core, Adapter("unsupported", "external Core selected by feature-report contract")).description
