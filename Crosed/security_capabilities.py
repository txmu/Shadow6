"""Bounded source-contract inventory; never substitutes for runtime attestation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath

from feature_contract import CORE_PATHS, TRANSPORTS

CONTROLS = frozenset({"encryption", "authentication", "fresh_keys", "replay",
                      "session_lifecycle", "rekey", "shaping", "persistent_replay"})
STATUSES = frozenset({"native", "transport", "limited", "mode-dependent", "not-declared"})
MATRIX_PATH = Path(__file__).with_name("security_capabilities.json")
ROOT = Path(__file__).resolve().parents[1]
TRANSPORTS_TO_DIRECTORY = {core: Path(path).parent for core, path in CORE_PATHS.items()}


def _fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unknown or missing security matrix fields")


def _text(value, maximum=2048):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(
            ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid security matrix text")


def validate_matrix(value, *, source_root=None):
    _fields(value, {"schema", "security_domain", "evidence_kind", "outer_domain", "cores"})
    if (value["schema"] != "shadow6.native-security-capabilities.v1" or
            value["security_domain"] != "native-core" or value["evidence_kind"] != "source-contract"):
        raise ValueError("unsupported security matrix domain/schema")
    outer = value["outer_domain"]
    _fields(outer, {"component", "independent", "mandatory_encryption", "native_protocol_translation"})
    if (outer["component"] != "S6EPE" or outer["independent"] is not True or
            outer["mandatory_encryption"] is not True or outer["native_protocol_translation"] is not False):
        raise ValueError("invalid outer security domain")
    rows = value["cores"]
    if not isinstance(rows, list) or len(rows) != len(TRANSPORTS):
        raise ValueError("security matrix must cover all twelve native families")
    seen = set()
    sources = {}
    for row in rows:
        _fields(row, {"core", "transport", "scope", "capabilities", "evidence", "legacy_modes"})
        core = row["core"]
        if not isinstance(core, str) or core not in TRANSPORTS or core in seen:
            raise ValueError("unknown or duplicate native family")
        seen.add(core)
        if row["transport"] != TRANSPORTS[core]:
            raise ValueError("security matrix transport conflicts with feature contract")
        if row["scope"] != "native broker/agent/client data path":
            raise ValueError("invalid native security scope")
        _fields(row["capabilities"], CONTROLS)
        for capability in row["capabilities"].values():
            _fields(capability, {"status", "detail"})
            if not isinstance(capability["status"], str) or capability["status"] not in STATUSES:
                raise ValueError("invalid security capability status")
            _text(capability["detail"])
        evidence = row["evidence"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 16:
            raise ValueError("missing or excessive source evidence")
        evidence_seen = set()
        family = Path(TRANSPORTS_TO_DIRECTORY[core])
        for reference in evidence:
            _fields(reference, {"path", "contains"})
            _text(reference["path"], 256)
            _text(reference["contains"], 256)
            name = PurePosixPath(reference["path"])
            if (name.is_absolute() or ".." in name.parts or "\\" in reference["path"] or
                    name.as_posix() != reference["path"] or name.parts[0] != family.name):
                raise ValueError("source evidence must belong to the declared native family")
            key = (reference["path"], reference["contains"])
            if key in evidence_seen:
                raise ValueError("duplicate source evidence")
            evidence_seen.add(key)
            if source_root is not None:
                path = Path(source_root) / reference["path"]
                if path not in sources:
                    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_097_152:
                        raise ValueError("source evidence unavailable or exceeds bound")
                    sources[path] = path.read_text(encoding="utf-8")
                if reference["contains"] not in sources[path]:
                    raise ValueError("security matrix source evidence no longer matches")
        legacy = row["legacy_modes"]
        if not isinstance(legacy, list) or len(legacy) > 8:
            raise ValueError("invalid legacy mode inventory")
        modes = set()
        for mode in legacy:
            _fields(mode, {"mode", "limitation"})
            _text(mode["mode"], 64)
            _text(mode["limitation"])
            if mode["mode"] in modes:
                raise ValueError("duplicate legacy mode")
            modes.add(mode["mode"])
    return value


def load_matrix(path=MATRIX_PATH, *, source_root=None):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate security matrix field")
            value[key] = item
        return value

    def reject_number(_):
        raise ValueError("numbers are not part of the security matrix schema")

    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("security matrix exceeds document bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_int=reject_number, parse_float=reject_number,
                           parse_constant=reject_number)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError("invalid security matrix JSON") from error
    return validate_matrix(value, source_root=source_root)


def markdown(matrix):
    lines = ["| Core / native transport | " + " | ".join(sorted(CONTROLS)) + " |",
             "| --- | " + " | ".join("---" for _ in CONTROLS) + " |"]
    for row in matrix["cores"]:
        lines.append("| " + row["core"] + " / " + row["transport"] + " | " +
                     " | ".join(row["capabilities"][key]["status"] for key in sorted(CONTROLS)) + " |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-sources", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    matrix = load_matrix(source_root=ROOT if args.check_sources else None)
    print(markdown(matrix) if args.markdown else json.dumps(matrix, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
