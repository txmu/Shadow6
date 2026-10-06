"""Small, bounded PCAP flow summarizer with optional native protocol observers.

The built-in parser reports only fields it can read from classic PCAP safely.
Unknown payloads remain ``unknown/custom``. TShark labels are recorded as an
additional observer, never used to overwrite the packet parser's evidence.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import struct
import subprocess

SCHEMA = "shadow6.wan-pcap-fingerprint.v1"
MAX_PCAP_BYTES = 8 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_SNAPLEN = 65_535


def _u16(data, offset, endian):
    return struct.unpack_from(endian + "H", data, offset)[0]


def _packet_network(packet: bytes, linktype: int):
    offset = 0
    ethertype = None
    if linktype == 1:  # Ethernet, including bounded VLAN nesting.
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        offset = 14
        for _ in range(2):
            if ethertype not in (0x8100, 0x88A8, 0x9100):
                break
            if len(packet) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += 4
    elif linktype == 113:  # Linux cooked capture v1.
        if len(packet) < 16:
            return None
        ethertype = struct.unpack_from("!H", packet, 14)[0]
        offset = 16
    elif linktype == 276:  # Linux cooked capture v2.
        if len(packet) < 20:
            return None
        ethertype = struct.unpack_from("!H", packet, 0)[0]
        offset = 20
    elif linktype in (101, 12):  # DLT_RAW / DLT_RAW_ALT.
        if not packet:
            return None
        ethertype = 0x0800 if packet[0] >> 4 == 4 else 0x86DD if packet[0] >> 4 == 6 else None
    else:
        return None
    if ethertype == 0x0800:
        if len(packet) < offset + 20:
            return None
        first = packet[offset]
        ihl = (first & 0x0F) * 4
        total = struct.unpack_from("!H", packet, offset + 2)[0]
        fragment = struct.unpack_from("!H", packet, offset + 6)[0]
        if first >> 4 != 4 or ihl < 20 or len(packet) < offset + ihl or total < ihl:
            return None
        source = ".".join(map(str, packet[offset + 12:offset + 16]))
        target = ".".join(map(str, packet[offset + 16:offset + 20]))
        protocol = packet[offset + 9]
        transport_offset = offset + ihl
        payload_end = min(len(packet), offset + total)
        if fragment & 0x1FFF:
            return {"source": source, "target": target, "protocol": protocol,
                    "source_port": None, "target_port": None, "payload": b"",
                    "tcp_flags": None}
    elif ethertype == 0x86DD:
        if len(packet) < offset + 40 or packet[offset] >> 4 != 6:
            return None
        source = ":".join(f"{int.from_bytes(packet[offset + i:offset + i + 2], 'big'):x}" for i in range(8, 24, 2))
        target = ":".join(f"{int.from_bytes(packet[offset + i:offset + i + 2], 'big'):x}" for i in range(24, 40, 2))
        protocol = packet[offset + 6]
        payload_end = min(len(packet), offset + 40 + struct.unpack_from("!H", packet, offset + 4)[0])
        transport_offset = offset + 40
        # Walk only common, bounded IPv6 extension headers.
        for _ in range(8):
            if protocol not in (0, 43, 44, 51, 60):
                break
            if protocol == 44:
                if len(packet) < transport_offset + 8:
                    return None
                fragment = struct.unpack_from("!H", packet, transport_offset + 2)[0]
                next_protocol = packet[transport_offset]
                transport_offset += 8
                protocol = next_protocol
                if fragment & 0xFFF8:
                    return {"source": source, "target": target, "protocol": protocol,
                            "source_port": None, "target_port": None, "payload": b"",
                            "tcp_flags": None}
                continue
            if len(packet) < transport_offset + 2:
                return None
            next_protocol = packet[transport_offset]
            extension_length = ((packet[transport_offset + 1] + 2) * 4 if protocol == 51
                                else (packet[transport_offset + 1] + 1) * 8)
            if extension_length < 8 or len(packet) < transport_offset + extension_length:
                return None
            transport_offset += extension_length
            protocol = next_protocol
        else:
            return None
    else:
        return None
    if transport_offset > payload_end:
        return None
    source_port = target_port = tcp_flags = None
    payload = b""
    if protocol == 6 and payload_end >= transport_offset + 20:
        source_port, target_port = struct.unpack_from("!HH", packet, transport_offset)
        header = (packet[transport_offset + 12] >> 4) * 4
        if header < 20 or transport_offset + header > payload_end:
            return None
        tcp_flags = packet[transport_offset + 13]
        payload = packet[transport_offset + header:payload_end]
    elif protocol == 17 and payload_end >= transport_offset + 8:
        source_port, target_port = struct.unpack_from("!HH", packet, transport_offset)
        payload = packet[transport_offset + 8:payload_end]
    elif protocol == 132 and payload_end >= transport_offset + 12:
        source_port, target_port = struct.unpack_from("!HH", packet, transport_offset)
        payload = packet[transport_offset + 12:payload_end]
    return {"source": source, "target": target, "protocol": protocol,
            "source_port": source_port, "target_port": target_port,
            "payload": payload, "tcp_flags": tcp_flags}


def _decode_pcap(path: Path):
    info = path.lstat()
    if not os.path.isfile(path) or path.is_symlink() or info.st_size > MAX_PCAP_BYTES:
        raise ValueError("PCAP must be a regular non-symlink file no larger than 8 MiB")
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("truncated PCAP global header")
    variants = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in variants:
        raise ValueError("only classic PCAP is supported by the built-in parser")
    endian, ticks_per_second = variants[data[:4]]
    major, minor = struct.unpack_from(endian + "HH", data, 4)
    snaplen, linktype = struct.unpack_from(endian + "II", data, 16)
    if (major != 2 or minor != 4 or not 1 <= snaplen <= MAX_SNAPLEN or linktype > 3000):
        raise ValueError("invalid or unsupported PCAP header")
    packets = []
    offset = 24
    while offset < len(data):
        if len(packets) >= MAX_PACKETS or len(data) - offset < 16:
            raise ValueError("PCAP packet count or header exceeds bounds")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > snaplen or captured > MAX_SNAPLEN or captured > len(data) - offset or original < captured:
            raise ValueError("invalid PCAP packet length")
        timestamp = seconds + fraction / ticks_per_second
        if not math.isfinite(timestamp):
            raise ValueError("invalid PCAP timestamp")
        frame = data[offset:offset + captured]
        offset += captured
        network = _packet_network(frame, linktype)
        packets.append({"timestamp": timestamp, "captured": captured,
                        "original": original, "network": network})
    return packets, data, linktype


def _packet_class(network):
    if network is None:
        return "unclassified"
    proto = network["protocol"]
    payload = network["payload"]
    if proto == 132:
        return "sctp"
    if proto == 6:
        if payload.startswith((b"S6EP3", b"S6EPE")):
            return "s6epe-marker-visible"
        if len(payload) >= 3 and payload[0] == 22 and payload[1] == 3:
            return "tls-record-observed"
        if payload.startswith((b"S6I3", b"S6G1", b"S6P1")):
            return "shadow6-marker-visible"
        return "tcp-unknown-custom"
    if proto == 17:
        if len(payload) >= 3 and payload[0] == 22 and payload[1] == 0xFE:
            return "dtls-record-observed"
        if payload.startswith((b"S6EP3", b"S6EPE")):
            return "s6epe-marker-visible"
        if payload.startswith((b"S6I3", b"S6I2", b"S6P1")):
            return "shadow6-marker-visible"
        return "udp-unknown-custom"
    return {1: "icmp", 58: "icmpv6"}.get(proto, "ip-unknown-custom")


def _tshark_protocols(path: Path):
    binary = shutil.which("tshark")
    if not binary:
        return {"status": "unavailable", "reason": "tshark not installed", "protocols": []}
    try:
        result = subprocess.run([binary, "-n", "-r", str(path), "-T", "fields",
                                 "-e", "_ws.col.Protocol"], capture_output=True,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "failed", "reason": type(error).__name__, "protocols": []}
    if len(result.stdout) > 1024 * 1024:
        return {"status": "failed", "reason": "tshark output exceeds 1 MiB", "protocols": []}
    if result.returncode:
        return {"status": "failed", "reason": "tshark could not read capture", "protocols": []}
    protocols = sorted({line.strip()[:64] for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()})
    return {"status": "available", "reason": None, "protocols": protocols}


def analyze(path: Path, *, run_id=None, core=None, profile=None, link_type="unknown",
            scenario="unspecified", forbidden_literals=()):
    path = Path(path)
    packets, raw, linktype = _decode_pcap(path)
    flows = {}
    classes = set()
    marker_names = (b"shadow6", b"s6epe", b"s6p1", b"s6i3", b"s6g1")
    marker_found = set()
    for marker in marker_names:
        if marker in raw.lower():
            marker_found.add(marker.decode("ascii"))
    explicit = []
    for literal in forbidden_literals:
        value = literal if isinstance(literal, bytes) else str(literal).encode("utf-8")
        if value and value in raw:
            explicit.append(hashlib.sha256(value).hexdigest())
    for packet in packets:
        network = packet["network"]
        label = _packet_class(network)
        classes.add(label)
        if network is None or network["source_port"] is None:
            continue
        proto = network["protocol"]
        left = (network["source"], network["source_port"])
        right = (network["target"], network["target_port"])
        endpoints = tuple(sorted((left, right)))
        direction = "a-to-b" if left == endpoints[0] else "b-to-a"
        key = (proto, endpoints[0], endpoints[1])
        flow = flows.setdefault(key, {"transport": {6: "tcp", 17: "udp", 132: "sctp"}.get(proto, "ip"),
            "endpointA": {"address": endpoints[0][0], "port": endpoints[0][1]},
            "endpointB": {"address": endpoints[1][0], "port": endpoints[1][1]},
            "packets": 0, "bytes": 0, "directions": {"a-to-b": {"packets": 0, "bytes": 0},
            "b-to-a": {"packets": 0, "bytes": 0}}, "lengths": [], "timestamps": [],
            "classes": set(), "tcpHandshakeSeconds": None})
        flow["packets"] += 1
        flow["bytes"] += packet["original"]
        direction_stats = flow["directions"][direction]
        direction_stats["packets"] += 1
        direction_stats["bytes"] += packet["original"]
        flow["lengths"].append(packet["original"])
        flow["timestamps"].append(packet["timestamp"])
        flow["classes"].add(label)
        if proto == 6 and network["tcp_flags"] is not None:
            flags = network["tcp_flags"]
            if flags & 0x02 and not flags & 0x10 and direction == "a-to-b":
                flow.setdefault("synAt", packet["timestamp"])
            elif flags & 0x12 == 0x12 and direction == "b-to-a" and "synAt" in flow:
                flow["synAckAt"] = packet["timestamp"]
            elif (flags & 0x10 and not flags & 0x02 and direction == "a-to-b" and
                  "synAckAt" in flow and flow["tcpHandshakeSeconds"] is None):
                flow["tcpHandshakeSeconds"] = max(0.0, packet["timestamp"] - flow["synAt"])
    normalized = []
    for flow in flows.values():
        times = flow.pop("timestamps")
        lengths = flow.pop("lengths")
        ordered_times = sorted(times)
        iats = [max(0.0, right - left) for left, right in zip(ordered_times, ordered_times[1:])]
        burst_count = 0
        previous = None
        for timestamp in ordered_times:
            if previous is None or timestamp - previous > 0.1:
                burst_count += 1
            previous = timestamp
        ordered_lengths = sorted(lengths)
        flow["classes"] = sorted(flow["classes"])
        flow["packetLengthDistribution"] = {"min": min(lengths), "max": max(lengths),
            "mean": round(statistics.fmean(lengths), 6), "p50": ordered_lengths[(len(lengths)-1)//2],
            "p95": ordered_lengths[min(len(lengths)-1, int(len(lengths)*0.95))]}
        flow["timing"] = {"firstPacketSeconds": min(times), "lastPacketSeconds": max(times),
            "durationSeconds": max(times) - min(times), "interArrivalMeanSeconds": round(statistics.fmean(iats), 9) if iats else None,
            "interArrivalP95Seconds": round(sorted(iats)[min(len(iats)-1, int(len(iats)*0.95))], 9) if iats else None,
            "burstsAt100msThreshold": burst_count}
        for key in ("synAt", "synAckAt"):
            flow.pop(key, None)
        normalized.append(flow)
    normalized.sort(key=lambda item: (item["transport"], item["endpointA"]["address"],
                                      item["endpointA"]["port"], item["endpointB"]["address"],
                                      item["endpointB"]["port"]))
    return {"schema": SCHEMA, "capture": {"file": path.name, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "linkType": linktype,
            "pcapPackets": len(packets), "runId": run_id, "core": core, "profile": profile,
            "linkTypeLabel": link_type, "scenario": scenario},
        "classification": {"observed": sorted(classes) or ["unknown/custom"],
            "meaning": "packet signatures and protocol fields only; no DPI-resistance inference",
            "tshark": _tshark_protocols(path)},
        "flows": normalized,
        "leakScan": {"status": "detected" if marker_found or explicit else "no-known-marker-found",
            "publicMarkers": sorted(marker_found), "explicitForbiddenLiteralDigests": sorted(explicit),
            "secretCoverage": "explicit literal and common Shadow6 identity markers only; not a general secret detector"}}
