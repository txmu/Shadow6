#!/usr/bin/env python3
"""Sequence-aware Shadow6 detector with safe RF/LSTM model loading."""

from __future__ import annotations

import argparse
import collections
import logging
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

from detector_core import (
    DecoyManager,
    SafeRandomForestModel,
    TrafficFeatures,
    atomic_write_csv,
    open_validated_model,
)
from shadow6_detector import FEATURE_COLUMNS, ModelPipeline as RFModelPipeline


os.umask(0o077)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("Detector")

try:
    import numpy as np
    import pandas as pd
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from sklearn.model_selection import train_test_split
    from torch.utils.data import DataLoader, TensorDataset

    NEO_AVAILABLE = True
except ImportError:
    NEO_AVAILABLE = False

try:
    from scapy.all import IP, IPv6, PcapReader, TCP, UDP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


if NEO_AVAILABLE:
    class DPI_LSTM(nn.Module):
        def __init__(self, input_dim: int = 5, hidden_dim: int = 32, num_layers: int = 1, num_classes: int = 2):
            super().__init__()
            self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
            self.fc = nn.Linear(hidden_dim, num_classes)

        def forward(self, values):
            output, _ = self.lstm(values)
            return self.fc(output[:, -1, :])


class ModelPipeline(RFModelPipeline):
    @staticmethod
    def _require_neo() -> None:
        if not NEO_AVAILABLE:
            raise RuntimeError("Neo dependencies are missing; install requirements-ml.txt")

    @staticmethod
    def extract_pcap_to_csv(normal_pcap: str, probe_pcap: str, output_csv: str, max_packets: int = 1_000_000) -> None:
        if not SCAPY_AVAILABLE or not NEO_AVAILABLE:
            raise RuntimeError("PCAP extraction requires scapy, pandas, and numpy")
        rows = []
        for pcap_path, label in ((normal_pcap, 0), (probe_pcap, 1)):
            if not Path(pcap_path).is_file():
                raise FileNotFoundError(pcap_path)
            last_seen = {}
            with PcapReader(pcap_path) as packets:
                for index, packet in enumerate(packets):
                    if index >= max_packets:
                        raise ValueError(f"PCAP exceeds max_packets={max_packets}")
                    network = packet.getlayer(IP) or packet.getlayer(IPv6)
                    if network is None:
                        continue
                    protocol = TCP if packet.haslayer(TCP) else UDP if packet.haslayer(UDP) else None
                    payload = bytes(packet[protocol].payload) if protocol and packet[protocol].payload else b""
                    source_port = int(packet[protocol].sport) if protocol else 0
                    destination_port = int(packet[protocol].dport) if protocol else 0
                    endpoints = sorted(((str(network.src), source_port), (str(network.dst), destination_port)))
                    flow = (endpoints[0], endpoints[1], int(getattr(network, "nh", getattr(network, "proto", -1))))
                    timestamp = float(packet.time)
                    iat = max(0.0, timestamp - last_seen.get(flow, timestamp))
                    last_seen[flow] = timestamp
                    rows.append(
                        [
                            len(packet),
                            TrafficFeatures.calculate_entropy(payload[:256]),
                            int(protocol is TCP),
                            len(payload),
                            iat,
                            label,
                        ]
                    )
        if not rows:
            raise ValueError("no IPv4/IPv6 packets were extracted")
        frame = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["label"])
        atomic_write_csv(output_csv, frame)
        logger.info("Extracted %d packets into %s", len(rows), output_csv)

    @staticmethod
    def create_sliding_windows(values, labels, window_size: int = 10):
        if window_size < 2 or len(values) < window_size:
            raise ValueError("dataset is smaller than the requested window")
        windows = [values[index : index + window_size] for index in range(len(values) - window_size + 1)]
        targets = [labels[index + window_size - 1] for index in range(len(values) - window_size + 1)]
        return np.asarray(windows, dtype=np.float32), np.asarray(targets, dtype=np.int64)

    @staticmethod
    def train_lstm_model(dataset_path: str, model_path: str, window_size: int = 10, epochs: int = 10) -> None:
        ModelPipeline._require_neo()
        if not 1 <= epochs <= 1_000:
            raise ValueError("epochs must be between 1 and 1000")
        frame = pd.read_csv(dataset_path)
        missing = set(FEATURE_COLUMNS + ["label"]) - set(frame.columns)
        if missing:
            raise ValueError(f"dataset is missing columns: {sorted(missing)}")
        numeric = frame[FEATURE_COLUMNS + ["label"]].apply(pd.to_numeric, errors="raise")
        values = numeric[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
        labels = numeric["label"].to_numpy(dtype=np.int64)
        if not np.isfinite(values).all():
            raise ValueError("dataset features must all be finite")
        if (
            (values[:, 0] < 0).any()
            or ((values[:, 1] < 0) | (values[:, 1] > 8)).any()
            or (~np.isin(values[:, 2], [0, 1])).any()
            or (values[:, 3] < 0).any()
            or (values[:, 3] > values[:, 0]).any()
            or (values[:, 4] < 0).any()
        ):
            raise ValueError("dataset contains out-of-range feature values")
        if sorted(set(labels.tolist())) != [0, 1]:
            raise ValueError("dataset labels must be exactly 0 and 1")
        means = values.mean(axis=0)
        standard_deviations = values.std(axis=0)
        standard_deviations[standard_deviations < 1e-8] = 1.0
        normalized = (values - means) / standard_deviations
        sequences, sequence_labels = ModelPipeline.create_sliding_windows(normalized, labels, window_size)
        class_counts = collections.Counter(sequence_labels.tolist())
        if set(class_counts) != {0, 1} or min(class_counts.values()) < 2:
            raise ValueError("sliding windows must contain at least two samples from each class")
        train_x, test_x, train_y, test_y = train_test_split(
            sequences,
            sequence_labels,
            test_size=0.2,
            random_state=42,
            stratify=sequence_labels,
        )
        torch.manual_seed(42)
        model = DPI_LSTM()
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        loss_function = nn.CrossEntropyLoss()
        loader = DataLoader(
            TensorDataset(torch.from_numpy(train_x), torch.from_numpy(train_y)),
            batch_size=64,
            shuffle=True,
        )
        model.train()
        for epoch in range(epochs):
            total_loss = 0.0
            for batch_values, batch_labels in loader:
                optimizer.zero_grad()
                loss = loss_function(model(batch_values), batch_labels)
                loss.backward()
                optimizer.step()
                total_loss += float(loss.item())
            logger.info("Epoch %d/%d loss %.5f", epoch + 1, epochs, total_loss / max(1, len(loader)))
        model.eval()
        with torch.no_grad():
            predicted = model(torch.from_numpy(test_x)).argmax(dim=1)
            accuracy = float((predicted == torch.from_numpy(test_y)).float().mean().item())
        logger.info("LSTM test accuracy: %.4f", accuracy)
        payload = {
            "format_version": 1,
            "state_dict": model.state_dict(),
            "means": torch.tensor(means),
            "standard_deviations": torch.tensor(standard_deviations),
            "window_size": window_size,
        }
        destination = Path(model_path).expanduser()
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.tmp-", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w+b") as handle:
                torch.save(payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        finally:
            if temporary.exists():
                temporary.unlink()


class LSTMModel:
    def __init__(self, path: str):
        if not NEO_AVAILABLE:
            raise RuntimeError("PyTorch is unavailable")
        with open_validated_model(path) as handle:
            payload = torch.load(handle, map_location="cpu", weights_only=True)
        if not isinstance(payload, dict):
            raise ValueError("invalid LSTM model document")
        if payload.get("format_version") != 1:
            raise ValueError("unsupported LSTM model format")
        self.window_size = int(payload["window_size"])
        if not 2 <= self.window_size <= 10_000:
            raise ValueError("invalid LSTM window size")
        self.means = payload["means"].to(dtype=torch.float32)
        self.standard_deviations = payload["standard_deviations"].to(dtype=torch.float32)
        if self.means.shape != (5,) or self.standard_deviations.shape != (5,):
            raise ValueError("invalid LSTM normalization tensors")
        if not torch.isfinite(self.means).all() or not torch.isfinite(self.standard_deviations).all():
            raise ValueError("LSTM normalization tensors must be finite")
        if not torch.all(self.standard_deviations > 0):
            raise ValueError("LSTM standard deviations must be positive")
        self.model = DPI_LSTM()
        self.model.load_state_dict(payload["state_dict"], strict=True)
        self.model.eval()

    def predict_sequence(self, sequence) -> int:
        values = torch.tensor(sequence, dtype=torch.float32)
        if values.shape != (self.window_size, 5) or not torch.isfinite(values).all():
            raise ValueError("sequence must match the model window and contain finite features")
        values = (values - self.means) / self.standard_deviations
        with torch.no_grad():
            return int(self.model(values.unsqueeze(0)).argmax(dim=1).item())


class RealTimeDetector:
    def __init__(self, model_path: str, model_type: str, interface: str, decoy: DecoyManager | None = None):
        self.interface = interface
        self.model_type = model_type
        self.decoy = decoy
        self.last_seen = {}
        self.buffers = collections.OrderedDict()
        if model_type == "rf":
            self.model = SafeRandomForestModel.load(model_path)
            self.window_size = 1
        else:
            self.model = LSTMModel(model_path)
            self.window_size = self.model.window_size

    def sniff_loop(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("real-time AF_PACKET capture requires root or CAP_NET_RAW")
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as raw_socket:
            if self.interface != "any":
                if self.interface not in {name for _, name in socket.if_nameindex()}:
                    raise ValueError(f"unknown interface: {self.interface}")
                raw_socket.bind((self.interface, 0))
            logger.info("Started Neo capture on %s using %s", self.interface, self.model_type)
            while True:
                packet, _ = raw_socket.recvfrom(65_535)
                packet_length, entropy, is_tcp, payload_size = TrafficFeatures.extract_features(packet)
                if payload_size == 0:
                    continue
                flow = TrafficFeatures.flow_key(packet)
                now = time.monotonic()
                iat = max(0.0, now - self.last_seen.get(flow, now))
                self.last_seen[flow] = now
                features = [packet_length, entropy, is_tcp, payload_size, iat]
                if self.model_type == "rf":
                    malicious = self.model.predict([features])[0] == 1
                else:
                    buffer = self.buffers.setdefault(flow, collections.deque(maxlen=self.window_size))
                    buffer.append(features)
                    self.buffers.move_to_end(flow)
                    if len(self.buffers) > 10_000:
                        expired, _ = self.buffers.popitem(last=False)
                        self.last_seen.pop(expired, None)
                    malicious = len(buffer) == self.window_size and self.model.predict_sequence(buffer) == 1
                if malicious:
                    logger.warning("PROBE SEQUENCE DETECTED: flow=%r", flow)
                    if self.decoy:
                        self.decoy.start()


def run_integration_test() -> None:
    ModelPipeline._require_neo()
    with tempfile.TemporaryDirectory(prefix="shadow6-neo-") as temp_dir:
        dataset = str(Path(temp_dir) / "data.csv")
        rf_model = str(Path(temp_dir) / "rf.json")
        lstm_model = str(Path(temp_dir) / "lstm.pt")
        ModelPipeline.generate_dummy_dataset(dataset, samples=1_000)
        ModelPipeline.train_model(dataset, rf_model)
        ModelPipeline.train_lstm_model(dataset, lstm_model, epochs=1)
        SafeRandomForestModel.load(rf_model)
        loaded = LSTMModel(lstm_model)
        if loaded.predict_sequence([[128, 1.0, 1, 74, 0.001]] * loaded.window_size) not in (0, 1):
            raise AssertionError("LSTM inference returned an invalid class")
    logger.info("Neo integration test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Shadow6 Neo RF/LSTM detector")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--test", action="store_true")
    actions.add_argument("--generate-dummy", metavar="CSV")
    actions.add_argument("--extract-pcap", nargs=3, metavar=("NORMAL_PCAP", "PROBE_PCAP", "OUT_CSV"))
    actions.add_argument("--train", nargs=2, metavar=("DATASET_CSV", "MODEL_OUT"))
    actions.add_argument("--detect", action="store_true")
    parser.add_argument("--model-type", choices=("rf", "lstm"), default="rf")
    parser.add_argument("--model-path", help="Safe JSON RF model or weights-only LSTM model")
    parser.add_argument("--interface", default="any")
    parser.add_argument("--window-size", type=int, default=10)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--decoy", action="store_true")
    parser.add_argument("--decoy-host", default="127.0.0.1")
    parser.add_argument("--decoy-port", type=int, default=8080)
    args = parser.parse_args()

    if args.test:
        run_integration_test()
        return 0
    if args.generate_dummy:
        ModelPipeline.generate_dummy_dataset(args.generate_dummy)
        return 0
    if args.extract_pcap:
        ModelPipeline.extract_pcap_to_csv(*args.extract_pcap)
        return 0
    if args.train:
        if args.model_type == "rf":
            ModelPipeline.train_model(*args.train)
        else:
            ModelPipeline.train_lstm_model(*args.train, args.window_size, args.epochs)
        return 0
    if not args.model_path:
        parser.error("--detect requires --model-path")
    decoy = DecoyManager(args.decoy_port, args.decoy_host) if args.decoy else None
    if decoy:
        decoy.start()
    try:
        RealTimeDetector(args.model_path, args.model_type, args.interface, decoy).sniff_loop()
    except KeyboardInterrupt:
        pass
    finally:
        if decoy:
            decoy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
