#!/usr/bin/env python3
"""Shadow6 packet anomaly detector and bounded decoy service."""

from __future__ import annotations

import argparse
import collections
import logging
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

from detector_core import (
    DecoyManager,
    HeuristicProbeModel,
    LogMonitor,
    SafeRandomForestModel,
    TrafficFeatures,
    atomic_write_csv,
    export_random_forest,
)


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
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


FEATURE_COLUMNS = ["packet_length", "entropy", "is_tcp", "payload_size", "iat"]


class ModelPipeline:
    @staticmethod
    def _require_ml() -> None:
        if not ML_AVAILABLE:
            raise RuntimeError("ML dependencies are missing; install requirements-ml.txt")

    @staticmethod
    def generate_dummy_dataset(output_path: str, samples: int = 10_000) -> None:
        ModelPipeline._require_ml()
        if samples < 100:
            raise ValueError("at least 100 samples are required")
        import random

        data = []
        for _ in range(samples):
            label = random.choices([0, 1], weights=[0.8, 0.2])[0]
            if label == 0:
                packet_length = random.randint(100, 1500)
                entropy = random.uniform(6.5, 8.0)
                is_tcp = random.choice([0, 1])
                iat = random.uniform(0.001, 0.2)
            else:
                packet_length = random.choice([64, 128, 256, 512])
                entropy = random.uniform(0.5, 5.0)
                is_tcp = 1
                iat = random.uniform(0.0001, 0.01)
            payload_size = max(0, packet_length - (54 if is_tcp else 42))
            data.append([packet_length, entropy, is_tcp, payload_size, iat, label])
        frame = pd.DataFrame(data, columns=FEATURE_COLUMNS + ["label"])
        atomic_write_csv(output_path, frame)
        logger.info("Generated %d training rows in %s", samples, output_path)

    @staticmethod
    def train_model(dataset_path: str, model_path: str) -> None:
        ModelPipeline._require_ml()
        frame = pd.read_csv(dataset_path)
        required = FEATURE_COLUMNS + ["label"]
        missing = set(required) - set(frame.columns)
        if missing:
            raise ValueError(f"dataset is missing columns: {sorted(missing)}")
        frame = frame[required].apply(pd.to_numeric, errors="raise")
        if len(frame) < 100 or not bool(np.isfinite(frame.to_numpy(dtype=float)).all()):
            raise ValueError("dataset must contain at least 100 finite rows")
        if (
            (frame["packet_length"] < 0).any()
            or ((frame["entropy"] < 0) | (frame["entropy"] > 8)).any()
            or (~frame["is_tcp"].isin([0, 1])).any()
            or (frame["payload_size"] < 0).any()
            or (frame["payload_size"] > frame["packet_length"]).any()
            or (frame["iat"] < 0).any()
        ):
            raise ValueError("dataset contains out-of-range feature values")
        labels = sorted(frame["label"].unique().tolist())
        if labels != [0, 1]:
            raise ValueError("dataset labels must be exactly 0 and 1")
        train_x, test_x, train_y, test_y = train_test_split(
            frame[FEATURE_COLUMNS],
            frame["label"],
            test_size=0.2,
            random_state=42,
            stratify=frame["label"],
        )
        classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )
        classifier.fit(train_x, train_y)
        logger.info("Model test accuracy: %.4f", classifier.score(test_x, test_y))
        logger.info("\n%s", classification_report(test_y, classifier.predict(test_x), zero_division=0))
        export_random_forest(classifier, model_path)
        logger.info("Persisted inert JSON model to %s", model_path)


class RealTimeDetector:
    def __init__(self, model_path: str | None, interface: str, decoy: DecoyManager | None = None):
        self.interface = interface
        self.decoy = decoy
        self.last_seen: collections.OrderedDict[tuple, float] = collections.OrderedDict()
        if model_path:
            self.classifier = SafeRandomForestModel.load(model_path)
            logger.info("Loaded validated JSON model from %s", model_path)
        else:
            self.classifier = HeuristicProbeModel()
            logger.warning("No model configured; using conservative heuristic detection")

    def sniff_loop(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("real-time AF_PACKET capture requires root or CAP_NET_RAW")
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as raw_socket:
            if self.interface != "any":
                available = {name for _, name in socket.if_nameindex()}
                if self.interface not in available:
                    raise ValueError(f"unknown interface: {self.interface}")
                raw_socket.bind((self.interface, 0))
            logger.info("Started packet capture on %s", self.interface)
            while True:
                packet, _ = raw_socket.recvfrom(65_535)
                now = time.monotonic()
                packet_length, entropy, is_tcp, payload_size = TrafficFeatures.extract_features(packet)
                flow = TrafficFeatures.flow_key(packet)
                iat = max(0.0, now - self.last_seen.get(flow, now))
                self.last_seen[flow] = now
                self.last_seen.move_to_end(flow)
                if len(self.last_seen) > 10_000:
                    self.last_seen.popitem(last=False)
                if payload_size == 0:
                    continue
                prediction = self.classifier.predict([[packet_length, entropy, is_tcp, payload_size, iat]])[0]
                if prediction == 1:
                    logger.warning(
                        "MALICIOUS PROBE DETECTED: Len:%d Ent:%.2f TCP:%d IAT:%.4f",
                        packet_length,
                        entropy,
                        is_tcp,
                        iat,
                    )
                    if self.decoy:
                        self.decoy.start()


def run_integration_test() -> None:
    logger.info("=== BEGIN DETECTOR INTEGRATION TEST ===")
    with tempfile.TemporaryDirectory(prefix="shadow6-detector-") as temp_dir:
        dataset = str(Path(temp_dir) / "data.csv")
        model = str(Path(temp_dir) / "model.json")
        ModelPipeline.generate_dummy_dataset(dataset, samples=1_000)
        ModelPipeline.train_model(dataset, model)
        loaded = SafeRandomForestModel.load(model)
        if loaded.predict([[128, 1.0, 1, 74, 0.001]])[0] != 1:
            raise AssertionError("trained model failed the synthetic probe sanity check")
        if TrafficFeatures.calculate_entropy(b"A" * 100) != 0.0:
            raise AssertionError("entropy calculation failed")

        decoy = DecoyManager(tarpit_port=0, hold_seconds=3)
        decoy.start()
        try:
            started = time.monotonic()
            with socket.create_connection(("127.0.0.1", decoy.tarpit_port), timeout=3) as client:
                client.settimeout(3)
                response = client.recv(1024)
            if b"X-Decoy" not in response or time.monotonic() - started < 0.8:
                raise AssertionError("bounded tarpit behavior is invalid")
        finally:
            decoy.stop()
    logger.info("=== DETECTOR INTEGRATION TEST PASSED ===")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shadow6 packet anomaly detector")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--test", action="store_true", help="Run the integration test")
    actions.add_argument("--generate-dummy", metavar="CSV", help="Generate a synthetic CSV dataset")
    actions.add_argument("--train", nargs=2, metavar=("DATASET_CSV", "MODEL_JSON"), help="Train and export a safe JSON model")
    actions.add_argument("--detect", action="store_true", help="Start real-time packet detection")
    parser.add_argument("--interface", default="any", help="Capture interface")
    parser.add_argument("--model-path", help="Validated Shadow6 JSON model; omit for heuristic mode")
    parser.add_argument("--watch-log", metavar="LOG_FILE", help="Watch a relay log for probe alerts")
    parser.add_argument("--decoy", action="store_true", help="Start the bounded decoy service")
    parser.add_argument("--decoy-host", default="127.0.0.1", help="Decoy bind address")
    parser.add_argument("--decoy-port", type=int, default=8080, help="Decoy TCP port")
    parser.add_argument("--decoy-max-clients", type=int, default=64, help="Maximum concurrent decoy clients")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    if args.test:
        run_integration_test()
        return 0
    if args.generate_dummy:
        ModelPipeline.generate_dummy_dataset(args.generate_dummy)
    if args.train:
        ModelPipeline.train_model(*args.train)

    decoy = None
    if args.decoy:
        decoy = DecoyManager(args.decoy_port, args.decoy_host, args.decoy_max_clients)
        decoy.start()

    stop_event = threading.Event()
    monitor_thread = None
    if args.watch_log:
        monitor_thread = threading.Thread(
            target=LogMonitor(args.watch_log, decoy, stop_event).tail_log,
            daemon=True,
        )
        monitor_thread.start()

    try:
        if args.detect:
            RealTimeDetector(args.model_path, args.interface, decoy).sniff_loop()
        elif args.watch_log or args.decoy:
            while monitor_thread is None or monitor_thread.is_alive() or decoy:
                time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        stop_event.set()
        if decoy:
            decoy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
