#!/bin/bash
# Shadow6-Rust Security Audit & Unit Test Suite
# Using single thread to ensure clean environment for LPD/UDP tests.

echo "[*] Running Rust Security & Integration Test Suite..."
cargo test -- --nocapture --test-threads=1
