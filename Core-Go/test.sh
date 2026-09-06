#!/bin/bash
# Shadow6-Go Security Audit & Unit Test Suite
# Runs all tests sequentially (-p 1) to avoid LPD port conflicts.

echo "[*] Running Go Security & Integration Test Suite..."
go test -v -p 1 -count=1 ./...
