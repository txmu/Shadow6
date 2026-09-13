#!/usr/bin/env python3
"""Test harness for Core-Idris feature contract validation."""

import json
import shlex
import subprocess
import sys
from pathlib import Path

def run_command(cmd, check=True):
    """Run command and return output."""
    result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Command failed: {cmd}")
        print(f"stderr: {result.stderr}")
        sys.exit(1)
    return result.stdout.strip()

def test_feature_report():
    """Test feature report JSON output."""
    print("Testing feature report...")
    
    output = run_command("./shadow6-idris --feature-report")
    report = json.loads(output)
    
    # Validate required fields
    assert report["core"] == "shadow6-idris", "Core name mismatch"
    assert report["version"] == "1.1.0", "Version mismatch"
    assert report["utf8"] == True, "UTF-8 must be enabled"
    assert report["gate_compiled"] == True, "Gate must be compiled"
    assert report["gate_enabled_by_default"] == False, "Gate must be disabled by default"
    
    # Default build checks
    assert report["crosed_compiled"] == False, "Default build must have Crosed disabled"
    assert report["crosed_max_level"] == 0, "Default build must be level 0"
    assert report["app_transport"] == False, "Default build must have app transport disabled"
    assert report["qubes_isolation"] == False, "Default build must have Qubes disabled"
    assert len(report["crosed_capabilities"]) == 0, "Default build must have no capabilities"
    
    print("✓ Feature report validated")
    return True

def test_crosed_variant():
    """Test Crosed variant feature report if it exists."""
    if not Path("./shadow6-idris-crosed").exists():
        print("⊘ Crosed variant not built, skipping")
        return True
    
    print("Testing Crosed variant feature report...")
    
    output = run_command("./shadow6-idris-crosed --feature-report")
    report = json.loads(output)
    
    assert report["core"] == "shadow6-idris", "Core name mismatch"
    assert report["crosed_compiled"] == True, "Crosed variant must have Crosed enabled"
    assert report["crosed_max_level"] == 5, "Crosed variant must be level 5"
    assert report["app_transport"] == True, "Crosed variant must have app transport"
    assert report["qubes_isolation"] == True, "Crosed variant must have Qubes isolation"
    
    # Validate capability list
    expected_caps = [
        "core.hook",
        "core.lifecycle",
        "identity.assert",
        "identity.resolve",
        "observe.health",
        "observe.version",
        "policy.config",
        "policy.request",
        "transport.application",
        "transport.metadata"
    ]
    
    caps = sorted(report["crosed_capabilities"])
    expected_caps_sorted = sorted(expected_caps)
    
    assert caps == expected_caps_sorted, f"Capability mismatch: {caps} != {expected_caps_sorted}"
    
    print("✓ Crosed variant validated")
    return True

def test_version_output():
    """Test version output."""
    print("Testing version output...")
    
    output = run_command("./shadow6-idris --version")
    assert "Shadow6 Core-Idris 1.1.0" in output, "Version string mismatch"
    assert "Formally verified" in output, "Missing verification claim"
    
    print("✓ Version output validated")
    return True

def main():
    """Run all tests."""
    print("=== Core-Idris Feature Contract Tests ===\n")
    
    # Change to Core-Idris directory
    if Path("Core-Idris").exists():
        import os
        os.chdir("Core-Idris")
    
    if not Path("./shadow6-idris").exists():
        print("ERROR: shadow6-idris binary not found")
        print("Run: make core-idris")
        sys.exit(1)
    
    try:
        test_feature_report()
        test_crosed_variant()
        test_version_output()
        
        print("\n=== All Core-Idris tests passed ===")
        return 0
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except json.JSONDecodeError as e:
        print(f"\n✗ JSON parse error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
