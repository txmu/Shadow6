"""Deployment import facade for the shared Profile Registry and Limits."""
from pathlib import Path
import sys
_root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(_root/'Crosed'))
from native_profiles import *
from limits import HostBudget, LimitResolver, LimitResolution, validate_policy
