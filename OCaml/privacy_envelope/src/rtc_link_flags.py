"""Portable link flags for the optional Linux native WebRTC backend."""
import sys
print('(-ldl -lpthread)' if sys.platform.startswith('linux') else '()')
