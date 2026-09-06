Dependencies: install ../requirements.txt in an isolated virtual environment.

To Run Unit Tests    : python3 test_shadow6_auto.py
To Apply Topology    : python3 shadow6_auto.py apply -f shadow-net.yaml
To SPA Knock & Start : SHADOW6_SPA_SECRET='<SECRET>' python3 shadow6_auto.py client-knock <IP> <PORT>
To Launch TUI Dash   : python3 shadow6_auto.py dashboard

Notes:
- Every node in one topology must select the same core engine. Core-Go and
  Core-Rust intentionally use different wire protocols and are not mixed.
- Plain ws:// control links are accepted only for loopback test topologies.
- Remote SSH nodes must provide a known_hosts file; host-key checking is never
  disabled.
- Generated configuration files are owner-only (0600).
- init_system supports systemd, openrc, runit, sysv, rc.d/FreeBSD,
  procd/OpenWrt, launchd/macOS, and guix/Guix System (plus documented aliases).
- Guix deployment writes a Shepherd fragment but deliberately does not run a
  whole-system reconfigure; runit activation is also left explicit.
