# Shadow6 Virtual Adapter

This optional, out-of-process adapter carries IP packets from an already
created TUN/TAP descriptor over an authenticated S6NA session. It never loads
code into a Core, never changes host routes or firewall rules, and never runs
operator-supplied commands. Interface creation and route activation remain
explicit local administrator actions.

The configuration is read once at startup from an owned, non-symlink regular
file. The transport key uses the same strict 32-byte secret-file contract as
S6NA. `mode` is `tun` for layer 3 or `tap` for layer 2; packets are validated
and bounded before entering stream 0. Both peers must use the same Core family
and S6NA limits.

Android uses the same packet contract through `VpnService`; Android owns the
virtual interface and does not require root or manipulate global routes.
