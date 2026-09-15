# Detector and Sentinel response policy

The RF and Neo detectors emit bounded `SHADOW6_THREAT` events containing schema
version 1, the packet's directional source IP and destination port. Sentinel
rejects malformed events, duplicate JSON fields and unknown schemas. A textual
alert alone cannot trigger network rotation.

Global MTD requires evidence from at least three different source addresses and
three destination ports within 60 seconds. Repeated source/port pairs count
once. The evidence cache holds at most 4096 pairs and rejects new entries when
full; old evidence expires by time. `--score-threshold` and `--score-window`
configure the evidence threshold and lifetime.

A separate token bucket permits one global rotation attempt per hour by
default (`--rotation-interval 3600`). The normal cooldown and exponential
failure backoff also apply. Failed, timed-out and exceptional orchestrator
attempts consume their budget, and subprocess execution is bounded to 120
seconds with no captured-output accumulation.

This is aggregation by one local detector, not distributed consensus. Source IP
addresses in observed traffic can be spoofed; evidence diversity is not proof
of independent attackers. The rotation budget bounds disruption even when an
attacker can manufacture enough detector evidence. These settings do not apply
Guard firewall rules or automatically quarantine a source. The host firewall
and any operator-authorized Guard policy remain separate deployment controls.
