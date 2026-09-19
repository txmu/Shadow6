# Counterstrike: Graduated Active Defense

Counterstrike (防守反击) is Shadow6's opt-in active-defense engine. It upgrades
the Detector layer from a single bounded tarpit into a **graduated, fully
operator-configured response ladder**, while preserving every existing safety
invariant: fail-closed defaults, strict parsing, bounded resources, and a
budgeted global MTD path.

It is pure Python (asyncio + the standard socket/HTTP building blocks) and
requires **no Core rebuild**.

## Design contract

- **Opt-in and fail-closed.** With no policy the engine is a no-op; detection
  behaves exactly as before. A policy sets `enabled: true` to arm anything.
- **Strict policy.** The policy is a JSON document parsed with unknown-field
  rejection, no floats, and no shell, loaded from a regular, non-symlink,
  owner-controlled, mode-`0600` file that is re-checked after opening.
- **Bounded everywhere.** Tracked attackers, concurrent engagements, per-source
  budgets, and a global per-minute ceiling are all capped. A spoofed-evidence
  flood cannot exhaust threads, sockets, or memory.
- **No outbound offense.** Counterstrike never initiates a connection to an
  attacker. Deception and engagement act only on transport the attacker already
  opened; the highest tier only *requests* rotation through the existing
  Sentinel, which keeps its multi-source/multi-port diversity and token budget.

## The response ladder

Events arrive as bounded `SHADOW6_THREAT` v1 lines (a directional source IP and
a destination port — never packet payload text). Each distinct hostile source
climbs a severity ladder; repeated attacks from the same address escalate.

| Tier | Name | Effect | Bound |
| --- | --- | --- | --- |
| 1 | `deception` | Always-on decoy lures (SSH/FTP/SMTP/MySQL/Redis/HTTP/401) that waste a scanner's time | ≤32 listeners, ≤256 clients each, ≤16 KiB bodies |
| 2 | `engagement` | Tarpit: hold a hostile connection open to burn attacker resources | ≤256 concurrent, hold ≤600 s, per-source/hour budget |
| 3 | `throttle` | Drip bytes back to an engaged source at a capped rate so tools stall | rate ≤65535 kbit/s, per-source/hour budget |
| 4 | `rotation` | Request global MTD rotation via the Sentinel | one token per interval + diversity threshold |

Lower tiers act on a single hostile source immediately. Rotation still requires
the Sentinel's own evidence diversity and rotation budget, so counterstrike can
never force an unbudgeted global network change.

## Configuration

Copy the example, then enable only the tiers you want:

```sh
cp Detector/counterstrike.policy.example.json /etc/shadow6/counterstrike.json
chmod 600 /etc/shadow6/counterstrike.json
```

Top-level fields:

- `version` (integer, must be `1`)
- `enabled` (boolean master switch; `false` force-disables every tier)
- `global_actions_per_minute` (integer 1–10000, global response ceiling)
- `attack_decay_seconds` (integer 60–86400, how long a source stays tracked)
- `tiers` (object with `deception`, `engagement`, `throttle`, `rotation`)

Validate a policy before deploying:

```sh
.venv/bin/python Detector/counterstrike.py --validate /etc/shadow6/counterstrike.json
```

## Running

Run the loopback self-test (binds only `127.0.0.1`, ephemeral ports):

```sh
.venv/bin/python Detector/counterstrike.py --test
```

Attach the engine to the live Sentinel so real `SHADOW6_THREAT` events drive the
ladder:

```sh
.venv/bin/python Detector/watch.py \
  --topo Auto-Orchestrator/local-test.yaml.example \
  --counterstrike-policy /etc/shadow6/counterstrike.json
```

## What it is not

Counterstrike is defensive deception and resource-exhaustion of *inbound*
hostile connections, plus a budgeted request to the existing MTD rotation. It is
not port scanning, exploitation, credential collection, arbitrary outbound
traffic, or firewall mutation. Host firewall and operator-authorized Guard
policy remain separate deployment controls.
