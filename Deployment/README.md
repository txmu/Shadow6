# Shadow6 deployment and S6ABI/1

`shadow6.deployment.v1` is a strict, Core-neutral intent document. It names
logical Broker replica sets, node identities, loopback services, policies and
application requirements. It never contains private keys or native Core
arguments. `shadow6 deployment plan` translates it into a bounded plan that an
installed Core driver can apply without rebuilding the Core.

`S6ABI/1` is a process-boundary application contract. Control frames are
length-prefixed canonical JSON; data frames are bounded binary records. The
ABI reports the selected Core and its guarantees instead of pretending that
the twelve native wire protocols are compatible. S6AR1 carries control-plane
requests and S6P1 carries admission context.

Use the single acceptance gate:

```sh
shadow6 acceptance --manifest Deployment/example.deployment.json --source-only
```

CI supplies native feature reports and checksums with `--artifact-dir`. Cases
that cannot be run are explicitly `unavailable` or `not-run`; they are never
silently treated as native verification.
