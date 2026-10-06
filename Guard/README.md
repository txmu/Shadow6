# Shadow6 Guard

Guard owns perimeter/exposure policy: SPA/IP windows, rate control, AntiProbe,
Broker Shield and TLS/Web facade. An IP unlock is not session authentication.
S6EPE independently authenticates stream/message sessions and datagrams before
forwarding payloads; Gate independently provides an authenticated encrypted
Shadow6 path; Core owns native data-plane semantics.

Explicit optional combinations are S6EPE -> Core, Guard -> S6EPE -> Core,
S6EPE -> Gate -> Core and Guard -> S6EPE -> Gate -> Core. No build/install step
silently activates Gate or requires the complete stack. In an envelope service,
enabled Guard forwarding features must target the EPE listener. See
[configuration, lifecycle and verification boundaries](../docs/service-connections.md).
