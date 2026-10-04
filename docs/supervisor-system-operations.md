# Supervisor system-operation interface

The Linux pidfd supervisor remains the only runtime lifecycle backend with the
current process-identity and owned-socket evidence. Other native managers still
report partial or degraded lifecycle capabilities. `shadow6 init --capabilities`
also advertises `shadow6.system-operation.v1`, a fixed request format for an
external system operator to implement without adding platform commands to the
Core runner.

For a locked service, `shadow6 init --system launchd --named-service NAME
--operation activate` emits one short-lived JSON request. The allowed operation
names are `install-definition`, `activate`, `deactivate`, `restart`, `status`,
`remove-definition`, and `logs`. A request carries a derived service label,
the DeploymentLock digest, the private launch-plan path, and a bounded expiry.
It has no command, argv, shell text, arbitrary environment, or user-selected
system unit name.

An OS integration implements `Deployment.system_operations.SystemOperationsProvider`.
Its platform mapping must use fixed system APIs and recheck the lock digest and
plan material before mutating a service. It returns a typed receipt bound to
the request ID and lock. An `activate` receipt cannot claim application
readiness; readiness still needs a separate process-owned endpoint and ready
event observation. Secret paths and native config contents do not go into the
request.

The provider API is an extension point for system operations, not evidence of
cross-platform lifecycle parity. No launchd, OpenRC, runit, SysV, rc.d, procd,
or Guix provider is included or claimed as tested. Definition generation stays
available, and activation remains an explicit operator action.
