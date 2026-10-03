"""Explicit lifecycle capabilities: declarations never replace runtime facts."""
import os
import shutil
import sys

NATIVE = {'systemd':'systemctl','openrc':'rc-service','runit':'sv',
          'sysv':'service','procd':'ubus','rc.d':'service','launchd':'launchctl','guix':'herd'}


def capabilities(backend='strong'):
    if backend == 'strong':
        available = sys.platform == 'linux' and hasattr(os,'pidfd_open')
        if available:
            try:
                descriptor = os.pidfd_open(os.getpid())
                os.close(descriptor)
            except OSError: available = False
        state = 'available' if available else 'unavailable'
        return {'schema':'shadow6.supervisor-capabilities.v1','backend':'linux-pidfd',
                'availability':state,'exactProcessIdentity':state,'pidReuseProtection':state,
                'componentGroupFailClosed':state,'startupObservation':state,
                'runtimeObservation':state,'driftRevalidation':state,
                'bootIntegration':'unavailable','nativeLogging':'unavailable'}
    if backend not in NATIVE:raise ValueError('unknown supervisor backend')
    manager = shutil.which(NATIVE[backend])
    # Generating a unit is not activation, exact manager->PID mapping or proof
    # of readiness. Native definitions launch the canonical component runner.
    return {'schema':'shadow6.supervisor-capabilities.v1','backend':backend,
            'availability':'partial' if manager else 'unavailable','manager':manager,
            'definitionGeneration':'available','activation':'explicit-operator-action',
            'exactProcessIdentity':'partial','pidReuseProtection':'partial',
            'componentGroupFailClosed':'available' if sys.platform == 'linux' else 'unavailable',
            'startupObservation':'available' if sys.platform == 'linux' else 'unavailable',
            'runtimeObservation':'available' if sys.platform == 'linux' else 'unavailable',
            'driftRevalidation':'available','bootIntegration':'partial' if manager else 'unavailable',
            'nativeLogging':'partial' if backend in {'systemd','procd','launchd','guix'} else 'unavailable'}
