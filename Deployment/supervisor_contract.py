"""Explicit lifecycle capabilities: declarations never replace runtime facts."""
import os
import shutil
import sys

NATIVE = {'systemd':'systemctl','openrc':'rc-service','runit':'sv',
          'sysv':'service','procd':'ubus','rc.d':'service','launchd':'launchctl','guix':'herd',
          'windows-service':'sc.exe','smf':'svcadm','aix-src':'lssrc'}
SYSTEM_OPERATIONS = ['install-definition','activate','deactivate','restart',
                    'status','remove-definition','logs']


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
                'bootIntegration':'unavailable','nativeLogging':'unavailable',
                'systemOperationInterface':'available',
                'systemOperationProvider':'optional-external',
                'systemOperationSchema':'shadow6.system-operation.v1',
                'systemOperations':SYSTEM_OPERATIONS.copy()}
    if backend not in NATIVE:raise ValueError('unknown supervisor backend')
    manager = shutil.which(NATIVE[backend])
    # Generating a unit is not activation, exact manager->PID mapping or proof
    # of readiness. Native definitions launch the canonical component runner.
    native_observation = 'available' if sys.platform == 'linux' else 'unavailable'
    identity = 'strong' if sys.platform == 'linux' else 'degraded'
    return {'schema':'shadow6.supervisor-capabilities.v1','backend':backend,
            'availability':'partial' if manager else 'unavailable','manager':manager,
            'definitionGeneration':'available','activation':'explicit-operator-action',
            'exactProcessIdentity':identity,'pidReuseProtection':'strong' if sys.platform == 'linux' else 'degraded',
            'componentGroupFailClosed':'available' if sys.platform == 'linux' else 'unavailable',
            'startupObservation':native_observation,
            'runtimeObservation':native_observation,
            'readyEvent':'required','processAliveImpliesReady':False,
            'driftRevalidation':'available','bootIntegration':'partial' if manager else 'unavailable',
            'nativeLogging':'partial' if backend in {'systemd','procd','launchd','guix','smf'} else 'unavailable',
            'systemOperationInterface':'available',
            'systemOperationProvider':'optional-external',
            'systemOperationSchema':'shadow6.system-operation.v1',
            'systemOperations':SYSTEM_OPERATIONS.copy(),
            'nativeLifecycleParity':'unverified'}
