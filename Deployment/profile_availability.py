"""Bounded installed-artifact admission from the Native Profile authority.

Build prerequisites are informational: an installed runtime never requires a
compiler and this module never downloads, installs or builds anything.
"""
import os
import socket
import sys
try:
    from .profile_registry import profiles, select_profile
except ImportError:
    from profile_registry import profiles, select_profile


def inspect_profile(catalog, core, profile=None, *, report=None):
    try:
        from .service_runtime import feature_report
    except ImportError:
        from service_runtime import feature_report
    from feature_contract import validate_feature_report
    selected = select_profile(core, profile)
    diagnostics = []
    def issue(code, message, action):
        diagnostics.append(dict(code=code, message=message, action=action))
    try:
        report = report if report is not None else feature_report(catalog.inspect(core)['executable'])
        validate_feature_report(report, 'shadow6-' + core)
        if selected['applicationBoundary'] not in report['application_boundaries']:
            raise ValueError('installed binary does not declare this Profile boundary')
    except FileNotFoundError:
        issue('NativeArtifactMissing', 'The selected Native Core binary is not installed.',
              'Install the prebuilt ' + selected['artifact'] + '; then retry setup. Run never builds a Core.')
    except (ValueError, OSError, KeyError, TypeError) as error:
        dependencies = ', '.join(selected['requirements']['libraries'])
        issue('NativeFeatureContractUnavailable', str(error),
              'Install a matching prebuilt artifact with its runtime libraries'
              + (' (' + dependencies + ')' if dependencies else '')
              + '; stop existing services before an explicit upgrade and relock.')
    if sys.platform != 'linux' or not hasattr(os, 'pidfd_open'):
        issue('NamedSupervisorUnavailable', 'The installed Named Service supervisor requires Linux pidfd.',
              'Use a platform with the declared supervisor contract; native-init lifecycle support is not yet verified here.')
    for feature in selected['requirements']['kernelFeatures']:
        if feature == 'sctp':
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP): pass
            except OSError:
                issue('KernelSCTPUnavailable', 'The selected Profile requires kernel SCTP sockets.',
                      'Have the operator enable SCTP kernel support; then repeat doctor/setup with the same Profile.')
    return dict(schema='shadow6.installed-profile.v1', core=core, profile=selected['id'],
        available=not diagnostics, diagnostics=diagnostics,
        buildPrerequisites=selected['requirements']['toolchains'],
        runtimeRequirements={key: selected['requirements'][key] for key in ('libraries', 'kernelFeatures')},
        evidence='bounded-installed-feature-probe-and-runtime-prerequisites')


def installed_profiles(catalog):
    # Probe each independently compiled artifact once, including Gleam's two
    # explicit Profile contracts. Failed probes remain explicit diagnostics.
    try:
        from .service_runtime import feature_report
    except ImportError:
        from service_runtime import feature_report
    reports = {}
    result = []
    for selected in profiles():
        core = selected['core']
        if core not in reports:
            try: reports[core] = feature_report(catalog.inspect(core)['executable'])
            except FileNotFoundError: pass  # Keep the actionable missing-artifact diagnostic.
            except (ValueError, OSError): reports[core] = {}
        result.append(inspect_profile(catalog, core, selected['id'], report=reports.get(core)))
    return dict(schema='shadow6.installed-profile-catalog.v1', profiles=result,
        availableProfiles=[item['profile'] for item in result if item['available']])
