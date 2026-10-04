"""Installed/source import bridge for the shared Native Profile authority."""
from pathlib import Path
import sys

try:
    from native_profiles import (CORE_IDS, application_boundaries, artifact_map, bind_profile, native_material_paths, validate_profile_binding, validate_profile_realization,
        profile_digest, profiles, select_profile, topology_profile, transport_map)

except ModuleNotFoundError as error:
    if error.name != 'native_profiles':
        raise
    here = Path(__file__).resolve()
    locations = [here.parents[1] / 'Crosed', here.parents[1] / 'modules']
    for parent in here.parents:
        locations.append(parent / 'share/shadow6/modules')
    for location in locations:
        if (location / 'native_profiles.py').is_file():
            sys.path.insert(0, str(location))
            break
    from native_profiles import (CORE_IDS, application_boundaries, artifact_map, bind_profile, native_material_paths, validate_profile_binding, validate_profile_realization,
        profile_digest, profiles, select_profile, topology_profile, transport_map)

from limits import HostBudget, LimitResolver, LimitResolution, validate_policy
