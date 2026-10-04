from pathlib import Path
from .profile_registry import profiles
def inspect_profile(catalog, core, profile):
    p=next(x for x in profiles(core) if x['id']==profile)
    path=Path(catalog.inspect(core)['executable'])
    return {'core':core,'profile':profile,'available':path.is_file() and path.stat().st_mode & 0o111 != 0,'artifact':str(path),'reason':None if path.is_file() else 'binary unavailable'}
def installed_profiles(catalog):
    rows=[inspect_profile(catalog,p['core'],p['id']) for p in profiles()]
    return {'schema':'shadow6.installed-profile-catalog.v1','profiles':rows,'availableProfiles':[x['profile'] for x in rows if x['available']]}
