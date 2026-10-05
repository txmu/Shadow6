#!/usr/bin/env python3
"""Validate every Native Profile against installed/CI-provided artifacts."""
import argparse, json, pathlib, subprocess
from native_profiles import profiles
from Deployment.profile_registry import bind_profile, validate_profile_binding

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--artifact-root',required=True); args=ap.parse_args()
    root=pathlib.Path(args.artifact_root); rows=[]
    for profile in profiles():
        path=root/profile['artifact']; row={'profile':profile['id'],'core':profile['core'],'artifact':str(path),'contract':'ok','artifactAvailable':path.is_file()}
        try: validate_profile_binding(bind_profile(profile['core'],profile['id']),core=profile['core'])
        except Exception as e: row['contract']='error:'+str(e)
        if path.is_file():
            try:
                report=json.loads(subprocess.run([str(path),'--feature-report'],capture_output=True,text=True,timeout=8,check=True).stdout)
                row['featureReport']={'core':report.get('core'),'crosedMaxLevel':report.get('crosed_max_level'),'appTransport':report.get('app_transport')}
            except Exception as e: row['artifactError']=type(e).__name__+': '+str(e)
        rows.append(row)
    print(json.dumps({'schema':'shadow6.profile-validation.v1','profiles':rows,'count':len(rows),'contractsPassed':sum(r['contract']=='ok' for r in rows),'artifactsAvailable':sum(r['artifactAvailable'] for r in rows)},sort_keys=True,indent=2))
    return 0 if all(r['contract']=='ok' for r in rows) else 2
if __name__=='__main__': raise SystemExit(main())
