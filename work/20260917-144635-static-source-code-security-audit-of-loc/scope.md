# Case Scope

## meta
- case_id: 20260917-144635-static-source-code-security-audit-of-loc
- created: 2026-09-17T14:46:35+00:00
- operator: local
- project_root: /home/admin/Shadow6
- primary_skill: reverse-engineering/SKILL.md
- primary_id: R0
- lead_role: lead
- specialist_roles: []
- hint: static source code security audit of local Shadow6 repository
- preset: none

## auth
- status: granted
- basis: operator-owned local repository; owner authorized static review in-session
- evidence_of_auth: repository owner (admin) is the operator and requested this review
- MUST NOT proceed if status != granted

## in_scope
- assets:
    - /home/admin/Shadow6 (local source tree, offline static review)
- surfaces: []
- activities: [static source audit, local in-process probe against owner-built binaries, unit tests, offline audit]

## out_of_scope
- assets: []
- activities: [dos, phishing_real_users, unrestricted_exfil]

## network_profile
- mode: offline
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.
    Presets: offline-sample | ctf-public | own-system

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: true
- checklist:
  - [x] auth.status = granted
  - [x] in_scope.assets non-empty OR offline sample path set
  - [x] network_profile.mode chosen
  - [x] out_of_scope reviewed
  - [x] roles assigned (see skills/ops/role-map.md)

## ops_refs
- skills/ops/scope-contract.md
- skills/ops/evidence-finding-path.md
- skills/ops/role-map.md
- skills/ops/timeline-workitem.md
- skills/ops/IDENTITY.md
