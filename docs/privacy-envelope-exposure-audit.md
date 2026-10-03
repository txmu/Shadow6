# Privacy Envelope Exposure Audit

| Surface | Classification | Decision |
| --- | --- | --- |
| Native Core feature reports | PUBLIC_INTENTIONAL | Unchanged; required for local capability discovery. |
| Control Center loopback API | LOCAL_ONLY | Remains loopback and bearer authenticated. |
| S6EPE pre-auth listener | PUBLIC_INTENTIONAL | Generic bounded rejection; no product/Core banner. |
| S6EPE authenticated transcript | ENCRYPTED_AUTHENTICATED | Internal domain separation may be used here. |
| Native Core listener when envelope is enabled | LOCAL_ONLY | Deployment policy binds it to private/loopback endpoint. |
| S6EPE metrics | LOCAL_ONLY | Counters only; no payloads, tokens or native data. |

The existing Core magic and native protocol labels were not changed.
