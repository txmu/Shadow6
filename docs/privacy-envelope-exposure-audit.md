# Privacy Envelope Exposure Audit

| Surface | Classification | Decision |
| --- | --- | --- |
| Native Core feature reports | PUBLIC_INTENTIONAL | Unchanged; required for local capability discovery. |
| Control Center loopback API | LOCAL_ONLY | Remains loopback and bearer authenticated. |
| S6EPE pre-auth listener | PUBLIC_INTENTIONAL | Generic bounded rejection; no product/Core banner. |
| S6EPE authenticated transcript | AUTHENTICATED; target ENCRYPTED_AUTHENTICATED remains planned | Direction-separated HMAC proofs; no outer encryption in the current implementation. Native payload confidentiality depends on the selected Core/transport. |
| Native Core listener when envelope is enabled | LOCAL_ONLY | Deployment policy binds it to private/loopback endpoint. |
| S6EPE metrics | LOCAL_ONLY | Counters only; no payloads, tokens or native data. |

The existing Core magic and native protocol labels were not changed.

Version 2 sends only random challenge bytes before stream authentication. Server
upstream creation follows verified client proof. UDP verifies direction, MAC,
timestamp and nonce before allocating a native upstream; replies are also
protected. The replay cache is bounded and process-local. Logs and metrics do
not include the auth key or forwarded bytes. Numeric IPv4/loopback checks are
implemented; deployment must still verify every other native listening address.

The encrypted-transcript target is preserved above with its current status.
See [verification evidence and remaining goals](review-2026-10-03.md).
