# Shadow6 combined extension contract

`shadow6-extensions` joins the three extension boundaries without weakening
any of them:

1. an explicit `*-crosed` Core validates the signed, fresh Crosed request and
   computes its build/request/Mod/capability/domain-policy intersection;
2. the signed request contains exactly one versioned `shadow.extension` v1
   application document, which is passed through the common bounded UTF-8 JSON
   frame parser and whose source/target domains must equal the signed envelope;
3. a typed Slot must have at least one enabled provider whose signed Plugin
   manifest authorizes both the capability and hook. The provider continues to
   execute out of process under the Plugin resource and network sandbox.

No partial fallback exists. A missing application capability, mismatched domain,
unsupported schema, insufficient Crosed level, absent provider, bad Plugin
signature, or provider failure denies the entire transaction. Default Core
builds cannot be selected by the Control Center transport policy; the operator
must explicitly select an owner-controlled `shadow6-*-crosed` binary and enable
mutating Control API operations.

The application document inside the Crosed request has this exact schema:

```json
{
  "protocol": "shadow.extension",
  "version": 1,
  "slot": "slot.chat.filter",
  "source_domain": "work",
  "target_domain": "vault",
  "payload": {"text": "example"}
}
```

It is stored as the sole `payload.application` member of the signed Crosed
request. Privileged level 3/4 Slots additionally require the existing explicit
`--allow-privileged` operator approval.
