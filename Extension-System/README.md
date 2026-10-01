# Shadow6 combined extension contract

The extension mechanism was integrated during the 2026-09-01 to 2026-09-06
transition, building on the platform boundaries designed at the end of August.
The first visible repository integration was recorded immediately afterward.
It is a component-layer contract, so adding or using an extension does not
change a Native Core wire protocol or require rebuilding an Android APK.

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

## Entrypoints and lifecycle

Use the standalone command for a local transaction:

```sh
shadow6-extensions --core Core-Go/shadow6-go-crosed \
  --request request.json --crosed-trust crosed-trust.json \
  --bindings Slot-System/bindings.json --plugin-root plugins
```

The same operation is exposed as `extensions.invoke` by Control Center and is
therefore discoverable through JSONL, HTTP, MCP, LSP and OpenAI function tools.
It remains a mutating operation and requires explicit operator approval. The
unified `shadow6` CLI also lists the route without starting it. Existing Plugin,
Slot and Crosed commands remain valid and are not silently redirected.

The transaction order is fixed: securely read the request, parse the single
application frame, verify the signed Crosed grant against a private snapshot,
resolve an enabled signed provider, then invoke it in the Plugin sandbox. Any
failure denies the complete transaction. Results are bounded `shadow6.extension.v1`
objects; no extension provider can load into a Core, choose a host command, add
a listener, or bypass the Core's capability and domain policy.
