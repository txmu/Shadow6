# Shadow6 signed online repositories

Place bounded `.s6pkg`, `.zip`, or `.tar.gz` packages in a directory, create an
Ed25519 key, and run `shadow6 repo build ...` (or
`shadow6 component repo -- build ...`) to generate `index.json`. Publish that
directory with any HTTPS static server. The bundled server defaults to
loopback; a non-loopback bind is rejected unless a TLS certificate and key are
provided explicitly.

Clients trust an explicit signer public key, verify the canonical signed index,
then check declared size and SHA-256 while downloading atomically. HTTP is
accepted only for loopback development. Package Manager performs its own
package signature verification after repository verification; the layers are
independent. Android accepts only HTTPS and verifies the Ed25519 index before
saving a source.
