# Shadow6 Package and Version Manager

`shadow6-pkg` installs signed `crosed-mod`, `plugin`, and `app` packages into
separate version directories. Installation verifies an Ed25519 signature and
every file digest before an atomic rename; activation is a small atomic JSON
record, so switching versions never edits an installed payload.

The manager does not execute packages or load code into a Core. Plugin and Slot
runtime isolation and Crosed grants remain independent mandatory boundaries.

Use `keygen`, `build`, `verify`, `install`, `list`, and `activate --help` for the
local-owner workflow. Private keys must be owner-controlled mode `0600` files.
