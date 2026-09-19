"""Resolve the Shadow6 tree that an entry point should operate on.

Installed entry points live in ``<prefix>/bin`` and their companion modules in
``<prefix>/share/shadow6/modules`` or ``<prefix>/share/shadow6/assistants``,
while the tree they inspect is installed at ``<prefix>/share/shadow6/tree``.
Deriving the tree from ``Path(__file__).parents[1]`` therefore yields the
installation prefix, and the previous hard-coded ``/usr/local`` fallback broke
every other prefix and staged ``DESTDIR`` installation.

Resolution order is explicit: ``SHADOW6_ROOT``, then the source-checkout
location, then the installed tree of the nearest enclosing installation prefix.
The source-checkout candidate is tested first so a checkout that happens to sit
below an installation prefix still operates on itself.
"""
import os
from pathlib import Path

#: Environment override honoured by every entry point that needs a tree.
TREE_ENV = "SHADOW6_ROOT"

#: File that identifies a directory as a Shadow6 source or installed tree.
TREE_MARKER = "Makefile"

#: Installed tree location relative to an installation prefix.
TREE_RELATIVE = Path("share") / "shadow6" / "tree"


def installed_tree(prefix) -> Path:
    """Return the tree location ``make install`` uses for an installation prefix."""
    return Path(prefix) / TREE_RELATIVE


def is_tree(candidate) -> bool:
    """Return True when the directory holds a Shadow6 tree."""
    return (Path(candidate) / TREE_MARKER).is_file()


def installation_prefixes(script) -> list:
    """Return enclosing installation prefixes, deepest first.

    A prefix is a directory that owns a ``bin`` directory or a ``share/shadow6``
    layout.  The deepest match is the prefix the running script was installed
    into, which keeps staged ``DESTDIR`` installs working.
    """
    prefixes = []
    seen = set()
    for ancestor in Path(script).resolve().parents:
        if ancestor in seen:
            continue
        seen.add(ancestor)
        if (ancestor / "share" / "shadow6").is_dir() or (ancestor / "bin").is_dir():
            prefixes.append(ancestor)
    return prefixes


def resolve_tree(*candidates) -> Path:
    """Return the first candidate that is a Shadow6 tree, honouring the override.

    The first candidate is returned unchanged when none of them is a tree so a
    misconfigured installation reports the path it actually used.
    """
    override = os.environ.get(TREE_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if not candidates:
        raise ValueError("resolve_tree requires at least one candidate root")
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if is_tree(path):
            return path.resolve()
    return Path(candidates[0]).expanduser().resolve()


def tree_root(script) -> Path:
    """Return the tree the entry point at ``script`` (its ``__file__``) describes."""
    override = os.environ.get(TREE_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    path = Path(script).resolve()
    candidates = []
    if len(path.parents) > 1:
        # Source checkout: <tree>/<component>/<script>.
        candidates.append(path.parents[1])
    for prefix in installation_prefixes(path):
        candidates.append(installed_tree(prefix))
    if not candidates:
        return path.parent
    return resolve_tree(*candidates)
