#!/usr/bin/env python3
"""Bounded UTF-8 bundles and named-only interpolation for contributed text."""
from __future__ import annotations

import json
import os
import re
import stat
import string
import unicodedata
from pathlib import Path

LOCALE = re.compile(r"^[a-z]{2,3}(?:-[A-Z]{2})?$")
KEY = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")
FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_BUNDLE = 1_048_576
MAX_MESSAGES = 4096
MAX_TEXT = 4096
FORMATTER = string.Formatter()


class I18nError(ValueError):
    pass


def normalize_locale(value: str | None) -> str:
    if not isinstance(value, str) or len(value) > 16:
        return "en"
    parts = value.replace("_", "-").split("-")
    if len(parts) not in (1, 2):
        return "en"
    result = parts[0].lower() + ("-" + parts[1].upper() if len(parts) == 2 else "")
    return result if LOCALE.fullmatch(result) else "en"


def _fields(template: str) -> set[str]:
    fields = set()
    try:
        for _, field, spec, conversion in FORMATTER.parse(template):
            if field is not None:
                if not FIELD.fullmatch(field) or spec or conversion:
                    raise I18nError("only plain named placeholders are supported")
                fields.add(field)
    except ValueError as exc:
        raise I18nError("invalid translation placeholder") from exc
    return fields


def _text(value: object) -> bool:
    return (isinstance(value, str) and len(value) <= MAX_TEXT
            and not any(0xD800 <= ord(c) <= 0xDFFF or c == "\x00" for c in value)
            and unicodedata.normalize("NFC", value) == value)


def _object(pairs: list[tuple[str, object]]) -> dict[str, str]:
    result = {}
    for key, value in pairs:
        if key in result or len(key) > 256 or not KEY.fullmatch(key) or not _text(value):
            raise I18nError("duplicate or invalid translation key/value")
        _fields(value)
        result[key] = value
    if len(result) > MAX_MESSAGES:
        raise I18nError("too many translations")
    return result


def load_bundle(path: Path) -> dict[str, str]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_BUNDLE:
        raise I18nError("bundle must be a bounded regular non-symlink file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= MAX_BUNDLE
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)):
            raise I18nError("bundle changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(MAX_BUNDLE + 1)
    finally:
        os.close(fd)
    if len(payload) > MAX_BUNDLE:
        raise I18nError("bundle grew beyond its limit")
    try:
        source = payload.decode("utf-8", errors="strict")
        quoted = escaped = False
        depth = 0
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 1:
                    raise I18nError("translation bundles cannot contain nested containers")
            elif char in "}]":
                depth -= 1
        document = json.loads(source, object_pairs_hook=_object)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise I18nError("invalid UTF-8 translation bundle") from exc
    if not isinstance(document, dict):
        raise I18nError("bundle must be an object")
    return document


class Translator:
    def __init__(self, root: Path, locale: str = "en", fallback: str = "en"):
        self.root = root.resolve(strict=True)
        self.locale = normalize_locale(locale)
        self.fallback = normalize_locale(fallback)
        self.bundles = {}
        for name in dict.fromkeys((self.fallback, self.locale)):
            path = self.root / f"{name}.json"
            try:
                self.bundles[name] = load_bundle(path)
            except FileNotFoundError:
                if path.is_symlink():
                    raise I18nError("bundle must not be a symlink")
                self.bundles[name] = {}
        base, selected = self.bundles[self.fallback], self.bundles[self.locale]
        for key in base.keys() & selected.keys():
            if _fields(base[key]) != _fields(selected[key]):
                raise I18nError(f"placeholder mismatch for {key}")

    def text(self, key: str, **values: object) -> str:
        template = self.bundles[self.locale].get(key, self.bundles[self.fallback].get(key, key))
        if not _text(template):
            raise I18nError("invalid translation template")
        replacements = {}
        for name in _fields(template):
            value = values.get(name)
            if name not in values or type(value) not in (str, int, float, bool, type(None)):
                raise I18nError(f"invalid interpolation for {key}")
            try:
                replacements[name] = str(value)
            except ValueError as exc:
                raise I18nError("oversized interpolation value") from exc
            if len(replacements[name]) > MAX_TEXT:
                raise I18nError("oversized interpolation value")
        parts, size = [], 0
        for literal, field, _, _ in FORMATTER.parse(template):
            part = literal + (replacements[field] if field is not None else "")
            size += len(part)
            if size > MAX_TEXT:
                raise I18nError("translated output exceeds its limit")
            parts.append(part)
        return "".join(parts)
