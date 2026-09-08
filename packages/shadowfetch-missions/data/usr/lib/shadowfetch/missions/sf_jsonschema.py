"""A small, strict JSON Schema validator for provider manifests.

Why this exists rather than the jsonschema package: the manifest has to be
validated on the INSTALLED system, inside the mission engine, and no shipped
Shadowfetch package depends on python3-jsonschema -- live-build never installs
it, so relying on it would mean a registry that works on the build host and
fails on a user's machine. This module is standard library only.

The dangerous failure mode for a hand-written validator is silently ignoring a
keyword it does not implement: the schema author believes a constraint is
enforced and it never runs. So this validator REFUSES a schema containing any
keyword it does not implement, and refuses an unknown "type". A constraint
either runs or the whole validation is an error; it is never quietly skipped.

Supported: type, enum, const, required, properties, additionalProperties,
propertyNames, items, minItems, maxItems, uniqueItems, minLength, maxLength,
pattern, minimum, maximum, allOf, anyOf, oneOf, not, if/then/else, and the
annotation-only keywords $schema, $id, title, description, examples, default,
deprecated.
"""
from __future__ import annotations

import re

__all__ = ["SchemaError", "ValidationError", "validate", "check_schema"]

_ANNOTATIONS = frozenset({
    "$schema", "$id", "title", "description", "examples", "default", "deprecated",
})
_SUPPORTED = frozenset({
    "type", "enum", "const", "required", "properties", "additionalProperties",
    "propertyNames", "items", "minItems", "maxItems", "uniqueItems",
    "minLength", "maxLength", "pattern", "minimum", "maximum",
    "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
}) | _ANNOTATIONS
_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "number": (int, float), "integer": int, "null": type(None),
}


class SchemaError(Exception):
    """The schema itself is unusable -- a bug in the schema, not the document."""


class ValidationError(Exception):
    """The document does not satisfy the schema."""

    def __init__(self, path, message):
        self.path = path or "<root>"
        self.message = message
        super().__init__(f"{self.path}: {message}")


def check_schema(schema, path="<schema>"):
    """Refuse a schema this validator cannot fully enforce."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaError(f"{path}: schema must be an object or boolean")
    unknown = sorted(set(schema) - _SUPPORTED)
    if unknown:
        raise SchemaError(
            f"{path}: unsupported schema keyword(s) {', '.join(unknown)}. This "
            "validator refuses rather than ignoring them, because a silently "
            "skipped constraint is worse than no constraint.")
    declared = schema.get("type")
    for name in ([declared] if isinstance(declared, str) else declared or []):
        if name not in _TYPES:
            raise SchemaError(f"{path}: unknown type {name!r}")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise SchemaError(f"{path}: invalid pattern: {exc}") from exc
    for key in ("properties", "propertyNames"):
        value = schema.get(key)
        if key == "properties" and isinstance(value, dict):
            for name, sub in value.items():
                check_schema(sub, f"{path}.properties.{name}")
        elif key == "propertyNames" and value is not None:
            check_schema(value, f"{path}.propertyNames")
    for key in ("items", "additionalProperties", "not", "if", "then", "else"):
        if key in schema and schema[key] is not None:
            check_schema(schema[key], f"{path}.{key}")
    for key in ("allOf", "anyOf", "oneOf"):
        for index, sub in enumerate(schema.get(key) or []):
            check_schema(sub, f"{path}.{key}[{index}]")


def validate(document, schema, *, path=""):
    """Raise ValidationError on the first failure. Schema is checked first."""
    check_schema(schema)
    _validate(document, schema, path)
    return True


def _fail(path, message):
    raise ValidationError(path, message)


def _matches(document, schema, path):
    try:
        _validate(document, schema, path)
        return True
    except ValidationError:
        return False


def _validate(document, schema, path):
    if schema is True or schema == {}:
        return
    if schema is False:
        _fail(path, "no value is permitted here")

    declared = schema.get("type")
    if declared is not None:
        names = [declared] if isinstance(declared, str) else list(declared)
        if not any(_is_type(document, name) for name in names):
            _fail(path, f"expected {' or '.join(names)}, got {type(document).__name__}")

    if "const" in schema and document != schema["const"]:
        _fail(path, f"must be {schema['const']!r}")
    if "enum" in schema and document not in schema["enum"]:
        _fail(path, f"must be one of {schema['enum']!r}")

    if isinstance(document, str):
        if "minLength" in schema and len(document) < schema["minLength"]:
            _fail(path, f"shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(document) > schema["maxLength"]:
            _fail(path, f"longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], document):
            _fail(path, f"does not match {schema['pattern']}")

    if _is_type(document, "number"):
        if "minimum" in schema and document < schema["minimum"]:
            _fail(path, f"below minimum {schema['minimum']}")
        if "maximum" in schema and document > schema["maximum"]:
            _fail(path, f"above maximum {schema['maximum']}")

    if isinstance(document, list):
        if "minItems" in schema and len(document) < schema["minItems"]:
            _fail(path, f"needs at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(document) > schema["maxItems"]:
            _fail(path, f"allows at most {schema['maxItems']} item(s)")
        if schema.get("uniqueItems"):
            seen = []
            for item in document:
                if item in seen:
                    _fail(path, f"duplicate item {item!r}")
                seen.append(item)
        if "items" in schema:
            for index, item in enumerate(document):
                _validate(item, schema["items"], f"{path}[{index}]")

    if isinstance(document, dict):
        for name in schema.get("required", []):
            if name not in document:
                _fail(path, f"missing required property {name!r}")
        properties = schema.get("properties") or {}
        for name, value in document.items():
            child = f"{path}.{name}" if path else name
            if "propertyNames" in schema:
                _validate(name, schema["propertyNames"], child)
            if name in properties:
                _validate(value, properties[name], child)
            elif "additionalProperties" in schema:
                extra = schema["additionalProperties"]
                if extra is False:
                    _fail(child, "property is not permitted by the schema")
                elif extra is not True:
                    _validate(value, extra, child)

    for index, sub in enumerate(schema.get("allOf") or []):
        _validate(document, sub, path)
    if "anyOf" in schema and not any(_matches(document, s, path) for s in schema["anyOf"]):
        _fail(path, "does not match any permitted alternative")
    if "oneOf" in schema:
        hits = sum(1 for s in schema["oneOf"] if _matches(document, s, path))
        if hits != 1:
            _fail(path, f"must match exactly one alternative, matched {hits}")
    if "not" in schema and _matches(document, schema["not"], path):
        _fail(path, "matches a forbidden alternative")
    if "if" in schema:
        if _matches(document, schema["if"], path):
            if "then" in schema:
                _validate(document, schema["then"], path)
        elif "else" in schema:
            _validate(document, schema["else"], path)


def _is_type(value, name):
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    expected = _TYPES[name]
    if isinstance(value, bool) and expected in (int, (int, float)):
        return False
    return isinstance(value, expected)
