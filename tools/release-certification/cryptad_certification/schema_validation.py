"""Small offline JSON Schema validator for checked-in certification contracts."""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .io import read_json

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_SUPPORTED_SCHEMA_KEYS = frozenset(
    {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "title",
        "type",
        "additionalProperties",
        "required",
        "properties",
        "const",
        "enum",
        "pattern",
        "minLength",
        "minimum",
        "minItems",
        "maxItems",
        "uniqueItems",
        "items",
        "oneOf",
        "format",
    }
)


def validate_schema(value: Any, schema_filename: str) -> list[str]:
    """Validate a value against one confined, checked-in certification schema."""

    relative = Path(schema_filename)
    if relative.is_absolute() or len(relative.parts) != 1 or ".." in relative.parts:
        return ["$ references an unsafe certification schema"]
    target = _SCHEMA_DIR / relative
    if target.is_symlink() or not target.is_file():
        return ["$ certification schema is missing or unsafe"]
    resolved = target.resolve()
    try:
        resolved.relative_to(_SCHEMA_DIR.resolve())
    except ValueError:
        return ["$ certification schema escapes its directory"]
    try:
        schema = read_json(resolved)
    except (OSError, ValueError):
        return ["$ certification schema is malformed"]
    if not isinstance(schema, dict):
        return ["$ certification schema is malformed"]
    return _schema_errors(value, schema, schema, "$", {})


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    return left == right


def _matches_schema_type(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": type(value) is bool,
        "integer": type(value) is int,
        "null": value is None,
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def _schema_pointer(root: dict[str, Any], fragment: str) -> dict[str, Any]:
    current: Any = root
    if fragment and not fragment.startswith("/"):
        raise ValueError("schema reference fragment is malformed")
    for raw_part in fragment.lstrip("/").split("/") if fragment else []:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise ValueError("schema reference does not resolve")
        current = current[part]
    if not isinstance(current, dict):
        raise ValueError("schema reference target is not an object")
    return current


def _resolve_schema_reference(
    reference: str,
    root_schema: dict[str, Any],
    cache: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    filename, marker, fragment = reference.partition("#")
    if not filename:
        return _schema_pointer(root_schema, fragment if marker else ""), root_schema
    relative = Path(filename)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("external schema reference is unsafe")
    target = _SCHEMA_DIR / relative
    if target.is_symlink() or not target.is_file():
        raise ValueError("external schema reference is missing or unsafe")
    resolved = target.resolve()
    try:
        resolved.relative_to(_SCHEMA_DIR.resolve())
    except ValueError as exc:
        raise ValueError("external schema reference escapes the schema directory") from exc
    key = resolved.as_posix()
    external = cache.get(key)
    if external is None:
        loaded = read_json(resolved)
        if not isinstance(loaded, dict):
            raise ValueError("external schema is malformed")
        external = loaded
        cache[key] = external
    return _schema_pointer(external, fragment if marker else ""), external


def _valid_date_time(value: str) -> bool:
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _schema_errors(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    path: str,
    cache: dict[str, dict[str, Any]],
) -> list[str]:
    unsupported = set(schema).difference(_SUPPORTED_SCHEMA_KEYS)
    if unsupported:
        return [f"{path} uses unsupported schema constraints"]
    reference = schema.get("$ref")
    if isinstance(reference, str):
        try:
            resolved, resolved_root = _resolve_schema_reference(reference, root_schema, cache)
        except (OSError, ValueError):
            return [f"{path} references an unavailable schema definition"]
        return _schema_errors(value, resolved, resolved_root, path, cache)
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matching = [
            branch
            for branch in one_of
            if isinstance(branch, dict)
            and not _schema_errors(value, branch, root_schema, path, cache)
        ]
        if len(matching) != 1:
            return [f"{path} does not match exactly one allowed schema shape"]
    expected_type = schema.get("type")
    if isinstance(expected_type, str):
        allowed_types = [expected_type]
    elif isinstance(expected_type, list) and all(isinstance(item, str) for item in expected_type):
        allowed_types = expected_type
    else:
        allowed_types = []
    if allowed_types and not any(_matches_schema_type(value, item) for item in allowed_types):
        return [f"{path} has the wrong schema type"]
    errors: list[str] = []
    if "const" in schema and not _json_equal(value, schema["const"]):
        errors.append(f"{path} does not match the required schema constant")
    allowed_values = schema.get("enum")
    if isinstance(allowed_values, list) and not any(
        _json_equal(value, item) for item in allowed_values
    ):
        errors.append(f"{path} is not an allowed schema value")
    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        if type(minimum_length) is int and len(value) < minimum_length:
            errors.append(f"{path} is shorter than the schema minimum")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            errors.append(f"{path} does not match the schema pattern")
        value_format = schema.get("format")
        if value_format == "date-time" and not _valid_date_time(value):
            errors.append(f"{path} is not a valid schema date-time")
        if value_format == "uri":
            parsed = urlsplit(value)
            if not parsed.scheme or any(character.isspace() for character in value):
                errors.append(f"{path} is not a valid schema URI")
    if type(value) is int and type(schema.get("minimum")) is int and value < schema["minimum"]:
        errors.append(f"{path} is below the schema minimum")
    if isinstance(value, dict):
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []
        for name in required:
            if isinstance(name, str) and name not in value:
                errors.append(f"{path} omits required field {name}")
        if schema.get("additionalProperties") is False:
            for name in sorted(set(value).difference(properties)):
                errors.append(f"{path} contains unknown field {name}")
        for name, child in value.items():
            child_schema = properties.get(name)
            if isinstance(child_schema, dict):
                errors.extend(
                    _schema_errors(child, child_schema, root_schema, f"{path}.{name}", cache)
                )
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if type(minimum_items) is int and len(value) < minimum_items:
            errors.append(f"{path} has fewer items than the schema minimum")
        if type(maximum_items) is int and len(value) > maximum_items:
            errors.append(f"{path} has more items than the schema maximum")
        if schema.get("uniqueItems") is True:
            serialized = [
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(serialized) != len(set(serialized)):
                errors.append(f"{path} contains duplicate schema items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(
                    _schema_errors(item, item_schema, root_schema, f"{path}[{index}]", cache)
                )
    return errors
