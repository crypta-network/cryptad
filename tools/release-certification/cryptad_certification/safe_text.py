"""Language-neutral safe-text rules for public lifecycle recovery guidance."""

from __future__ import annotations

import unicodedata


MAX_RECOVERY_GUIDANCE_UTF16_UNITS = 256


def java_utf16_units(value: str) -> int:
    """Return the number of UTF-16 code units used by a Java ``String``."""

    return sum(2 if ord(character) > 0xFFFF else 1 for character in value)


def recovery_guidance_error(value: object) -> str | None:
    """Return a bounded failure code when guidance cannot be consumed by the runtime.

    Stable lifecycle recovery guidance uses the runtime's deliberately strict public-text
    contract: a nonblank Java string of at most 256 UTF-16 code units, containing no ISO control,
    Unicode FORMAT, surrogate, or supplementary code point. Rejecting supplementary code points
    is intentional because every such Java string contains surrogate code units and the runtime
    rejects them fail closed.
    """

    if not isinstance(value, str) or not value:
        return "not-nonempty-text"
    if java_utf16_units(value) > MAX_RECOVERY_GUIDANCE_UTF16_UNITS:
        return "utf16-length-exceeded"
    if all(_java_is_whitespace(ord(character)) for character in value):
        return "blank-text"
    for character in value:
        code_point = ord(character)
        if code_point > 0xFFFF or 0xD800 <= code_point <= 0xDFFF:
            return "surrogate-or-supplementary"
        if code_point <= 0x1F or 0x7F <= code_point <= 0x9F:
            return "iso-control"
        if unicodedata.category(character) == "Cf":
            return "unicode-format"
    return None


def _java_is_whitespace(code_point: int) -> bool:
    """Mirror ``Character.isWhitespace`` for code points that survive the safety checks."""

    if 0x09 <= code_point <= 0x0D or 0x1C <= code_point <= 0x1F:
        return True
    if code_point in {0x00A0, 0x2007, 0x202F}:
        return False
    return unicodedata.category(chr(code_point)) in {"Zs", "Zl", "Zp"}
