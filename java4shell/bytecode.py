"""Derive distinct scripts and marker classes for retained-JVM ES7 comparisons."""
from __future__ import annotations

import hashlib
import re
import struct


MARKER_INTERNAL_NAME = b"org/elasticsearch/painless/OwnedBase64Marker"
MARKER_RETURN_LITERAL = b"owned-bytecode-executed"
_CONSTANT_SIZES = {
    3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
    12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2,
}


def fresh_script_source(base_source: str, ordinal: int) -> str:
    """Keep the audited program intact while selecting a fresh script cache key."""
    if not isinstance(base_source, str) or not base_source:
        raise ValueError("The audited Painless source must be nonempty text")
    if type(ordinal) is not int or not 1 <= ordinal <= 99999:
        raise ValueError("Script ordinal must be an integer from 1 to 99999")
    return f"// original-decoder retained request {ordinal:05d}\n" + base_source


def _u2(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("Truncated class-file value")
    return struct.unpack_from(">H", data, offset)[0]


def _class_info(data: bytes):
    """Read the pool and this_class; the pinned hash supplies full validity."""
    if not isinstance(data, bytes) or len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("Invalid class-file header")
    if _u2(data, 4) != 0 or _u2(data, 6) not in (61, 65):
        raise ValueError("Expected a non-preview Java 17 or Java 21 marker class")
    count = _u2(data, 8)
    if count < 2:
        raise ValueError("Invalid constant-pool count")
    entries = {}
    index, offset = 1, 10
    while index < count:
        if offset >= len(data):
            raise ValueError("Truncated constant pool")
        tag = data[offset]
        offset += 1
        if tag == 1:
            size = _u2(data, offset)
            offset += 2
        else:
            try:
                size = _CONSTANT_SIZES[tag]
            except KeyError as error:
                raise ValueError("Unsupported constant-pool tag") from error
        end = offset + size
        if end > len(data):
            raise ValueError("Truncated constant-pool entry")
        entries[index] = (tag, offset, end)
        offset = end
        if tag in (5, 6):
            if index + 1 >= count:
                raise ValueError("Invalid two-slot constant-pool entry")
            index += 1
        index += 1
    if offset + 6 > len(data):
        raise ValueError("Truncated class identity")
    this_class = _u2(data, offset + 2)
    entry = entries.get(this_class)
    if entry is None or entry[0] != 7:
        raise ValueError("this_class does not reference CONSTANT_Class")
    name = entries.get(_u2(data, entry[1]))
    if name is None or name[0] != 1:
        raise ValueError("Class name does not reference CONSTANT_Utf8")
    return entries, data[name[1]:name[2]]


def class_internal_name(class_bytes: bytes) -> str:
    """Return the ASCII internal name of a supported marker class."""
    _, name = _class_info(class_bytes)
    try:
        return name.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("Marker class name is not ASCII") from error


def _unique_utf8_span(data: bytes, entries, expected: bytes, label: str):
    matches = [(start, end) for tag, start, end in entries.values()
               if tag == 1 and data[start:end] == expected]
    if len(matches) != 1:
        raise ValueError("Expected exactly one " + label + " CONSTANT_Utf8 entry")
    return matches[0]


def derive_marker_class(base_class: bytes, expected_sha256: str,
                        ordinal: int) -> dict[str, str | bytes]:
    """Derive a unique class and return token, preserving method-code bytes."""
    # Equal-length constant-pool replacements keep every bytecode offset and
    # instruction intact. A distinct token exposes stale cached method targets
    # even when a later request manages to create its own marker file.
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("A canonical SHA-256 pin is required")
    if not isinstance(base_class, bytes) or hashlib.sha256(base_class).hexdigest() != expected_sha256:
        raise ValueError("Base marker class differs from its SHA-256 pin")
    if type(ordinal) is not int or not 1 <= ordinal <= 99999:
        raise ValueError("Marker ordinal must be an integer from 1 to 99999")

    entries, original = _class_info(base_class)
    if original != MARKER_INTERNAL_NAME:
        raise ValueError("Unexpected base marker class name")
    name_span = _unique_utf8_span(base_class, entries, MARKER_INTERNAL_NAME,
                                 "marker-name")
    return_span = _unique_utf8_span(base_class, entries, MARKER_RETURN_LITERAL,
                                   "marker-return")

    simple_name = f"OwnedBase64M{ordinal:05d}"
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", simple_name) is None:
        raise ValueError("Derived class name is not a Java identifier")
    internal_name = "org/elasticsearch/painless/" + simple_name
    replacement = internal_name.encode("ascii")
    if len(replacement) != len(MARKER_INTERNAL_NAME):
        raise ValueError("Derived class name changes the constant length")
    marker_return = f"owned-bytecode-{ordinal:08d}"
    return_bytes = marker_return.encode("ascii")
    if len(return_bytes) != len(MARKER_RETURN_LITERAL):
        raise ValueError("Derived return token changes the constant length")
    derived = bytearray(base_class)
    for (start, end), value in ((name_span, replacement),
                               (return_span, return_bytes)):
        derived[start:end] = value
    derived = bytes(derived)
    if class_internal_name(derived) != internal_name:
        raise ValueError("Derived class identity did not match its name")
    return {"binary_name": internal_name.replace("/", "."),
            "internal_name": internal_name,
            "marker_return": marker_return,
            "sha256": hashlib.sha256(derived).hexdigest(),
            "bytes": derived}
