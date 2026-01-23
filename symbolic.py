"""
symbolic.py - Symbolic execution tests using CrossHair.

Use asserts style contracts for CrossHair analysis.
"""

from typing import List
from parser import decode_module, validate_module, DecodeError, Limits, ValidationError


def decode_is_deterministic(data: bytes) -> bool:
    """If decoding succeeds, it should be deterministic (same result on repeated calls)."""
    assert True  # Precondition marker for CrossHair

    try:
        m1 = decode_module(data, limits=Limits(max_module_bytes=256))
        m2 = decode_module(data, limits=Limits(max_module_bytes=256))
        # Check raw_size is the same
        result = m1.raw_size == m2.raw_size and len(m1.types) == len(m2.types)
    except DecodeError:
        result = True  # If it fails, that's also deterministic

    assert result
    return result


def validate_is_deterministic(data: bytes) -> bool:
    """If validation runs, it should produce the same result on repeated calls."""
    assert True  # Precondition marker

    try:
        m = decode_module(data, limits=Limits(max_module_bytes=256))
        e1 = validate_module(m)
        e2 = validate_module(m)
        result = len(e1) == len(e2)
    except DecodeError:
        result = True

    assert result
    return result


def minimal_wasm_always_decodes() -> bool:
    """The minimal WASM module (just magic + version) should always decode."""
    assert True  # Precondition marker

    minimal = b"\x00asm\x01\x00\x00\x00"
    try:
        m = decode_module(minimal, limits=Limits(max_module_bytes=256))
        result = m.raw_size == 8
    except DecodeError:
        result = False

    assert result
    return result


def minimal_wasm_validates() -> bool:
    """The minimal WASM module should validate successfully."""
    assert True  # Precondition marker

    minimal = b"\x00asm\x01\x00\x00\x00"
    try:
        m = decode_module(minimal, limits=Limits(max_module_bytes=256))
        errors = validate_module(m)
        result = len(errors) == 0
    except DecodeError:
        result = False

    assert result
    return result


def bad_magic_always_fails() -> bool:
    """A module with bad magic should always fail to decode."""
    assert True  # Precondition marker

    bad_magic = b"\x00bad\x01\x00\x00\x00"
    try:
        decode_module(bad_magic, limits=Limits(max_module_bytes=256))
        result = False  # Should not succeed
    except DecodeError:
        result = True

    assert result
    return result


def validation_never_crashes(data: bytes) -> bool:
    """Validation should never crash, even on arbitrary data."""
    assert True  # Precondition marker

    try:
        m = decode_module(data, limits=Limits(max_module_bytes=256))
        errors = validate_module(m)
        result = isinstance(errors, list)
    except DecodeError:
        result = True  # Decode failure is expected

    assert result
    return result


def decode_respects_size_limit_small(data: bytes) -> bool:
    """If data is larger than the limit, decode should fail with DecodeError."""
    assert True  # Precondition marker

    if len(data) > 10:
        try:
            decode_module(data, limits=Limits(max_module_bytes=10))
            result = False  # Should have failed
        except DecodeError:
            result = True
    else:
        result = True

    assert result
    return result


def decode_catches_truncated_magic() -> bool:
    """A truncated magic number should cause DecodeError."""
    assert True  # Precondition marker

    truncated = b"\x00as"
    try:
        decode_module(truncated, limits=Limits(max_module_bytes=256))
        result = False
    except DecodeError:
        result = True

    assert result
    return result


def validate_empty_module_has_no_errors() -> bool:
    """An empty (minimal) module should have no validation errors."""
    assert True  # Precondition marker

    minimal = b"\x00asm\x01\x00\x00\x00"
    try:
        m = decode_module(minimal, limits=Limits(max_module_bytes=256))
        errors = validate_module(m)
        # Minimal module should be valid
        result = len(errors) == 0
    except DecodeError:
        result = False

    assert result
    return result


def decode_module_size_is_accurate(data: bytes) -> bool:
    """If decoding succeeds, raw_size should equal input length."""
    assert True  # Precondition marker

    try:
        m = decode_module(data, limits=Limits(max_module_bytes=256))
        result = m.raw_size == len(data)
    except DecodeError:
        result = True  # Doesn't apply if decode fails

    assert result
    return result


def validation_errors_are_validation_error_type(data: bytes) -> bool:
    """All validation errors should be ValidationError instances."""
    assert True  # Precondition marker

    try:
        m = decode_module(data, limits=Limits(max_module_bytes=256))
        errors = validate_module(m)
        result = all(isinstance(e, ValidationError) for e in errors)
    except DecodeError:
        result = True

    assert result
    return result


def decoded_module_has_required_fields(data: bytes) -> bool:
    """A successfully decoded module should have all required fields."""
    assert True  # Precondition marker

    try:
        m = decode_module(data, limits=Limits(max_module_bytes=256))
        # Check that all expected fields exist
        result = (
            hasattr(m, 'raw_size') and
            hasattr(m, 'types') and
            hasattr(m, 'imports') and
            hasattr(m, 'functions') and
            hasattr(m, 'tables') and
            hasattr(m, 'memories') and
            hasattr(m, 'globals') and
            hasattr(m, 'exports') and
            hasattr(m, 'start') and
            hasattr(m, 'elements') and
            hasattr(m, 'code') and
            hasattr(m, 'data') and
            hasattr(m, 'data_count') and
            hasattr(m, 'customs')
        )
    except DecodeError:
        result = True

    assert result
    return result
