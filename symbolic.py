"""
Symbolic execution tests using CrossHair.

These tests verify properties using symbolic reasoning.
"""

from parser import decode_module, validate_module, DecodeError, Limits


def decode_never_crashes_except_decodeerror(data: bytes) -> None:
    """
    Verify that decode_module either succeeds or raises DecodeError, never crashes.

    pre: len(data) <= 256
    post: True
    """
    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
        # If decoding succeeds, module should have valid structure
        assert module.raw_size == len(data)
    except DecodeError:
        # Expected for malformed input
        pass
    # Any other exception would violate the contract


def validate_is_total(data: bytes) -> None:
    """
    Verify that if decode succeeds, validate always returns a list (never crashes).

    pre: len(data) <= 256
    post: True
    """
    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
    except DecodeError:
        # Can't validate if decode fails
        return

    # If we got here, decode succeeded, so validate must work
    errors = validate_module(module)
    assert isinstance(errors, list)
    assert all(hasattr(e, 'code') and hasattr(e, 'message') for e in errors)


def minimal_module_decodes() -> None:
    """
    Verify that the minimal valid WASM module (magic + version) always decodes successfully.

    post: True
    """
    minimal = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(minimal)
    assert module.raw_size == 8
    assert len(module.types) == 0
    assert len(module.functions) == 0
    errors = validate_module(module)
    assert len(errors) == 0


def bad_magic_always_fails() -> None:
    """
    Verify that invalid magic always raises DecodeError.

    post: True
    """
    bad_magic = b"\x00bad\x01\x00\x00\x00"
    try:
        decode_module(bad_magic)
        # Should not get here
        assert False, "Expected DecodeError"
    except DecodeError as e:
        assert "magic" in e.message.lower()


def bad_version_always_fails() -> None:
    """
    Verify that invalid version always raises DecodeError.

    post: True
    """
    bad_version = b"\x00asm\x02\x00\x00\x00"
    try:
        decode_module(bad_version)
        # Should not get here
        assert False, "Expected DecodeError"
    except DecodeError as e:
        assert "version" in e.message.lower()


def decode_result_size_matches_input(data: bytes) -> None:
    """
    Verify that if decode succeeds, module.raw_size == len(data).

    pre: len(data) <= 256
    post: True
    """
    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
        assert module.raw_size == len(data)
    except DecodeError:
        pass


def validate_returns_list(data: bytes) -> None:
    """
    Verify that validate_module always returns a list.

    pre: len(data) <= 256
    post: True
    """
    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
        errors = validate_module(module)
        assert isinstance(errors, list)
    except DecodeError:
        pass
