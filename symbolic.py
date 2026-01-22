"""
Symbolic execution tests using CrossHair.
These tests use symbolic values to explore execution paths and verify contracts.
"""

from parser import decode_module, validate_module, DecodeError, Limits


def test_decode_never_crashes_on_small_inputs(data: bytes) -> None:
    """
    post: True
    """
    # Limit to very small inputs for symbolic execution
    if len(data) > 32:
        return

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=64))
    except DecodeError:
        # DecodeError is expected for malformed input
        pass
    except Exception as e:
        # Any other exception is a bug
        raise AssertionError(f"Unexpected exception: {e}")


def test_validate_never_crashes_on_minimal_valid_module() -> None:
    """
    post: True
    """
    # Minimal valid WASM module
    data = b"\x00asm\x01\x00\x00\x00"

    try:
        module = decode_module(data)
        errors = validate_module(module)
        assert isinstance(errors, list)
    except Exception as e:
        raise AssertionError(f"Minimal valid module should not raise: {e}")


def test_decode_rejects_invalid_magic() -> None:
    """
    post: True
    """
    # Any non-matching magic should raise DecodeError
    invalid_magic = b"\x00bad\x01\x00\x00\x00"

    try:
        decode_module(invalid_magic)
        raise AssertionError("Should have raised DecodeError for invalid magic")
    except DecodeError:
        # Expected
        pass


def test_decode_rejects_invalid_version() -> None:
    """
    post: True
    """
    # Any non-matching version should raise DecodeError
    invalid_version = b"\x00asm\x02\x00\x00\x00"

    try:
        decode_module(invalid_version)
        raise AssertionError("Should have raised DecodeError for invalid version")
    except DecodeError:
        # Expected
        pass


def test_decode_respects_module_size_limit() -> None:
    """
    post: True
    """
    # Create a module that's larger than the limit
    data = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 100

    try:
        decode_module(data, limits=Limits(max_module_bytes=10))
        raise AssertionError("Should have raised DecodeError for exceeding size limit")
    except DecodeError:
        # Expected
        pass


def test_validation_returns_list() -> None:
    """
    post: True
    """
    # For any successfully decoded module, validation must return a list
    data = b"\x00asm\x01\x00\x00\x00"

    module = decode_module(data)
    errors = validate_module(module)

    assert isinstance(errors, list), f"validate_module must return a list, got {type(errors)}"


def test_decode_handles_truncated_input(data: bytes) -> None:
    """
    post: True
    """
    # Any truncated input should either decode successfully or raise DecodeError
    if len(data) > 16:
        return

    try:
        decode_module(data, limits=Limits(max_module_bytes=32))
    except DecodeError:
        # Expected for malformed input
        pass
    except Exception as e:
        raise AssertionError(f"Unexpected exception on truncated input: {e}")


def test_empty_input_raises_decode_error() -> None:
    """
    post: True
    """
    try:
        decode_module(b"")
        raise AssertionError("Empty input should raise DecodeError")
    except DecodeError:
        # Expected
        pass


def test_minimal_valid_module_has_no_validation_errors() -> None:
    """
    post: True
    """
    data = b"\x00asm\x01\x00\x00\x00"

    module = decode_module(data)
    errors = validate_module(module)

    assert len(errors) == 0, f"Minimal valid module should have no validation errors, got {errors}"


def test_decoder_position_never_exceeds_input_length(data: bytes) -> None:
    """
    post: True
    """
    # Ensure decoder doesn't read past input bounds
    if len(data) > 24:
        return

    try:
        decode_module(data, limits=Limits(max_module_bytes=32))
    except DecodeError:
        # Expected for malformed input
        pass
    except IndexError:
        raise AssertionError("Decoder read past input bounds")
    except Exception:
        # Other exceptions might occur, but not IndexError
        pass
