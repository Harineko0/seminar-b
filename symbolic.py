"""
symbolic.py - CrossHair symbolic execution tests for wasm_sv parser.

This file contains contracts (preconditions/postconditions via asserts) that
CrossHair will verify symbolically. The goal is to ensure the parser handles
all edge cases correctly before we run it on concrete inputs.
"""

from typing import Any
from parser import (
    decode_module,
    validate_module,
    decode_and_validate,
    DecodeError,
    ValidationError,
    Limits,
    Module,
)


# CrossHair directive to enable assertion checking
# crosshair: analysis_kind=asserts


def test_decode_minimal_valid_module() -> None:
    """
    A minimal valid WASM module is just magic + version (8 bytes).
    This should always decode successfully.
    """
    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)
    assert module.raw_size == 8
    errors = validate_module(module)
    assert len(errors) == 0


def test_decode_rejects_bad_magic(data: bytes) -> None:
    """
    Any bytes that don't start with the magic should raise DecodeError.
    Precondition: data length >= 4 and first 4 bytes != magic.
    """
    assert len(data) >= 4
    assert data[:4] != b"\x00asm"

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError:
        pass  # Expected


def test_decode_rejects_bad_version(data: bytes) -> None:
    """
    Data with correct magic but wrong version should raise DecodeError.
    Precondition: starts with magic, length >= 8, version bytes != 01 00 00 00.
    """
    assert len(data) >= 8
    assert data[:4] == b"\x00asm"
    assert data[4:8] != b"\x01\x00\x00\x00"

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError:
        pass  # Expected


def test_decode_respects_module_size_limit(data: bytes) -> None:
    """
    If data exceeds max_module_bytes limit, decode should raise DecodeError.
    """
    assert len(data) > 100  # Assume limit is 100
    limits = Limits(max_module_bytes=100)

    try:
        decode_module(data, limits=limits)
        assert False, "Should have raised DecodeError for size limit"
    except DecodeError:
        pass  # Expected


def test_decode_empty_input() -> None:
    """Empty input should raise DecodeError."""
    data = b""
    try:
        decode_module(data)
        assert False, "Empty input should raise DecodeError"
    except DecodeError:
        pass


def test_decode_truncated_magic() -> None:
    """Input shorter than 8 bytes should raise DecodeError."""
    for length in range(1, 8):
        data = b"\x00asm\x01\x00\x00\x00"[:length]
        try:
            decode_module(data)
            assert False, f"Truncated input (len={length}) should raise DecodeError"
        except DecodeError:
            pass


def test_validate_detects_no_errors_on_minimal() -> None:
    """Minimal valid module should have no validation errors."""
    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)
    errors = validate_module(module)
    assert len(errors) == 0


def test_decode_and_validate_minimal() -> None:
    """decode_and_validate should work on minimal valid module."""
    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_and_validate(data)
    assert module.raw_size == 8


def check_decode_module_always_returns_or_raises(data: bytes) -> None:
    """
    For any input, decode_module must either return a Module or raise DecodeError.
    It must never hang, crash, or return None.
    Precondition: reasonable size limit to prevent timeouts.
    """
    assert True  # Enable CrossHair checking
    assert len(data) <= 100  # Limit for symbolic execution

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=1000))
        assert isinstance(module, Module)
        assert module.raw_size > 0
    except DecodeError as e:
        # Expected for invalid input
        assert isinstance(e.message, str)
        assert len(e.message) > 0


def check_validate_always_returns_list(data: bytes) -> None:
    """
    If decode succeeds, validate must return a list (possibly empty).
    It must never raise, hang, or crash.
    Precondition: decode succeeds.
    """
    assert True  # Enable CrossHair checking
    assert len(data) <= 100

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=1000))
        errors = validate_module(module)
        assert isinstance(errors, list)
        for error in errors:
            assert isinstance(error, ValidationError)
            assert isinstance(error.code, str)
            assert isinstance(error.message, str)
    except DecodeError:
        # If decode fails, we can't validate
        pass


def test_limits_are_respected() -> None:
    """Test that Limits dataclass works correctly."""
    limits = Limits(
        max_module_bytes=100,
        max_section_bytes=50,
        max_vector_length=10,
        max_function_body_bytes=20,
        max_locals_per_function=5,
        max_custom_section_bytes=30,
    )
    assert limits.max_module_bytes == 100
    assert limits.max_section_bytes == 50
    assert limits.max_vector_length == 10
    assert limits.max_function_body_bytes == 20
    assert limits.max_locals_per_function == 5
    assert limits.max_custom_section_bytes == 30


def test_decode_error_properties() -> None:
    """Test DecodeError exception properties."""
    error = DecodeError("test message", offset=42, code="test_code")
    assert error.message == "test message"
    assert error.offset == 42
    assert error.code == "test_code"
    assert str(error) == "test message"


def test_validation_error_properties() -> None:
    """Test ValidationError dataclass properties."""
    error = ValidationError(code="test_code", message="test message", context="test context")
    assert error.code == "test_code"
    assert error.message == "test message"
    assert error.context == "test context"


# Additional property-based tests for CrossHair

def test_decode_idempotent_on_valid_minimal() -> None:
    """Decoding the same valid data multiple times gives consistent results."""
    data = b"\x00asm\x01\x00\x00\x00"
    m1 = decode_module(data)
    m2 = decode_module(data)
    assert m1.raw_size == m2.raw_size


def test_validation_deterministic() -> None:
    """Validating the same module multiple times gives same results."""
    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)
    e1 = validate_module(module)
    e2 = validate_module(module)
    assert len(e1) == len(e2)


def check_minimal_module_is_valid() -> None:
    """
    A minimal WASM module (magic + version) should always decode successfully
    and have no validation errors.
    """
    assert True  # Enable CrossHair checking

    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)

    # Postconditions
    assert isinstance(module, Module)
    assert module.raw_size == 8

    errors = validate_module(module)
    assert len(errors) == 0
