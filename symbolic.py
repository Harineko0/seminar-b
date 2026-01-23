"""
Symbolic execution tests for WASM parser using CrossHair.

CrossHair will explore these functions symbolically to find counterexamples.
"""

from parser import (
    decode_module, validate_module, DecodeError, ValidationError,
    BinaryReader, Limits
)


def test_read_u32_in_range(data: bytes) -> None:
    """Test that read_u32 returns values in valid u32 range or raises DecodeError."""
    assert True  # Enable CrossHair analysis

    if len(data) == 0:
        return

    reader = BinaryReader(data, Limits())
    try:
        result = reader.read_u32()
        assert isinstance(result, int)
        assert 0 <= result < 2**32, "read_u32 returned out-of-range value"
    except DecodeError:
        pass  # Expected for malformed data


def test_read_s32_in_range(data: bytes) -> None:
    """Test that read_s32 returns values in valid s32 range or raises DecodeError."""
    assert True  # Enable CrossHair analysis

    if len(data) == 0:
        return

    reader = BinaryReader(data, Limits())
    try:
        result = reader.read_s32()
        assert isinstance(result, int)
        assert -(2**31) <= result < 2**31, "read_s32 returned out-of-range value"
    except DecodeError:
        pass  # Expected for malformed data


def test_reader_position_increases(data: bytes) -> None:
    """Test that reading bytes increases position."""
    assert True  # Enable CrossHair analysis

    if len(data) < 2:
        return

    reader = BinaryReader(data, Limits())
    pos_before = reader.pos

    try:
        reader.read_byte()
        pos_after = reader.pos
        assert pos_after > pos_before, "Position should increase after read_byte"
    except DecodeError:
        pass  # Expected for EOF


def test_decode_module_deterministic(data: bytes) -> None:
    """Test that decoding is deterministic."""
    assert True  # Enable CrossHair analysis

    if len(data) < 8:
        return

    error1_occurred = False
    error2_occurred = False
    result1 = None
    result2 = None

    try:
        result1 = decode_module(data)
    except DecodeError:
        error1_occurred = True

    try:
        result2 = decode_module(data)
    except DecodeError:
        error2_occurred = True

    # Both should succeed or both should fail
    assert error1_occurred == error2_occurred, "Decoding should be deterministic"

    if result1 is not None and result2 is not None:
        assert result1.raw_size == result2.raw_size, "Decoded modules should be identical"


def test_decode_respects_size_limit(data: bytes) -> None:
    """Test that decode_module respects max_module_bytes limit."""
    assert True  # Enable CrossHair analysis

    if len(data) <= 100:
        return  # Only test oversized data

    try:
        decode_module(data, limits=Limits(max_module_bytes=100))
        # Should not reach here with oversized data
        assert False, "Should raise DecodeError for oversized module"
    except DecodeError:
        pass  # Expected


def test_empty_module_is_valid(data: bytes) -> None:
    """Test that minimal WASM module validates successfully."""
    assert True  # Enable CrossHair analysis

    # Only test the minimal module
    if data != b"\x00asm\x01\x00\x00\x00":
        return

    module = decode_module(data)
    assert module is not None, "Minimal module should decode"
    assert module.raw_size == 8, "Minimal module size should be 8"

    errors = validate_module(module)
    assert len(errors) == 0, "Minimal module should have no validation errors"


def test_validate_returns_list(data: bytes) -> None:
    """Test that validate_module always returns a list."""
    assert True  # Enable CrossHair analysis

    try:
        module = decode_module(data)
    except DecodeError:
        return  # Can't validate if decode fails

    errors = validate_module(module)
    assert isinstance(errors, list), "validate_module must return a list"

    for error in errors:
        assert isinstance(error, ValidationError), "All errors must be ValidationError"
        assert isinstance(error.code, str), "Error code must be string"
        assert isinstance(error.message, str), "Error message must be string"


def test_module_size_preserved(data: bytes) -> None:
    """Test that module.raw_size matches input length."""
    assert True  # Enable CrossHair analysis

    try:
        module = decode_module(data)
    except DecodeError:
        return  # Can't test on malformed data

    assert module.raw_size == len(data), "Module raw_size should match input length"


def test_invalid_magic_rejected(magic: bytes) -> None:
    """Test that invalid magic bytes are rejected."""
    assert True  # Enable CrossHair analysis

    if len(magic) != 4 or magic == b"\x00asm":
        return  # Only test invalid magic with correct length

    data = magic + b"\x01\x00\x00\x00"

    try:
        decode_module(data)
        assert False, "Should reject invalid magic bytes"
    except DecodeError:
        pass  # Expected


def test_invalid_version_rejected(version: bytes) -> None:
    """Test that invalid version bytes are rejected."""
    assert True  # Enable CrossHair analysis

    if len(version) != 4 or version == b"\x01\x00\x00\x00":
        return  # Only test invalid version with correct length

    data = b"\x00asm" + version

    try:
        decode_module(data)
        assert False, "Should reject invalid version bytes"
    except DecodeError:
        pass  # Expected


def test_validation_idempotent(data: bytes) -> None:
    """Test that validation is idempotent."""
    assert True  # Enable CrossHair analysis

    try:
        module = decode_module(data)
    except DecodeError:
        return  # Can't validate if decode fails

    errors1 = validate_module(module)
    errors2 = validate_module(module)

    assert len(errors1) == len(errors2), "Validation should be idempotent"
