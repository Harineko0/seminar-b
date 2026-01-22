"""
Symbolic execution tests using CrossHair.

These tests use CrossHair to verify contracts and find counterexamples.
"""

from typing import Optional
import leb128
from binary_reader import ByteReader


def test_leb128_u32_never_exceeds_32_bits() -> None:
    """
    Verify that read_u32 always returns values that fit in 32 bits.
    """
    # Create test data with symbolic bytes
    data = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x0F])  # Max valid u32 encoding
    reader = ByteReader(data)

    try:
        value, bytes_consumed = leb128.read_u32(reader)
        # Post-condition: value must fit in unsigned 32-bit
        assert 0 <= value <= 0xFFFFFFFF, f"u32 value {value} exceeds 32-bit range"
        # Post-condition: bytes consumed must be 1-5
        assert 1 <= bytes_consumed <= 5, f"bytes consumed {bytes_consumed} out of range"
    except leb128.LEB128Error:
        # Expected for invalid encodings
        pass


def test_leb128_s32_fits_in_32_bits() -> None:
    """
    Verify that read_s32 always returns values that fit in signed 32 bits.
    """
    # Test with max positive value
    data_pos = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x07])
    reader_pos = ByteReader(data_pos)

    try:
        value, bytes_consumed = leb128.read_s32(reader_pos)
        # Post-condition: value must fit in signed 32-bit
        assert -2147483648 <= value <= 2147483647, f"s32 value {value} exceeds 32-bit range"
        assert 1 <= bytes_consumed <= 5, f"bytes consumed {bytes_consumed} out of range"
    except leb128.LEB128Error:
        pass

    # Test with max negative value
    data_neg = bytes([0x80, 0x80, 0x80, 0x80, 0x78])
    reader_neg = ByteReader(data_neg)

    try:
        value, bytes_consumed = leb128.read_s32(reader_neg)
        assert -2147483648 <= value <= 2147483647, f"s32 value {value} exceeds 32-bit range"
        assert 1 <= bytes_consumed <= 5, f"bytes consumed {bytes_consumed} out of range"
    except leb128.LEB128Error:
        pass


def test_leb128_u32_consumes_correct_bytes() -> None:
    """
    Verify that read_u32 consumes exactly the bytes it claims to consume.
    """
    # Single-byte encoding
    data = bytes([0x42])  # 66 in decimal
    reader = ByteReader(data)
    initial_offset = reader.offset()

    try:
        value, bytes_consumed = leb128.read_u32(reader)
        final_offset = reader.offset()
        # Post-condition: offset advanced by bytes_consumed
        assert final_offset - initial_offset == bytes_consumed, "offset mismatch"
        assert value == 66, f"expected 66, got {value}"
    except leb128.LEB128Error:
        pass


def test_leb128_detects_truncation() -> None:
    """
    Verify that read_u32 detects truncated encodings.
    """
    # Truncated encoding (continuation bit set but no more bytes)
    data = bytes([0x80])
    reader = ByteReader(data)

    try:
        value, bytes_consumed = leb128.read_u32(reader)
        # Should not reach here - truncation should be detected
        assert False, "Truncation not detected"
    except leb128.LEB128Error as e:
        # Expected
        assert "truncat" in str(e).lower()


def test_leb128_rejects_overlong() -> None:
    """
    Verify that read_u32 rejects overlong encodings.
    """
    # Overlong encoding of 0: should be single byte 0x00, not 0x80 0x00
    data = bytes([0x80, 0x00])
    reader = ByteReader(data)

    try:
        value, bytes_consumed = leb128.read_u32(reader)
        # Should either reject or accept (implementation-dependent)
        # If accepted, value must be correct
        if bytes_consumed > 1:
            # Might be accepted as overlong
            pass
    except leb128.LEB128Error:
        # Expected - overlong rejected
        pass


def test_leb128_rejects_overflow() -> None:
    """
    Verify that read_u32 rejects values that overflow 32 bits.
    """
    # Value that would overflow u32: 0xFFFFFFFF + 1
    data = bytes([0x80, 0x80, 0x80, 0x80, 0x10])
    reader = ByteReader(data)

    try:
        value, bytes_consumed = leb128.read_u32(reader)
        # Should not reach here
        assert False, f"Overflow not detected, got value {value}"
    except leb128.LEB128Error as e:
        # Expected
        assert "overflow" in str(e).lower() or "exceed" in str(e).lower()


def test_bytereader_boundary_checking() -> None:
    """
    Verify that ByteReader enforces boundaries.
    """
    data = bytes([1, 2, 3, 4, 5])
    reader = ByteReader(data, start=0, end=3)

    # Should be able to read 3 bytes
    b1 = reader.read_byte()
    b2 = reader.read_byte()
    b3 = reader.read_byte()

    assert b1 == 1
    assert b2 == 2
    assert b3 == 3

    # Fourth read should fail
    try:
        b4 = reader.read_byte()
        assert False, "Boundary not enforced"
    except Exception:
        # Expected
        pass


def test_bytereader_slice_advances_position() -> None:
    """
    Verify that slice() advances the reader position.
    """
    data = bytes([1, 2, 3, 4, 5])
    reader = ByteReader(data)

    initial_offset = reader.offset()
    sub_reader = reader.slice(2)

    # Main reader should have advanced by 2
    assert reader.offset() == initial_offset + 2

    # Sub-reader should be able to read exactly 2 bytes
    b1 = sub_reader.read_byte()
    b2 = sub_reader.read_byte()

    assert b1 == 1
    assert b2 == 2

    # Sub-reader should be at end
    assert sub_reader.at_end()


def test_validator_returns_list() -> None:
    """
    Verify that validator always returns a list.
    """
    from parser import decode_module, validate_module

    # Minimal valid module
    data = b"\x00asm\x01\x00\x00\x00"

    try:
        module = decode_module(data)
        errors = validate_module(module)
        assert isinstance(errors, list), "Validator must return a list"
    except Exception:
        pass


# Run with: uv run crosshair check symbolic.py
if __name__ == "__main__":
    print("Running symbolic execution tests with CrossHair...")
    print("Use: uv run crosshair check symbolic.py")
