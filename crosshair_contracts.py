"""
crosshair_contracts.py - Property-based contracts for CrossHair symbolic execution.

These contracts define properties that should hold for all inputs.
"""

from parser import decode_module, Limits, DecodeError


def decode_never_crashes_on_bytes(data: bytes) -> bool:
    """
    PROPERTY: decode_module should never crash, only raise DecodeError or return Module.

    post: True
    """
    assert len(data) <= 1000  # Precondition: reasonable size limit

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=1000))
        # If it succeeds, module.raw_size should equal input size
        assert module.raw_size == len(data)
        return True
    except DecodeError:
        # Decode errors are expected for invalid input
        return True
    # Any other exception would be a contract violation


def valid_minimal_module_decodes() -> bool:
    """
    PROPERTY: A minimal valid WASM module should decode successfully.

    post: True
    """
    assert True  # No precondition

    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)

    # Postconditions
    assert module.raw_size == 8
    assert len(module.types) == 0
    assert len(module.imports) == 0

    return True


def decoder_respects_size_limit(data: bytes, limit: int) -> bool:
    """
    PROPERTY: If data exceeds the size limit, decode_module must raise DecodeError.

    post: True
    """
    # Preconditions
    if not (len(data) >= 1 and len(data) <= 2000):
        return True
    if not (limit >= 1 and limit < 2000):
        return True
    if not (len(data) > limit):
        return True

    try:
        decode_module(data, limits=Limits(max_module_bytes=limit))
        # Should not succeed
        assert False, "Should have raised DecodeError"
    except DecodeError:
        # Expected
        pass

    return True


def bad_magic_raises_error(b0: int, b1: int, b2: int, b3: int) -> bool:
    """
    PROPERTY: Data with invalid magic should raise DecodeError.

    post: True
    """
    # Preconditions
    if not (0 <= b0 <= 255 and 0 <= b1 <= 255 and 0 <= b2 <= 255 and 0 <= b3 <= 255):
        return True

    bad_magic = bytes([b0, b1, b2, b3])
    if bad_magic == b"\x00asm":  # Skip valid magic
        return True

    # Add version bytes
    data = bad_magic + b"\x01\x00\x00\x00"

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert "magic" in e.message.lower()

    return True


def truncated_data_raises_error(length: int) -> bool:
    """
    PROPERTY: Data shorter than magic+version should raise DecodeError.

    post: True
    """
    # Precondition
    if not (1 <= length < 8):
        return True

    data = b"\x00" * length

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError:
        pass

    return True
