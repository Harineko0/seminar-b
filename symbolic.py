"""
symbolic.py - CrossHair symbolic execution contracts for wasm_sv

This file defines symbolic contracts that CrossHair will explore to find counterexamples.
We focus on critical invariants that must hold for all inputs.
"""

from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module
)


def check_decode_never_crashes(data: bytes) -> bool:
    """
    Property: decode_module either returns a Module or raises DecodeError.
    No other exceptions should occur.

    pre: len(data) <= 256
    post: __return__ == True
    """
    assert len(data) <= 256  # precondition for reasonable runtime

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
        # If we get here, decoding succeeded
        assert isinstance(module, Module)
        assert module.raw_size == len(data)
        return True
    except DecodeError:
        # Expected for malformed input
        return True


def check_validate_is_total(data: bytes) -> bool:
    """
    Property: If decode succeeds, validate_module always returns a list.

    pre: len(data) <= 256
    post: __return__ == True
    """
    assert len(data) <= 256

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
    except DecodeError:
        return True

    errors = validate_module(module)
    assert isinstance(errors, list)
    assert all(isinstance(e, ValidationError) for e in errors)
    return True


def check_valid_magic_version() -> bool:
    """
    Property: Minimal valid module (just magic + version) should decode successfully.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data, limits=Limits(max_module_bytes=64))
    assert module.raw_size == 8
    assert len(module.types) == 0
    errors = validate_module(module)
    assert len(errors) == 0
    return True


def check_invalid_magic_fails() -> bool:
    """
    Property: Invalid magic should raise DecodeError.

    post: __return__ == True
    """
    data = b"\x00BAD\x01\x00\x00\x00"
    try:
        decode_module(data, limits=Limits(max_module_bytes=64))
        return False  # Should have raised
    except DecodeError:
        return True


def check_module_size_limit_enforced() -> bool:
    """
    Property: Modules exceeding max_module_bytes should raise DecodeError.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 100
    try:
        decode_module(data, limits=Limits(max_module_bytes=10))
        return False  # Should have raised
    except DecodeError:
        return True


def check_leb128_u32_bounds(byte_val: int) -> bool:
    """
    Property: Single-byte LEB128 values are correctly bounded.

    pre: 0 <= byte_val < 128
    post: __return__ == True
    """
    assert 0 <= byte_val < 128

    # Custom section with a single-byte length
    data = b"\x00asm\x01\x00\x00\x00"
    data += bytes([0])  # custom section id
    data += bytes([byte_val])  # length (single byte LEB128)
    data += b"\x00" * byte_val  # name length = 0, then padding

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=256))
        # Should succeed for valid inputs
        return True
    except DecodeError:
        # May fail if byte_val is too large or structure is malformed
        return True


def check_type_section_basic() -> bool:
    """
    Property: Type section with one func type [] -> [] should decode.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: id=1, len=4, count=1, functype tag=0x60, params count=0, results count=0
    data += b"\x01\x04\x01\x60\x00\x00"

    module = decode_module(data, limits=Limits(max_module_bytes=64))
    assert len(module.types) == 1
    assert len(module.types[0].params) == 0
    assert len(module.types[0].results) == 0

    errors = validate_module(module)
    assert len(errors) == 0
    return True


def check_export_duplicate_names_detected() -> bool:
    """
    Property: Duplicate export names should be detected by validation.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: [] -> []
    data += b"\x01\x04\x01\x60\x00\x00"
    # Function section: 1 func, typeidx=0
    data += b"\x03\x02\x01\x00"
    # Export section: 2 exports with same name "test"
    # Section 7, payload: count=2, then 2 exports
    # Each export: name_len + name_bytes + kind + index
    # export 1: len=4, "test", kind=0 (func), index=0
    # export 2: len=4, "test", kind=0 (func), index=0
    payload = b"\x02"  # count=2
    payload += b"\x04" + b"test" + b"\x00\x00"  # name len=4, name, kind=func, idx=0
    payload += b"\x04" + b"test" + b"\x00\x00"  # duplicate
    data += bytes([0x07]) + bytes([len(payload)]) + payload
    # Code section: 1 body, size=2, locals=0, end
    data += b"\x0a\x04\x01\x02\x00\x0b"

    module = decode_module(data, limits=Limits(max_module_bytes=128))
    errors = validate_module(module)

    # Should have duplicate_export_name error
    has_dup_error = any(e.code == "duplicate_export_name" for e in errors)
    assert has_dup_error
    return True


def check_start_func_signature() -> bool:
    """
    Property: Start function with non-empty signature should fail validation.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: [i32] -> []
    data += b"\x01\x05\x01\x60\x01\x7f\x00"
    # Function section: 1 func, typeidx=0
    data += b"\x03\x02\x01\x00"
    # Start section: funcidx=0
    data += b"\x08\x01\x00"
    # Code section: 1 body
    data += b"\x0a\x04\x01\x02\x00\x0b"

    module = decode_module(data, limits=Limits(max_module_bytes=128))
    errors = validate_module(module)

    # Should have bad_start_signature error
    has_bad_start = any(e.code == "bad_start_signature" for e in errors)
    assert has_bad_start
    return True


def check_limits_validation() -> bool:
    """
    Property: Limits with min > max should fail validation.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Memory section: limits with min=10, max=5
    data += b"\x05\x04\x01\x01\x0a\x05"  # mem section, 1 mem, flags=1, min=10, max=5

    module = decode_module(data, limits=Limits(max_module_bytes=128))
    errors = validate_module(module)

    # Should have limits_min_gt_max error
    has_limits_error = any(e.code == "limits_min_gt_max" for e in errors)
    assert has_limits_error
    return True


def check_func_code_count_mismatch() -> bool:
    """
    Property: Mismatched function/code counts should fail validation.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section
    data += b"\x01\x04\x01\x60\x00\x00"
    # Function section: 2 functions
    data += b"\x03\x03\x02\x00\x00"
    # Code section: 1 body (mismatch!)
    data += b"\x0a\x04\x01\x02\x00\x0b"

    module = decode_module(data, limits=Limits(max_module_bytes=128))
    errors = validate_module(module)

    # Should have func_code_count_mismatch error
    has_mismatch = any(e.code == "func_code_count_mismatch" for e in errors)
    assert has_mismatch
    return True


def check_local_index_validation() -> bool:
    """
    Property: Out-of-range local index should fail validation.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: [] -> []
    data += b"\x01\x04\x01\x60\x00\x00"
    # Function section: 1 func
    data += b"\x03\x02\x01\x00"
    # Code section: 1 body with local.get 100 (out of range)
    data += b"\x0a\x06\x01\x04\x00\x20\x64\x0b"  # body size=4, locals=0, local.get 100, end

    module = decode_module(data, limits=Limits(max_module_bytes=128))
    errors = validate_module(module)

    # Should have local_index_out_of_range error
    has_local_error = any(e.code == "local_index_out_of_range" for e in errors)
    assert has_local_error
    return True


def check_data_count_validation() -> bool:
    """
    Property: Data count mismatch should fail validation.

    post: __return__ == True
    """
    data = b"\x00asm\x01\x00\x00\x00"
    # Data section: 1 segment
    data += b"\x0b\x06\x01\x00\x41\x00\x0b\x00"  # 1 segment: memidx=0, offset=i32.const 0, len=0
    # Data count section: count=2 (mismatch! - comes after data section)
    data += b"\x0c\x01\x02"

    module = decode_module(data, limits=Limits(max_module_bytes=128))
    errors = validate_module(module)

    # Should have data_count_mismatch error
    has_data_error = any(e.code == "data_count_mismatch" for e in errors)
    assert has_data_error
    return True
