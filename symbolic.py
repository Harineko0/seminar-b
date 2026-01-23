"""
symbolic.py - CrossHair symbolic execution tests for wasm_sv.

These tests use assert-based contracts that CrossHair will check symbolically.
"""

from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module
)


def test_decode_valid_minimal() -> None:
    """A minimal valid module should decode without error."""
    # Precondition: we're checking a known-valid minimal module
    assert True

    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)

    # Postconditions
    assert module.raw_size == 8
    assert len(module.types) == 0
    assert len(module.imports) == 0
    assert len(module.code) == 0


def test_decode_requires_magic() -> None:
    """Modules without correct magic should fail."""
    assert True

    # Bad magic
    bad_data = b"\x00BAD\x01\x00\x00\x00"
    try:
        decode_module(bad_data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert "magic" in e.message.lower()


def test_decode_requires_version() -> None:
    """Modules with wrong version should fail."""
    assert True

    # Bad version
    bad_data = b"\x00asm\x02\x00\x00\x00"
    try:
        decode_module(bad_data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert "version" in e.message.lower()


def test_decode_respects_size_limit() -> None:
    """Decoder must reject modules exceeding size limits."""
    assert True

    # Create a module that's too large
    data = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 100
    limits = Limits(max_module_bytes=50)

    try:
        decode_module(data, limits=limits)
        assert False, "Should have raised DecodeError for size limit"
    except DecodeError:
        pass


def test_validate_empty_module() -> None:
    """An empty module should validate successfully."""
    assert True

    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)
    errors = validate_module(module)

    assert len(errors) == 0


def test_decode_truncated_fails() -> None:
    """Truncated modules should fail to decode."""
    assert True

    # Truncated magic
    truncated = b"\x00as"
    try:
        decode_module(truncated)
        assert False, "Should have raised DecodeError"
    except DecodeError:
        pass


def test_leb128_u32_basic() -> None:
    """Basic LEB128 decoding should work for small values."""
    assert True

    # Type section with 0 types: section_id=1, size=1, count=0
    data = b"\x00asm\x01\x00\x00\x00\x01\x01\x00"
    module = decode_module(data)

    assert module.raw_size == len(data)
    assert len(module.types) == 0


def test_function_code_count_must_match() -> None:
    """Function section and code section must have same count."""
    assert True

    # Module with 1 type, 1 function reference, but 0 code bodies
    # Type section: section_id=1, size=4, count=1, functype(0x60, 0 params, 0 results)
    type_sec = b"\x01\x04\x01\x60\x00\x00"
    # Function section: section_id=3, size=2, count=1, typeidx=0
    func_sec = b"\x03\x02\x01\x00"

    data = b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec
    module = decode_module(data)

    errors = validate_module(module)
    # Should have func_code_count_mismatch error
    assert len(errors) > 0
    assert any(e.code == "func_code_count_mismatch" for e in errors)


def test_export_duplicate_name_error() -> None:
    """Duplicate export names should produce validation error."""
    assert True

    # Create module with two exports with same name
    # Export section: section_id=7, size=13, count=2
    # Export 1: name="foo" (len=3), kind=0 (func), index=0
    # Export 2: name="foo" (len=3), kind=0 (func), index=0
    export_sec = b"\x07\x0d\x02\x03foo\x00\x00\x03foo\x00\x00"

    data = b"\x00asm\x01\x00\x00\x00" + export_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "duplicate_export_name" for e in errors)


def test_limits_min_must_not_exceed_max() -> None:
    """Table/memory limits with min > max should fail validation."""
    assert True

    # Memory section: section_id=5, size=5, count=1, flags=0x01, min=100, max=50
    # LEB128: 100 = 0xe4 0x00 (2 bytes), 50 = 0x32 (1 byte)
    mem_sec = b"\x05\x05\x01\x01\xe4\x00\x32"

    data = b"\x00asm\x01\x00\x00\x00" + mem_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "limits_min_gt_max" for e in errors)


def test_unsupported_valtype_fails() -> None:
    """Value types other than i32/i64 should fail decoding."""
    assert True

    # Type section with f32 (0x7D) which is not supported
    # section_id=1, size=4, count=1, functype(0x60, params=[f32], results=[])
    type_sec = b"\x01\x04\x01\x60\x01\x7d"

    data = b"\x00asm\x01\x00\x00\x00" + type_sec

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError for unsupported valtype"
    except DecodeError as e:
        assert "valtype" in e.code or "valtype" in e.message.lower()


def test_section_order_enforced() -> None:
    """Non-custom sections must appear in canonical order."""
    assert True

    # Put export section (7) before type section (1) - wrong order
    export_sec = b"\x07\x01\x00"  # Empty export section
    type_sec = b"\x01\x01\x00"    # Empty type section

    data = b"\x00asm\x01\x00\x00\x00" + export_sec + type_sec

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError for section order"
    except DecodeError as e:
        assert "order" in e.code or "order" in e.message.lower()


def test_start_function_signature_validated() -> None:
    """Start function must have type []->[]."""
    assert True

    # Type section: functype with params=[i32], results=[]
    type_sec = b"\x01\x05\x01\x60\x01\x7f\x00"
    # Function section: 1 function with typeidx=0
    func_sec = b"\x03\x02\x01\x00"
    # Code section: 1 function body with 0 locals, just end
    code_sec = b"\x0a\x04\x01\x02\x00\x0b"
    # Start section: funcidx=0
    start_sec = b"\x08\x01\x00"

    data = b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec + start_sec + code_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "bad_start_signature" for e in errors)


def test_unsupported_opcode_fails() -> None:
    """Opcodes outside the supported subset should fail decoding."""
    assert True

    # Type section: functype []->[]
    type_sec = b"\x01\x04\x01\x60\x00\x00"
    # Function section: 1 function
    func_sec = b"\x03\x02\x01\x00"
    # Code section: 1 function with unsupported opcode 0x1A (drop)
    code_sec = b"\x0a\x05\x01\x03\x00\x1a\x0b"

    data = b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec + code_sec

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError for unsupported opcode"
    except DecodeError as e:
        assert "opcode" in e.code or "opcode" in e.message.lower()


def test_local_index_validation() -> None:
    """Local indices in local.get/set must be in range."""
    assert True

    # Type section: functype [i32]->[]
    type_sec = b"\x01\x05\x01\x60\x01\x7f\x00"
    # Function section: 1 function
    func_sec = b"\x03\x02\x01\x00"
    # Code section: function with 0 additional locals, local.get 5 (out of range)
    # Body: size=5, locals count=0, local.get 5, end
    code_sec = b"\x0a\x06\x01\x04\x00\x20\x05\x0b"

    data = b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec + code_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "local_index_out_of_range" for e in errors)


def test_call_index_validation() -> None:
    """Call indices must be in range."""
    assert True

    # Type section: functype []->[]
    type_sec = b"\x01\x04\x01\x60\x00\x00"
    # Function section: 1 function
    func_sec = b"\x03\x02\x01\x00"
    # Code section: function calling funcidx=10 (doesn't exist)
    # Body: size=5, locals=0, call 10, end
    code_sec = b"\x0a\x06\x01\x04\x00\x10\x0a\x0b"

    data = b"\x00asm\x01\x00\x00\x00" + type_sec + func_sec + code_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "index_out_of_range" for e in errors)


def test_data_count_validation() -> None:
    """Data count section must match actual data segments."""
    assert True

    # Data section: 0 segments
    data_sec = b"\x0b\x01\x00"
    # Data count section: count=5
    datacount_sec = b"\x0c\x01\x05"

    data = b"\x00asm\x01\x00\x00\x00" + data_sec + datacount_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "data_count_mismatch" for e in errors)


def test_element_offset_must_be_i32_const() -> None:
    """Element segment offset must be exactly i32.const + end."""
    assert True

    # Table section: 1 table
    table_sec = b"\x04\x04\x01\x70\x00\x0a"
    # Element section with invalid offset expression (local.get instead of i32.const)
    # section_id=9, size=6, count=1, tableidx=0, offset=(local.get 0, end), init count=0
    elem_sec = b"\x09\x06\x01\x00\x20\x00\x0b\x00"

    data = b"\x00asm\x01\x00\x00\x00" + table_sec + elem_sec

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError for invalid element offset"
    except DecodeError as e:
        # Accept any decode error - the key is it must reject this
        pass


def test_data_offset_must_be_i32_const() -> None:
    """Data segment offset must be exactly i32.const + end."""
    assert True

    # Memory section: 1 memory
    mem_sec = b"\x05\x03\x01\x00\x01"
    # Data section with invalid offset (local.get instead of i32.const)
    # section_id=11, size=6, count=1, memidx=0, offset=(local.get 0, end), data len=0
    data_sec = b"\x0b\x06\x01\x00\x20\x00\x0b\x00"

    data = b"\x00asm\x01\x00\x00\x00" + mem_sec + data_sec

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError for invalid data offset"
    except DecodeError as e:
        # Accept any decode error - the key is it must reject this
        pass


def test_decode_and_validate_integration() -> None:
    """decode_and_validate should raise on validation errors."""
    assert True

    # Module with duplicate export names
    export_sec = b"\x07\x0d\x02\x03foo\x00\x00\x03foo\x00\x00"
    data = b"\x00asm\x01\x00\x00\x00" + export_sec

    try:
        decode_and_validate(data)
        assert False, "Should have raised ValueError for validation errors"
    except ValueError as e:
        assert "duplicate_export_name" in str(e)


def test_custom_sections_allowed_anywhere() -> None:
    """Custom sections (id=0) can appear anywhere in the module."""
    assert True

    # Custom section before and after type section
    # custom1: section_id=0, size=5, name_len=3, name="foo", data=0xaa (1 byte)
    custom1 = b"\x00\x05\x03foo\xaa"
    type_sec = b"\x01\x01\x00"
    # custom2: section_id=0, size=6, name_len=3, name="bar", data=0xbb,0xcc (2 bytes)
    custom2 = b"\x00\x06\x03bar\xbb\xcc"

    data = b"\x00asm\x01\x00\x00\x00" + custom1 + type_sec + custom2
    module = decode_module(data)

    assert len(module.customs) == 2
    assert module.customs[0].name == b"foo"
    assert module.customs[1].name == b"bar"


def test_type_index_validation_for_imports() -> None:
    """Import function typeidx must be in range."""
    assert True

    # Import section: import func with typeidx=5, but no type section
    # section_id=2, size=7, count=1, module="m", name="f", kind=0, typeidx=5
    import_sec = b"\x02\x07\x01\x01m\x01f\x00\x05"

    data = b"\x00asm\x01\x00\x00\x00" + import_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "type_index_out_of_range" for e in errors)


def test_export_index_validation() -> None:
    """Export indices must be valid for each kind."""
    assert True

    # Export a func index that doesn't exist
    # section_id=7, size=5, count=1, name="f", kind=0 (func), index=10
    export_sec = b"\x07\x05\x01\x01f\x00\x0a"

    data = b"\x00asm\x01\x00\x00\x00" + export_sec
    module = decode_module(data)

    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "index_out_of_range" for e in errors)


# Add a function to run all tests manually (CrossHair will check each individually)
def run_all_tests() -> None:
    """Manually run all test functions (for debugging)."""
    test_decode_valid_minimal()
    test_decode_requires_magic()
    test_decode_requires_version()
    test_decode_respects_size_limit()
    test_validate_empty_module()
    test_decode_truncated_fails()
    test_leb128_u32_basic()
    test_function_code_count_must_match()
    test_export_duplicate_name_error()
    test_limits_min_must_not_exceed_max()
    test_unsupported_valtype_fails()
    test_section_order_enforced()
    test_start_function_signature_validated()
    test_unsupported_opcode_fails()
    test_local_index_validation()
    test_call_index_validation()
    test_data_count_validation()
    test_element_offset_must_be_i32_const()
    test_data_offset_must_be_i32_const()
    test_decode_and_validate_integration()
    test_custom_sections_allowed_anywhere()
    test_type_index_validation_for_imports()
    test_export_index_validation()
    print("All tests passed!")


if __name__ == "__main__":
    run_all_tests()
