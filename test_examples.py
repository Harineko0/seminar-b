"""
test_examples.py - Concrete test cases for WASM parser.

These are not symbolic tests, but concrete examples that demonstrate
the parser working on various valid and invalid WASM binaries.
"""

from parser import (
    decode_module,
    validate_module,
    decode_and_validate,
    DecodeError,
    ValidationError,
    Limits,
)


def test_minimal_module():
    """Test minimal valid WASM module."""
    data = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(data)
    assert module.raw_size == 8
    assert len(module.types) == 0
    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Minimal module test passed")


def test_bad_magic():
    """Test that bad magic is rejected."""
    data = b"\x00ASM\x01\x00\x00\x00"
    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "bad_magic"
        print("✓ Bad magic test passed")


def test_bad_version():
    """Test that bad version is rejected."""
    data = b"\x00asm\x02\x00\x00\x00"
    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "bad_version"
        print("✓ Bad version test passed")


def test_module_with_type_section():
    """Test module with a type section."""
    # Magic + version
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: id=1, count=1, functype: 0x60, params=[i32], results=[i32]
    # Payload: count(1) + functype_tag(1) + param_count(1) + i32(1) + result_count(1) + i32(1) = 6 bytes
    data += b"\x01"  # section id
    data += b"\x06"  # payload length (6 bytes)
    data += b"\x01"  # 1 type
    data += b"\x60"  # functype tag
    data += b"\x01"  # 1 param
    data += b"\x7F"  # i32
    data += b"\x01"  # 1 result
    data += b"\x7F"  # i32

    module = decode_module(data)
    assert module.raw_size == len(data)
    assert len(module.types) == 1
    assert len(module.types[0].params) == 1
    assert len(module.types[0].results) == 1
    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Type section test passed")


def test_module_with_export():
    """Test module with export section."""
    # Magic + version
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: 1 func type [] -> []
    data += b"\x01"  # section id
    data += b"\x04"  # payload length
    data += b"\x01"  # 1 type
    data += b"\x60"  # functype tag
    data += b"\x00"  # 0 params
    data += b"\x00"  # 0 results

    # Function section: 1 function with type 0
    data += b"\x03"  # section id
    data += b"\x02"  # payload length
    data += b"\x01"  # 1 function
    data += b"\x00"  # type index 0

    # Export section: export function 0 as "test"
    data += b"\x07"  # section id
    data += b"\x08"  # payload length
    data += b"\x01"  # 1 export
    data += b"\x04"  # name length
    data += b"test"  # name
    data += b"\x00"  # kind: func
    data += b"\x00"  # index 0

    # Code section: 1 function body (empty, just end)
    data += b"\x0A"  # section id
    data += b"\x04"  # payload length
    data += b"\x01"  # 1 code entry
    data += b"\x02"  # body size
    data += b"\x00"  # 0 locals
    data += b"\x0B"  # end

    module = decode_module(data)
    assert len(module.types) == 1
    assert len(module.function_types) == 1
    assert len(module.exports) == 1
    assert module.exports[0].name == b"test"
    assert len(module.code) == 1

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Export section test passed")


def test_duplicate_export_names():
    """Test that duplicate export names are caught."""
    # Magic + version
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section: 1 func type [] -> []
    data += b"\x01"  # section id
    data += b"\x04"  # payload length
    data += b"\x01"  # 1 type
    data += b"\x60"  # functype tag
    data += b"\x00"  # 0 params
    data += b"\x00"  # 0 results

    # Function section: 2 functions
    data += b"\x03"  # section id
    data += b"\x03"  # payload length
    data += b"\x02"  # 2 functions
    data += b"\x00"  # type 0
    data += b"\x00"  # type 0

    # Export section: 2 exports with same name
    # Payload: count(1) + (name_len(1) + name(3) + kind(1) + idx(1)) * 2 = 1 + 6*2 = 13 bytes
    data += b"\x07"  # section id
    data += b"\x0D"  # payload length (13 bytes)
    data += b"\x02"  # 2 exports
    data += b"\x03"  # name length
    data += b"foo"  # name
    data += b"\x00"  # kind: func
    data += b"\x00"  # index 0
    data += b"\x03"  # name length
    data += b"foo"  # same name!
    data += b"\x00"  # kind: func
    data += b"\x01"  # index 1

    # Code section: 2 function bodies
    data += b"\x0A"  # section id
    data += b"\x07"  # payload length
    data += b"\x02"  # 2 code entries
    data += b"\x02"  # body size
    data += b"\x00"  # 0 locals
    data += b"\x0B"  # end
    data += b"\x02"  # body size
    data += b"\x00"  # 0 locals
    data += b"\x0B"  # end

    module = decode_module(data)
    errors = validate_module(module)

    # Should have duplicate_export_name error
    assert any(e.code == "duplicate_export_name" for e in errors)
    print("✓ Duplicate export names test passed")


def test_size_limits():
    """Test that size limits are enforced."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Should succeed with default limits
    module = decode_module(data)
    assert module.raw_size == 8

    # Should fail with tiny limit
    try:
        decode_module(data, limits=Limits(max_module_bytes=4))
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "limit_exceeded"
        print("✓ Size limits test passed")


def test_out_of_order_sections():
    """Test that out-of-order sections are rejected."""
    # Magic + version
    data = b"\x00asm\x01\x00\x00\x00"

    # Function section before Type section (wrong order!)
    data += b"\x03"  # section id (function)
    data += b"\x02"  # payload length
    data += b"\x01"  # 1 function
    data += b"\x00"  # type index 0

    data += b"\x01"  # section id (type) - should come before function!
    data += b"\x04"  # payload length
    data += b"\x01"  # 1 type
    data += b"\x60"  # functype tag
    data += b"\x00"  # 0 params
    data += b"\x00"  # 0 results

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "section_order"
        print("✓ Out-of-order sections test passed")


def test_unsupported_opcode():
    """Test that unsupported opcodes are rejected."""
    # Magic + version
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section
    data += b"\x01\x04\x01\x60\x00\x00"
    # Function section
    data += b"\x03\x02\x01\x00"
    # Code section with unsupported opcode
    data += b"\x0A"  # section id
    data += b"\x05"  # payload length
    data += b"\x01"  # 1 code entry
    data += b"\x03"  # body size
    data += b"\x00"  # 0 locals
    data += b"\x42"  # i64.const (unsupported opcode!)
    data += b"\x00"

    try:
        decode_module(data)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "unsupported_opcode"
        print("✓ Unsupported opcode test passed")


def test_func_code_count_mismatch():
    """Test that function/code count mismatch is caught."""
    # Magic + version
    data = b"\x00asm\x01\x00\x00\x00"
    # Type section
    data += b"\x01\x04\x01\x60\x00\x00"
    # Function section: 2 functions
    data += b"\x03\x03\x02\x00\x00"
    # Code section: only 1 body (mismatch!)
    data += b"\x0A\x04\x01\x02\x00\x0B"

    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "func_code_count_mismatch" for e in errors)
    print("✓ Func/code count mismatch test passed")


if __name__ == "__main__":
    test_minimal_module()
    test_bad_magic()
    test_bad_version()
    test_module_with_type_section()
    test_module_with_export()
    test_duplicate_export_names()
    test_size_limits()
    test_out_of_order_sections()
    test_unsupported_opcode()
    test_func_code_count_mismatch()
    print("\n✅ All tests passed!")
