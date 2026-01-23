import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import struct

from parser import (
    decode_module, validate_module, decode_and_validate, DecodeError,
    Limits, Module, ValType, FuncType, ExportKind
)

# Keep limits small for fast feedback; raise later if needed.
LIMITS = Limits(max_module_bytes=256)

@settings(
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(data=st.binary(min_size=0, max_size=LIMITS.max_module_bytes))
def test_decode_never_crashes_other_than_decodeerror(data: bytes) -> None:
    """
    Fuzz bytes: decoder may accept or reject, but should not crash with unexpected exceptions.
    """
    try:
        _m = decode_module(data, limits=LIMITS)
    except DecodeError:
        return  # expected for malformed inputs


@settings(max_examples=200)
@given(data=st.binary(min_size=0, max_size=LIMITS.max_module_bytes))
def test_decode_then_validate_is_total(data: bytes) -> None:
    """
    If decode succeeds, validation should always return a list (possibly empty),
    not crash with unexpected exceptions.
    """
    try:
        m = decode_module(data, limits=LIMITS)
    except DecodeError:
        return
    errs = validate_module(m)
    assert isinstance(errs, list)


# Helper to encode LEB128
def encode_u32_leb128(value: int) -> bytes:
    """Encode unsigned 32-bit integer as LEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def encode_s32_leb128(value: int) -> bytes:
    """Encode signed 32-bit integer as LEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            result.append(byte)
            break
        else:
            result.append(byte | 0x80)
    return bytes(result)


def make_minimal_module() -> bytes:
    """Create a minimal valid WASM module."""
    return b'\x00asm\x01\x00\x00\x00'


def test_minimal_module():
    """Test that a minimal module (just magic + version) decodes successfully."""
    data = make_minimal_module()
    module = decode_module(data, limits=LIMITS)
    assert module.raw_size == 8
    assert len(module.types) == 0
    errors = validate_module(module)
    assert len(errors) == 0


def test_invalid_magic():
    """Test that invalid magic bytes cause DecodeError."""
    data = b'\x00bad\x01\x00\x00\x00'
    with pytest.raises(DecodeError):
        decode_module(data, limits=LIMITS)


def test_invalid_version():
    """Test that invalid version causes DecodeError."""
    data = b'\x00asm\x02\x00\x00\x00'
    with pytest.raises(DecodeError):
        decode_module(data, limits=LIMITS)


def test_type_section():
    """Test decoding a type section with function types."""
    # Magic + version
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section: id=1, vec_len=1, functype tag=0x60, params=[i32], results=[i32]
    data += b'\x01'  # section id
    section_data = encode_u32_leb128(1)  # 1 type
    section_data += b'\x60'  # functype tag
    section_data += encode_u32_leb128(1) + b'\x7F'  # params: [i32]
    section_data += encode_u32_leb128(1) + b'\x7F'  # results: [i32]
    data += encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    assert len(module.types) == 1
    assert len(module.types[0].params) == 1
    assert module.types[0].params[0] == ValType.I32
    assert len(module.types[0].results) == 1
    assert module.types[0].results[0] == ValType.I32


def test_export_duplicate_name_validation():
    """Test that duplicate export names are detected during validation."""
    # Create a module with duplicate export names
    data = b'\x00asm\x01\x00\x00\x00'
    # Export section with two exports with the same name
    data += b'\x07'  # section id
    section_data = encode_u32_leb128(2)  # 2 exports
    # Export 1: name="test", kind=func, index=0
    section_data += encode_u32_leb128(4) + b'test' + b'\x00' + encode_u32_leb128(0)
    # Export 2: name="test", kind=func, index=0 (duplicate name)
    section_data += encode_u32_leb128(4) + b'test' + b'\x00' + encode_u32_leb128(0)
    data += encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "duplicate_export_name" for e in errors)


def test_function_code_count_mismatch():
    """Test that function/code count mismatch is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section with one type: () -> ()
    section_data = encode_u32_leb128(1) + b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Function section with 2 functions
    section_data = encode_u32_leb128(2) + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x03' + encode_u32_leb128(len(section_data)) + section_data
    # Code section with 1 function body (mismatch!)
    body = encode_u32_leb128(0) + b'\x0B'  # no locals, just end
    section_data = encode_u32_leb128(1) + encode_u32_leb128(len(body)) + body
    data += b'\x0A' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "func_code_count_mismatch" for e in errors)


def test_local_index_out_of_range():
    """Test that local index out of range is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section: () -> ()
    section_data = encode_u32_leb128(1) + b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Function section
    section_data = encode_u32_leb128(1) + encode_u32_leb128(0)
    data += b'\x03' + encode_u32_leb128(len(section_data)) + section_data
    # Code section with local.get 5 (but no locals exist)
    body = encode_u32_leb128(0) + b'\x20' + encode_u32_leb128(5) + b'\x0B'  # no locals, local.get 5, end
    section_data = encode_u32_leb128(1) + encode_u32_leb128(len(body)) + body
    data += b'\x0A' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "local_index_out_of_range" for e in errors)


def test_section_order_violation():
    """Test that section order violation is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Export section (7) before Type section (1) - out of order!
    data += b'\x07' + encode_u32_leb128(1) + encode_u32_leb128(0)  # empty export
    data += b'\x01' + encode_u32_leb128(1) + encode_u32_leb128(0)  # empty type

    with pytest.raises(DecodeError) as exc_info:
        decode_module(data, limits=LIMITS)
    assert exc_info.value.code == "section_order"


def test_unsupported_opcode():
    """Test that unsupported opcodes cause DecodeError."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section: () -> ()
    section_data = encode_u32_leb128(1) + b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Function section
    section_data = encode_u32_leb128(1) + encode_u32_leb128(0)
    data += b'\x03' + encode_u32_leb128(len(section_data)) + section_data
    # Code section with unsupported opcode 0x42 (i64.const)
    body = encode_u32_leb128(0) + b'\x42' + encode_s32_leb128(0) + b'\x0B'  # no locals, i64.const (unsupported), end
    section_data = encode_u32_leb128(1) + encode_u32_leb128(len(body)) + body
    data += b'\x0A' + encode_u32_leb128(len(section_data)) + section_data

    with pytest.raises(DecodeError) as exc_info:
        decode_module(data, limits=LIMITS)
    assert exc_info.value.code == "unsupported_opcode"


def test_limits_min_gt_max():
    """Test that limits with min > max are detected during validation."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Table section with min=10, max=5 (invalid!)
    data += b'\x04'  # section id
    section_data = encode_u32_leb128(1)  # 1 table
    section_data += b'\x70'  # funcref
    section_data += b'\x01'  # limits flag (has max)
    section_data += encode_u32_leb128(10)  # min
    section_data += encode_u32_leb128(5)   # max
    data += encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "limits_min_gt_max" for e in errors)


def test_data_count_mismatch():
    """Test that data count mismatch is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Memory section
    section_data = encode_u32_leb128(1) + b'\x00' + encode_u32_leb128(1)  # 1 memory, min=1
    data += b'\x05' + encode_u32_leb128(len(section_data)) + section_data
    # Data section: 2 segments
    seg1 = encode_u32_leb128(0) + b'\x41' + encode_s32_leb128(0) + b'\x0B' + encode_u32_leb128(2) + b'ab'
    seg2 = encode_u32_leb128(0) + b'\x41' + encode_s32_leb128(0) + b'\x0B' + encode_u32_leb128(2) + b'cd'
    section_data = encode_u32_leb128(2) + seg1 + seg2
    data += b'\x0B' + encode_u32_leb128(len(section_data)) + section_data
    # Data count section: count=5 (mismatch with 2 actual segments)
    section_data = encode_u32_leb128(5)
    data += b'\x0C' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "data_count_mismatch" for e in errors)


def test_complex_function_with_locals():
    """Test decoding a function with multiple locals and instructions."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section: (i32) -> (i32)
    section_data = encode_u32_leb128(1) + b'\x60'
    section_data += encode_u32_leb128(1) + b'\x7F'  # params: [i32]
    section_data += encode_u32_leb128(1) + b'\x7F'  # results: [i32]
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Function section
    section_data = encode_u32_leb128(1) + encode_u32_leb128(0)
    data += b'\x03' + encode_u32_leb128(len(section_data)) + section_data
    # Code section with locals and instructions
    # Function body: 2 local i32 vars, local.get 0, local.get 1, i32.add, end
    body = encode_u32_leb128(1)  # 1 local decl
    body += encode_u32_leb128(2) + b'\x7F'  # 2 x i32
    body += b'\x20' + encode_u32_leb128(0)  # local.get 0 (param)
    body += b'\x20' + encode_u32_leb128(1)  # local.get 1 (local)
    body += b'\x6A'  # i32.add
    body += b'\x0B'  # end
    section_data = encode_u32_leb128(1) + encode_u32_leb128(len(body)) + body
    data += b'\x0A' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    assert len(module.code) == 1
    assert len(module.code[0].locals) == 1
    assert module.code[0].locals[0].count == 2
    errors = validate_module(module)
    assert len(errors) == 0


def test_import_function_type_index_out_of_range():
    """Test that imported function with invalid type index is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section with 1 type
    section_data = encode_u32_leb128(1) + b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Import section with function import using typeidx=5 (out of range)
    section_data = encode_u32_leb128(1)  # 1 import
    section_data += encode_u32_leb128(3) + b'env'  # module name
    section_data += encode_u32_leb128(3) + b'foo'  # name
    section_data += b'\x00'  # kind = func
    section_data += encode_u32_leb128(5)  # typeidx = 5 (out of range!)
    data += b'\x02' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "type_index_out_of_range" for e in errors)


def test_start_function_bad_signature():
    """Test that start function with non-empty signature is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section with 2 types: () -> () and (i32) -> ()
    section_data = encode_u32_leb128(2)
    section_data += b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)  # type 0: () -> ()
    section_data += b'\x60' + encode_u32_leb128(1) + b'\x7F' + encode_u32_leb128(0)  # type 1: (i32) -> ()
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Function section with 2 functions
    section_data = encode_u32_leb128(2) + encode_u32_leb128(0) + encode_u32_leb128(1)
    data += b'\x03' + encode_u32_leb128(len(section_data)) + section_data
    # Start section pointing to function 1 (which has type (i32) -> ())
    section_data = encode_u32_leb128(1)
    data += b'\x08' + encode_u32_leb128(len(section_data)) + section_data
    # Code section
    body1 = encode_u32_leb128(0) + b'\x0B'
    body2 = encode_u32_leb128(0) + b'\x0B'
    section_data = encode_u32_leb128(2)
    section_data += encode_u32_leb128(len(body1)) + body1
    section_data += encode_u32_leb128(len(body2)) + body2
    data += b'\x0A' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "bad_start_signature" for e in errors)


def test_element_segment_func_index_out_of_range():
    """Test that element segment with invalid function index is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Table section
    section_data = encode_u32_leb128(1) + b'\x70' + b'\x00' + encode_u32_leb128(10)
    data += b'\x04' + encode_u32_leb128(len(section_data)) + section_data
    # Element section with funcidx out of range
    section_data = encode_u32_leb128(1)  # 1 element segment
    section_data += encode_u32_leb128(0)  # tableidx = 0
    section_data += b'\x41' + encode_s32_leb128(0) + b'\x0B'  # offset: i32.const 0, end
    section_data += encode_u32_leb128(2)  # 2 function indices
    section_data += encode_u32_leb128(0) + encode_u32_leb128(99)  # funcidx 0 and 99 (99 is out of range)
    data += b'\x09' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_custom_sections():
    """Test that custom sections are preserved and don't interfere."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Custom section before type
    section_data = encode_u32_leb128(4) + b'test' + b'data'
    data += b'\x00' + encode_u32_leb128(len(section_data)) + section_data
    # Type section
    section_data = encode_u32_leb128(1) + b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Another custom section
    section_data = encode_u32_leb128(5) + b'other' + b'xyz'
    data += b'\x00' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    assert len(module.customs) == 2
    assert module.customs[0].name == b'test'
    assert module.customs[0].data == b'data'
    assert module.customs[1].name == b'other'
    assert module.customs[1].data == b'xyz'
    errors = validate_module(module)
    assert len(errors) == 0


def test_call_function_index_validation():
    """Test that call instruction with out-of-range funcidx is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section
    section_data = encode_u32_leb128(1) + b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data
    # Function section - 1 function
    section_data = encode_u32_leb128(1) + encode_u32_leb128(0)
    data += b'\x03' + encode_u32_leb128(len(section_data)) + section_data
    # Code section with call to funcidx 10 (out of range, only 1 function exists)
    body = encode_u32_leb128(0) + b'\x10' + encode_u32_leb128(10) + b'\x0B'
    section_data = encode_u32_leb128(1) + encode_u32_leb128(len(body)) + body
    data += b'\x0A' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_export_index_out_of_range():
    """Test that export with out-of-range index is detected."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Export section with func export to non-existent function
    section_data = encode_u32_leb128(1)  # 1 export
    section_data += encode_u32_leb128(4) + b'test'  # name
    section_data += b'\x00'  # kind = func
    section_data += encode_u32_leb128(5)  # index = 5 (no functions exist!)
    data += b'\x07' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_i64_type_support():
    """Test that i64 types are supported."""
    data = b'\x00asm\x01\x00\x00\x00'
    # Type section: (i64) -> (i64)
    section_data = encode_u32_leb128(1) + b'\x60'
    section_data += encode_u32_leb128(1) + b'\x7E'  # params: [i64]
    section_data += encode_u32_leb128(1) + b'\x7E'  # results: [i64]
    data += b'\x01' + encode_u32_leb128(len(section_data)) + section_data

    module = decode_module(data, limits=LIMITS)
    assert len(module.types) == 1
    assert module.types[0].params[0] == ValType.I64
    assert module.types[0].results[0] == ValType.I64
    errors = validate_module(module)
    assert len(errors) == 0

