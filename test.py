"""
test.py - Comprehensive pytest tests for wasm_sv parser
"""

import pytest
from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module,
    ValType, FuncType, I32Const, End
)


# ----------------------------
# Helper functions
# ----------------------------

def make_wasm(*sections: bytes) -> bytes:
    """Build a WASM module from magic/version + sections."""
    return b'\x00asm\x01\x00\x00\x00' + b''.join(sections)


def encode_u32(val: int) -> bytes:
    """Encode u32 as unsigned LEB128."""
    result = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def encode_s32(val: int) -> bytes:
    """Encode s32 as signed LEB128."""
    result = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if (val == 0 and (byte & 0x40) == 0) or (val == -1 and (byte & 0x40) != 0):
            result.append(byte)
            break
        else:
            result.append(byte | 0x80)
    return bytes(result)


def section(section_id: int, payload: bytes) -> bytes:
    """Build a section with id and payload."""
    return bytes([section_id]) + encode_u32(len(payload)) + payload


def vec(items: list) -> bytes:
    """Encode a vector."""
    return encode_u32(len(items)) + b''.join(items)


def name(s: bytes) -> bytes:
    """Encode a name."""
    return encode_u32(len(s)) + s


# ----------------------------
# Basic decoding tests
# ----------------------------

def test_minimal_module():
    """Test decoding minimal valid module."""
    wasm = make_wasm()
    module = decode_module(wasm)
    assert module.raw_size == 8
    assert len(module.types) == 0


def test_invalid_magic():
    """Test that invalid magic causes DecodeError."""
    wasm = b'\x01asm\x01\x00\x00\x00'
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert "magic" in str(exc.value).lower()


def test_invalid_version():
    """Test that invalid version causes DecodeError."""
    wasm = b'\x00asm\x02\x00\x00\x00'
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert "version" in str(exc.value).lower()


def test_module_size_limit():
    """Test that module size limit is enforced."""
    wasm = make_wasm()
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm, limits=Limits(max_module_bytes=4))
    assert "exceeds limit" in str(exc.value)


# ----------------------------
# Type section tests
# ----------------------------

def test_type_section_empty():
    """Test empty type section."""
    payload = vec([])
    wasm = make_wasm(section(1, payload))
    module = decode_module(wasm)
    assert len(module.types) == 0


def test_type_section_single_functype():
    """Test single functype in type section."""
    # functype with params=[i32] results=[i64]
    functype = b'\x60' + vec([b'\x7F']) + vec([b'\x7E'])
    payload = vec([functype])
    wasm = make_wasm(section(1, payload))
    module = decode_module(wasm)
    assert len(module.types) == 1
    assert module.types[0].params == [ValType.I32]
    assert module.types[0].results == [ValType.I64]


def test_type_section_multiple_functypes():
    """Test multiple functypes."""
    ft1 = b'\x60' + vec([]) + vec([])
    ft2 = b'\x60' + vec([b'\x7F', b'\x7F']) + vec([b'\x7F'])
    payload = vec([ft1, ft2])
    wasm = make_wasm(section(1, payload))
    module = decode_module(wasm)
    assert len(module.types) == 2
    assert module.types[0].params == []
    assert module.types[0].results == []
    assert module.types[1].params == [ValType.I32, ValType.I32]
    assert module.types[1].results == [ValType.I32]


def test_unsupported_valtype():
    """Test that unsupported valtype causes DecodeError."""
    functype = b'\x60' + vec([b'\x7D']) + vec([])  # f32 is not supported
    payload = vec([functype])
    wasm = make_wasm(section(1, payload))
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_valtype"


# ----------------------------
# Import section tests
# ----------------------------

def test_import_func():
    """Test importing a function."""
    # Type section with one functype
    functype = b'\x60' + vec([]) + vec([])
    type_sec = section(1, vec([functype]))

    # Import section with one func import
    import_entry = name(b'env') + name(b'log') + b'\x00' + encode_u32(0)
    import_sec = section(2, vec([import_entry]))

    wasm = make_wasm(type_sec, import_sec)
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].module == b'env'
    assert module.imports[0].name == b'log'


def test_import_table():
    """Test importing a table."""
    import_entry = name(b'js') + name(b'tbl') + b'\x01' + b'\x70' + b'\x00' + encode_u32(10)
    import_sec = section(2, vec([import_entry]))
    wasm = make_wasm(import_sec)
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].tabletype.elemtype == 0x70
    assert module.imports[0].tabletype.limits.min == 10
    assert module.imports[0].tabletype.limits.max is None


def test_import_memory():
    """Test importing a memory."""
    import_entry = name(b'js') + name(b'mem') + b'\x02' + b'\x01' + encode_u32(1) + encode_u32(10)
    import_sec = section(2, vec([import_entry]))
    wasm = make_wasm(import_sec)
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].limits.min == 1
    assert module.imports[0].limits.max == 10


def test_import_global():
    """Test importing a global."""
    import_entry = name(b'js') + name(b'g') + b'\x03' + b'\x7F' + b'\x00'
    import_sec = section(2, vec([import_entry]))
    wasm = make_wasm(import_sec)
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].globaltype.valtype == ValType.I32
    assert module.imports[0].globaltype.mutable is False


# ----------------------------
# Function section tests
# ----------------------------

def test_function_section():
    """Test function section with typeidxs."""
    functype = b'\x60' + vec([]) + vec([])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0), encode_u32(0)]))
    wasm = make_wasm(type_sec, func_sec)
    module = decode_module(wasm)
    assert module.function_typeidxs == [0, 0]


# ----------------------------
# Table section tests
# ----------------------------

def test_table_section():
    """Test table section."""
    table = b'\x70' + b'\x01' + encode_u32(5) + encode_u32(20)
    table_sec = section(4, vec([table]))
    wasm = make_wasm(table_sec)
    module = decode_module(wasm)
    assert len(module.tables) == 1
    assert module.tables[0].limits.min == 5
    assert module.tables[0].limits.max == 20


def test_unsupported_table_elemtype():
    """Test that non-funcref elemtype causes DecodeError."""
    table = b'\x6F' + b'\x00' + encode_u32(5)  # 0x6F is not funcref
    table_sec = section(4, vec([table]))
    wasm = make_wasm(table_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_table_elemtype"


# ----------------------------
# Memory section tests
# ----------------------------

def test_memory_section():
    """Test memory section."""
    mem = b'\x00' + encode_u32(1)
    mem_sec = section(5, vec([mem]))
    wasm = make_wasm(mem_sec)
    module = decode_module(wasm)
    assert len(module.mems) == 1
    assert module.mems[0].min == 1
    assert module.mems[0].max is None


# ----------------------------
# Global section tests
# ----------------------------

def test_global_section():
    """Test global section."""
    # Global: i32 mutable, init = i32.const 42; end
    global_entry = b'\x7F\x01' + b'\x41' + encode_s32(42) + b'\x0B'
    global_sec = section(6, vec([global_entry]))
    wasm = make_wasm(global_sec)
    module = decode_module(wasm)
    assert len(module.globals) == 1
    assert module.globals[0].globaltype.valtype == ValType.I32
    assert module.globals[0].globaltype.mutable is True
    assert isinstance(module.globals[0].init.instrs[0], I32Const)
    assert module.globals[0].init.instrs[0].value == 42


# ----------------------------
# Export section tests
# ----------------------------

def test_export_section():
    """Test export section."""
    export_entry = name(b'add') + b'\x00' + encode_u32(0)
    export_sec = section(7, vec([export_entry]))
    wasm = make_wasm(export_sec)
    module = decode_module(wasm)
    assert len(module.exports) == 1
    assert module.exports[0].name == b'add'
    assert module.exports[0].kind == 0
    assert module.exports[0].index == 0


# ----------------------------
# Start section tests
# ----------------------------

def test_start_section():
    """Test start section."""
    start_sec = section(8, encode_u32(0))
    wasm = make_wasm(start_sec)
    module = decode_module(wasm)
    assert module.start == 0


# ----------------------------
# Element section tests
# ----------------------------

def test_element_section():
    """Test element section."""
    # elem: tableidx=0, offset=i32.const 0; end, init=[0]
    elem = encode_u32(0) + b'\x41' + encode_s32(0) + b'\x0B' + vec([encode_u32(0)])
    elem_sec = section(9, vec([elem]))
    wasm = make_wasm(elem_sec)
    module = decode_module(wasm)
    assert len(module.elems) == 1
    assert module.elems[0].tableidx == 0
    assert module.elems[0].init == [0]


def test_element_invalid_tableidx():
    """Test that element with tableidx != 0 causes DecodeError."""
    elem = encode_u32(1) + b'\x41' + encode_s32(0) + b'\x0B' + vec([encode_u32(0)])
    elem_sec = section(9, vec([elem]))
    wasm = make_wasm(elem_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_element_form"


def test_element_invalid_offset():
    """Test that element with non-const offset causes DecodeError."""
    # offset is local.get 0; end instead of i32.const
    elem = encode_u32(0) + b'\x20' + encode_u32(0) + b'\x0B' + vec([encode_u32(0)])
    elem_sec = section(9, vec([elem]))
    wasm = make_wasm(elem_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_element_form"


# ----------------------------
# Code section tests
# ----------------------------

def test_code_section():
    """Test code section."""
    # Function body: no locals, i32.const 42; end
    body = vec([]) + b'\x41' + encode_s32(42) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    # Need type and function sections too
    functype = b'\x60' + vec([]) + vec([b'\x7F'])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0)]))

    wasm = make_wasm(type_sec, func_sec, code_sec)
    module = decode_module(wasm)
    assert len(module.code) == 1
    assert len(module.code[0].locals) == 0
    assert len(module.code[0].expr.instrs) == 2


def test_code_with_locals():
    """Test code with local declarations."""
    # Function body: 2 x i32 locals, i32.const 42; end
    locals_decl = vec([encode_u32(2) + b'\x7F'])
    body = locals_decl + b'\x41' + encode_s32(42) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    functype = b'\x60' + vec([]) + vec([b'\x7F'])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0)]))

    wasm = make_wasm(type_sec, func_sec, code_sec)
    module = decode_module(wasm)
    assert len(module.code[0].locals) == 1
    assert module.code[0].locals[0].count == 2
    assert module.code[0].locals[0].valtype == ValType.I32


# ----------------------------
# Data section tests
# ----------------------------

def test_data_section():
    """Test data section."""
    # data: memidx=0, offset=i32.const 0; end, bytes="hello"
    data_seg = encode_u32(0) + b'\x41' + encode_s32(0) + b'\x0B' + name(b'hello')
    data_sec = section(11, vec([data_seg]))
    wasm = make_wasm(data_sec)
    module = decode_module(wasm)
    assert len(module.datas) == 1
    assert module.datas[0].memidx == 0
    assert module.datas[0].data == b'hello'


def test_data_invalid_memidx():
    """Test that data with memidx != 0 causes DecodeError."""
    data_seg = encode_u32(1) + b'\x41' + encode_s32(0) + b'\x0B' + name(b'x')
    data_sec = section(11, vec([data_seg]))
    wasm = make_wasm(data_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_data_form"


# ----------------------------
# Data count section tests
# ----------------------------

def test_data_count_section():
    """Test data count section."""
    data_count_sec = section(12, encode_u32(0))
    wasm = make_wasm(data_count_sec)
    module = decode_module(wasm)
    assert module.data_count == 0


# ----------------------------
# Custom section tests
# ----------------------------

def test_custom_section():
    """Test custom section."""
    payload = name(b'name') + b'custom data'
    custom_sec = section(0, payload)
    wasm = make_wasm(custom_sec)
    module = decode_module(wasm)
    assert len(module.customs) == 1
    assert module.customs[0].name == b'name'
    assert module.customs[0].data == b'custom data'


# ----------------------------
# Section ordering tests
# ----------------------------

def test_section_order_violation():
    """Test that out-of-order sections cause DecodeError."""
    # Function section (3) before type section (1) is invalid
    func_sec = section(3, vec([encode_u32(0)]))
    type_sec = section(1, vec([]))
    wasm = make_wasm(func_sec, type_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "section_order"


def test_duplicate_section():
    """Test that duplicate sections cause DecodeError."""
    type_sec = section(1, vec([]))
    wasm = make_wasm(type_sec, type_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "section_order"


def test_custom_sections_anywhere():
    """Test that custom sections can appear anywhere."""
    custom1 = section(0, name(b'a') + b'')
    type_sec = section(1, vec([]))
    custom2 = section(0, name(b'b') + b'')
    func_sec = section(3, vec([]))
    custom3 = section(0, name(b'c') + b'')
    wasm = make_wasm(custom1, type_sec, custom2, func_sec, custom3)
    module = decode_module(wasm)
    assert len(module.customs) == 3


# ----------------------------
# Unknown section tests
# ----------------------------

def test_unknown_section():
    """Test that unknown section id causes DecodeError."""
    unknown_sec = section(99, b'')
    wasm = make_wasm(unknown_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unknown_section_id"


# ----------------------------
# Section size mismatch tests
# ----------------------------

def test_section_size_mismatch():
    """Test that section size mismatch causes DecodeError."""
    # Claim payload is 10 bytes but only provide 5
    wasm = b'\x00asm\x01\x00\x00\x00' + bytes([1, 10]) + b'12345'
    with pytest.raises(DecodeError):
        decode_module(wasm)


# ----------------------------
# Instruction tests
# ----------------------------

def test_all_instructions():
    """Test all supported instructions."""
    # Function with all instruction types
    body = (
        vec([]) +  # no locals
        b'\x41' + encode_s32(10) +    # i32.const 10
        b'\x20' + encode_u32(0) +      # local.get 0
        b'\x21' + encode_u32(0) +      # local.set 0
        b'\x6A' +                      # i32.add
        b'\x10' + encode_u32(0) +      # call 0
        b'\x0B'                        # end
    )
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    # Type section with two functypes
    ft1 = b'\x60' + vec([b'\x7F']) + vec([b'\x7F'])
    type_sec = section(1, vec([ft1]))
    func_sec = section(3, vec([encode_u32(0)]))

    wasm = make_wasm(type_sec, func_sec, code_sec)
    module = decode_module(wasm)
    assert len(module.code) == 1


def test_unsupported_opcode():
    """Test that unsupported opcode causes DecodeError."""
    # 0x1A is drop, not supported
    body = vec([]) + b'\x1A' + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    functype = b'\x60' + vec([]) + vec([])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0)]))

    wasm = make_wasm(type_sec, func_sec, code_sec)
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_opcode"


# ----------------------------
# LEB128 tests
# ----------------------------

def test_leb128_truncated():
    """Test that truncated LEB128 causes DecodeError."""
    # Section with truncated length encoding
    wasm = b'\x00asm\x01\x00\x00\x00' + bytes([1, 0x80])  # 0x80 indicates more bytes follow
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert "truncated" in str(exc.value).lower() or "eof" in str(exc.value).lower()


def test_leb128_overflow():
    """Test that LEB128 overflow causes DecodeError."""
    # Encode a value > u32::MAX
    wasm = b'\x00asm\x01\x00\x00\x00' + bytes([1, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F])
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    # Should succeed as 0x1FFFFFFF fits in u32

    # Try with actual overflow
    wasm = b'\x00asm\x01\x00\x00\x00' + bytes([1, 0x80, 0x80, 0x80, 0x80, 0x80])
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert "overflow" in str(exc.value).lower()


# ----------------------------
# Validation tests
# ----------------------------

def test_validate_limits_min_gt_max():
    """Test validation error for limits where min > max."""
    table = b'\x70' + b'\x01' + encode_u32(20) + encode_u32(10)
    table_sec = section(4, vec([table]))
    wasm = make_wasm(table_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) == 1
    assert errors[0].code == "limits_min_gt_max"


def test_validate_duplicate_export_name():
    """Test validation error for duplicate export names."""
    exp1 = name(b'foo') + b'\x00' + encode_u32(0)
    exp2 = name(b'foo') + b'\x00' + encode_u32(0)
    export_sec = section(7, vec([exp1, exp2]))
    wasm = make_wasm(export_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "duplicate_export_name" for e in errors)


def test_validate_export_index_out_of_range():
    """Test validation error for export with out-of-range index."""
    exp = name(b'foo') + b'\x00' + encode_u32(5)  # func 5 doesn't exist
    export_sec = section(7, vec([exp]))
    wasm = make_wasm(export_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_start_index_out_of_range():
    """Test validation error for start with out-of-range index."""
    start_sec = section(8, encode_u32(10))
    wasm = make_wasm(start_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_bad_start_signature():
    """Test validation error for start function with bad signature."""
    # Type with params
    functype = b'\x60' + vec([b'\x7F']) + vec([])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0)]))
    start_sec = section(8, encode_u32(0))
    body = vec([]) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    # Sections must be in order: type(1), func(3), start(8), code(10)
    wasm = make_wasm(type_sec, func_sec, start_sec, code_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "bad_start_signature" for e in errors)


def test_validate_func_code_count_mismatch():
    """Test validation error for function/code count mismatch."""
    functype = b'\x60' + vec([]) + vec([])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0), encode_u32(0)]))  # 2 functions
    body = vec([]) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))  # 1 code

    wasm = make_wasm(type_sec, func_sec, code_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "func_code_count_mismatch" for e in errors)


def test_validate_local_index_out_of_range():
    """Test validation error for local.get with out-of-range index."""
    # Function with 1 param, no locals, accessing local 5
    functype = b'\x60' + vec([b'\x7F']) + vec([])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0)]))
    body = vec([]) + b'\x20' + encode_u32(5) + b'\x0B'  # local.get 5
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    wasm = make_wasm(type_sec, func_sec, code_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "local_index_out_of_range" for e in errors)


def test_validate_call_index_out_of_range():
    """Test validation error for call with out-of-range index."""
    functype = b'\x60' + vec([]) + vec([])
    type_sec = section(1, vec([functype]))
    func_sec = section(3, vec([encode_u32(0)]))
    body = vec([]) + b'\x10' + encode_u32(10) + b'\x0B'  # call 10
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    wasm = make_wasm(type_sec, func_sec, code_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_elem_index_out_of_range():
    """Test validation error for element with out-of-range funcidx."""
    elem = encode_u32(0) + b'\x41' + encode_s32(0) + b'\x0B' + vec([encode_u32(10)])
    elem_sec = section(9, vec([elem]))
    wasm = make_wasm(elem_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_data_count_mismatch():
    """Test validation error for data count mismatch."""
    data_seg = encode_u32(0) + b'\x41' + encode_s32(0) + b'\x0B' + name(b'x')
    data_sec = section(11, vec([data_seg]))
    data_count_sec = section(12, encode_u32(5))
    # Sections must be in order: data(11), data_count(12)
    wasm = make_wasm(data_sec, data_count_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "data_count_mismatch" for e in errors)


def test_validate_type_index_out_of_range():
    """Test validation error for typeidx out of range."""
    func_sec = section(3, vec([encode_u32(10)]))  # typeidx 10 doesn't exist
    body = vec([]) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))
    wasm = make_wasm(func_sec, code_sec)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "type_index_out_of_range" for e in errors)


# ----------------------------
# decode_and_validate tests
# ----------------------------

def test_decode_and_validate_success():
    """Test decode_and_validate with valid module."""
    wasm = make_wasm()
    module = decode_and_validate(wasm)
    assert module.raw_size == 8


def test_decode_and_validate_failure():
    """Test decode_and_validate with invalid module."""
    exp = name(b'foo') + b'\x00' + encode_u32(10)
    export_sec = section(7, vec([exp]))
    wasm = make_wasm(export_sec)
    with pytest.raises(ValueError) as exc:
        decode_and_validate(wasm)
    assert "validation failed" in str(exc.value).lower()


# ----------------------------
# Integration tests
# ----------------------------

def test_complete_module():
    """Test a complete module with multiple sections."""
    # Type section: [] -> [i32]
    functype = b'\x60' + vec([]) + vec([b'\x7F'])
    type_sec = section(1, vec([functype]))

    # Function section
    func_sec = section(3, vec([encode_u32(0)]))

    # Export section
    exp = name(b'get_value') + b'\x00' + encode_u32(0)
    export_sec = section(7, vec([exp]))

    # Code section: return i32.const 42
    body = vec([]) + b'\x41' + encode_s32(42) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    wasm = make_wasm(type_sec, func_sec, export_sec, code_sec)
    module = decode_and_validate(wasm)
    assert len(module.types) == 1
    assert len(module.function_typeidxs) == 1
    assert len(module.exports) == 1
    assert len(module.code) == 1


def test_module_with_imports():
    """Test module with imports and index space calculation."""
    # Type section
    functype = b'\x60' + vec([]) + vec([b'\x7F'])
    type_sec = section(1, vec([functype]))

    # Import 2 functions
    imp1 = name(b'env') + name(b'f1') + b'\x00' + encode_u32(0)
    imp2 = name(b'env') + name(b'f2') + b'\x00' + encode_u32(0)
    import_sec = section(2, vec([imp1, imp2]))

    # Define 1 function
    func_sec = section(3, vec([encode_u32(0)]))

    # Export function 1 (imported)
    exp = name(b'func') + b'\x00' + encode_u32(1)
    export_sec = section(7, vec([exp]))

    # Code for defined function
    body = vec([]) + b'\x41' + encode_s32(1) + b'\x0B'
    func_body = encode_u32(len(body)) + body
    code_sec = section(10, vec([func_body]))

    wasm = make_wasm(type_sec, import_sec, func_sec, export_sec, code_sec)
    module = decode_and_validate(wasm)
    assert len(module.imports) == 2
    assert len(module.function_typeidxs) == 1
    # Index space: funcs 0,1 are imported, func 2 is defined
    # Export references func 1 (imported), should be valid
