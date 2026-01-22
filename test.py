"""
Comprehensive test suite for wasm_sv parser and validator.
"""

import pytest
from parser import (
    decode_module,
    validate_module,
    decode_and_validate,
    DecodeError,
    ValidationError,
    Limits,
    Module,
    FuncType,
    ValType,
    I32Const,
    End,
)


# ----------------------------
# Helper functions
# ----------------------------

def make_wasm(sections: bytes = b"") -> bytes:
    """Create a WASM module with magic + version + sections."""
    return b"\x00asm\x01\x00\x00\x00" + sections


def leb128_u32(n: int) -> bytes:
    """Encode unsigned integer as LEB128."""
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n == 0:
            result.append(byte)
            break
        else:
            result.append(byte | 0x80)
    return bytes(result)


def leb128_s32(n: int) -> bytes:
    """Encode signed integer as LEB128."""
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if (n == 0 and (byte & 0x40) == 0) or (n == -1 and (byte & 0x40) != 0):
            result.append(byte)
            break
        else:
            result.append(byte | 0x80)
    return bytes(result)


def make_section(section_id: int, payload: bytes) -> bytes:
    """Create a section with id and payload."""
    return bytes([section_id]) + leb128_u32(len(payload)) + payload


def make_vec(items: list) -> bytes:
    """Create a vector (count + items)."""
    return leb128_u32(len(items)) + b"".join(items)


def make_name(s: str) -> bytes:
    """Create a name (length + bytes)."""
    b = s.encode("utf-8")
    return leb128_u32(len(b)) + b


# ----------------------------
# Basic decoding tests
# ----------------------------

def test_minimal_module():
    """Test minimal valid module (just magic + version)."""
    data = make_wasm()
    module = decode_module(data)
    assert module.raw_size == 8
    assert len(module.types) == 0


def test_invalid_magic():
    """Test that invalid magic raises DecodeError."""
    with pytest.raises(DecodeError) as exc_info:
        decode_module(b"\x01asm\x01\x00\x00\x00")
    assert exc_info.value.code == "bad_magic"


def test_invalid_version():
    """Test that invalid version raises DecodeError."""
    with pytest.raises(DecodeError) as exc_info:
        decode_module(b"\x00asm\x02\x00\x00\x00")
    assert exc_info.value.code == "bad_version"


def test_truncated_module():
    """Test that truncated module raises DecodeError."""
    with pytest.raises(DecodeError) as exc_info:
        decode_module(b"\x00asm\x01")
    assert exc_info.value.code == "truncated"


# ----------------------------
# Type section tests
# ----------------------------

def test_type_section():
    """Test type section with function types."""
    # One functype: [] -> []
    functype1 = b"\x60\x00\x00"
    # Another functype: [i32, i64] -> [i32]
    functype2 = b"\x60" + make_vec([b"\x7F", b"\x7E"]) + make_vec([b"\x7F"])

    payload = make_vec([functype1, functype2])
    data = make_wasm(make_section(1, payload))

    module = decode_module(data)
    assert len(module.types) == 2
    assert module.types[0].params == []
    assert module.types[0].results == []
    assert module.types[1].params == [ValType.I32, ValType.I64]
    assert module.types[1].results == [ValType.I32]


def test_unsupported_valtype():
    """Test that unsupported valtypes raise DecodeError."""
    # functype with f32
    functype = b"\x60\x00" + make_vec([b"\x7D"])  # 0x7D = f32
    payload = make_vec([functype])
    data = make_wasm(make_section(1, payload))

    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "unsupported_valtype"


def test_bad_functype_tag():
    """Test that bad functype tag raises DecodeError."""
    functype = b"\x61\x00\x00"  # Wrong tag
    payload = make_vec([functype])
    data = make_wasm(make_section(1, payload))

    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "bad_functype_tag"


# ----------------------------
# Import section tests
# ----------------------------

def test_import_func():
    """Test function import."""
    # Type section first
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Import: "env"."foo" func typeidx=0
    import_entry = make_name("env") + make_name("foo") + b"\x00" + leb128_u32(0)
    import_section = make_section(2, make_vec([import_entry]))

    data = make_wasm(type_section + import_section)
    module = decode_module(data)

    assert len(module.imports) == 1
    assert module.imports[0].module == b"env"
    assert module.imports[0].name == b"foo"


def test_import_table():
    """Test table import."""
    # Import: "env"."table" table funcref (min=1, max=10)
    import_entry = make_name("env") + make_name("table") + b"\x01" + b"\x70" + b"\x01" + leb128_u32(1) + leb128_u32(10)
    import_section = make_section(2, make_vec([import_entry]))

    data = make_wasm(import_section)
    module = decode_module(data)

    assert len(module.imports) == 1


def test_import_memory():
    """Test memory import."""
    # Import: "env"."mem" memory (min=1)
    import_entry = make_name("env") + make_name("mem") + b"\x02" + b"\x00" + leb128_u32(1)
    import_section = make_section(2, make_vec([import_entry]))

    data = make_wasm(import_section)
    module = decode_module(data)

    assert len(module.imports) == 1


def test_import_global():
    """Test global import."""
    # Import: "env"."g" global i32 immutable
    import_entry = make_name("env") + make_name("g") + b"\x03" + b"\x7F\x00"
    import_section = make_section(2, make_vec([import_entry]))

    data = make_wasm(import_section)
    module = decode_module(data)

    assert len(module.imports) == 1


def test_unsupported_table_elemtype():
    """Test that non-funcref table elemtype raises DecodeError."""
    # Import table with wrong elemtype
    import_entry = make_name("env") + make_name("table") + b"\x01" + b"\x6F" + b"\x00" + leb128_u32(1)
    import_section = make_section(2, make_vec([import_entry]))

    data = make_wasm(import_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "unsupported_table_elemtype"


def test_bad_mutability():
    """Test that bad mutability raises DecodeError."""
    # Import global with bad mutability
    import_entry = make_name("env") + make_name("g") + b"\x03" + b"\x7F\x02"  # 0x02 is invalid
    import_section = make_section(2, make_vec([import_entry]))

    data = make_wasm(import_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "bad_mutability"


# ----------------------------
# Function section tests
# ----------------------------

def test_function_section():
    """Test function section."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section - 2 functions with typeidx=0
    func_section = make_section(3, make_vec([leb128_u32(0), leb128_u32(0)]))

    data = make_wasm(type_section + func_section)
    module = decode_module(data)

    assert len(module.funcs) == 2
    assert module.funcs[0] == 0
    assert module.funcs[1] == 0


# ----------------------------
# Code section tests
# ----------------------------

def test_code_section():
    """Test code section with function bodies."""
    # Type section: [] -> []
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section: 1 function with typeidx=0
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section: 1 function body with no locals and just 'end'
    func_body = leb128_u32(0) + b"\x0B"  # 0 locals, end
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)

    assert len(module.code) == 1
    assert len(module.code[0].locals) == 0
    assert len(module.code[0].expr.instrs) == 1
    assert isinstance(module.code[0].expr.instrs[0], End)


def test_code_with_locals():
    """Test code section with local variables."""
    # Type section: [] -> []
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section with locals: 2 i32, 1 i64
    locals_vec = make_vec([
        leb128_u32(2) + b"\x7F",  # 2 x i32
        leb128_u32(1) + b"\x7E",  # 1 x i64
    ])
    func_body = locals_vec + b"\x0B"  # end
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)

    assert len(module.code[0].locals) == 2
    assert module.code[0].locals[0].count == 2
    assert module.code[0].locals[0].valtype == ValType.I32
    assert module.code[0].locals[1].count == 1
    assert module.code[0].locals[1].valtype == ValType.I64


def test_code_with_instructions():
    """Test code section with various instructions."""
    # Type section: [i32] -> [i32]
    functype = b"\x60" + make_vec([b"\x7F"]) + make_vec([b"\x7F"])
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code: i32.const 42, local.get 0, i32.add, end
    code_instrs = (
        b"\x41" + leb128_s32(42) +  # i32.const 42
        b"\x20" + leb128_u32(0) +   # local.get 0
        b"\x6A" +                   # i32.add
        b"\x0B"                     # end
    )
    func_body = leb128_u32(0) + code_instrs  # 0 locals
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)

    assert len(module.code[0].expr.instrs) == 4
    assert isinstance(module.code[0].expr.instrs[0], I32Const)
    assert module.code[0].expr.instrs[0].value == 42


def test_unsupported_opcode():
    """Test that unsupported opcodes raise DecodeError."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code with unsupported opcode (e.g., 0x1A = drop)
    code_instrs = b"\x1A\x0B"  # drop, end
    func_body = leb128_u32(0) + code_instrs
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "unsupported_opcode"


# ----------------------------
# Export section tests
# ----------------------------

def test_export_section():
    """Test export section."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    # Export section: export func 0 as "main"
    export_entry = make_name("main") + b"\x00" + leb128_u32(0)
    export_section = make_section(7, make_vec([export_entry]))

    data = make_wasm(type_section + func_section + export_section + code_section)
    module = decode_module(data)

    assert len(module.exports) == 1
    assert module.exports[0].name == b"main"
    assert module.exports[0].kind == 0
    assert module.exports[0].index == 0


# ----------------------------
# Start section tests
# ----------------------------

def test_start_section():
    """Test start section."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    # Start section: start func 0
    start_section = make_section(8, leb128_u32(0))

    data = make_wasm(type_section + func_section + start_section + code_section)
    module = decode_module(data)

    assert module.start == 0


# ----------------------------
# Element section tests
# ----------------------------

def test_element_section():
    """Test element section."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    # Element section: tableidx=0, offset=i32.const 0, init=[0]
    elem_entry = (
        leb128_u32(0) +             # tableidx
        b"\x41" + leb128_s32(0) + b"\x0B" +  # i32.const 0, end
        make_vec([leb128_u32(0)])   # init funcidx
    )
    elem_section = make_section(9, make_vec([elem_entry]))

    data = make_wasm(type_section + func_section + elem_section + code_section)
    module = decode_module(data)

    assert len(module.elems) == 1
    assert module.elems[0].tableidx == 0
    assert len(module.elems[0].init) == 1
    assert module.elems[0].init[0] == 0


def test_element_unsupported_form():
    """Test that unsupported element forms raise DecodeError."""
    # Element with tableidx != 0
    elem_entry = leb128_u32(1) + b"\x41\x00\x0B" + make_vec([leb128_u32(0)])
    elem_section = make_section(9, make_vec([elem_entry]))

    data = make_wasm(elem_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "unsupported_element_form"


# ----------------------------
# Data section tests
# ----------------------------

def test_data_section():
    """Test data section."""
    # Data segment: memidx=0, offset=i32.const 0, data="hello"
    data_bytes = b"hello"
    data_entry = (
        leb128_u32(0) +                      # memidx
        b"\x41" + leb128_s32(0) + b"\x0B" +  # i32.const 0, end
        leb128_u32(len(data_bytes)) + data_bytes
    )
    data_section = make_section(11, make_vec([data_entry]))

    wasm = make_wasm(data_section)
    module = decode_module(wasm)

    assert len(module.datas) == 1
    assert module.datas[0].memidx == 0
    assert module.datas[0].data == b"hello"


def test_data_unsupported_form():
    """Test that unsupported data forms raise DecodeError."""
    # Data with memidx != 0
    data_entry = leb128_u32(1) + b"\x41\x00\x0B" + leb128_u32(5) + b"hello"
    data_section = make_section(11, make_vec([data_entry]))

    data = make_wasm(data_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "unsupported_data_form"


# ----------------------------
# Data count section tests
# ----------------------------

def test_datacount_section():
    """Test data count section."""
    # Data count
    datacount_section = make_section(12, leb128_u32(0))

    data = make_wasm(datacount_section)
    module = decode_module(data)

    assert module.datacount == 0


# ----------------------------
# Section ordering tests
# ----------------------------

def test_section_order_violation():
    """Test that out-of-order sections raise DecodeError."""
    # Function section (3) before type section (1)
    func_section = make_section(3, make_vec([leb128_u32(0)]))
    type_section = make_section(1, make_vec([b"\x60\x00\x00"]))

    data = make_wasm(func_section + type_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "section_order"


def test_duplicate_section():
    """Test that duplicate sections raise DecodeError."""
    type_section = make_section(1, make_vec([b"\x60\x00\x00"]))

    data = make_wasm(type_section + type_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "section_order"


def test_custom_sections_anywhere():
    """Test that custom sections can appear anywhere."""
    custom1 = make_section(0, b"custom1")
    type_section = make_section(1, make_vec([b"\x60\x00\x00"]))
    custom2 = make_section(0, b"custom2")

    data = make_wasm(custom1 + type_section + custom2)
    module = decode_module(data)

    assert len(module.customs) == 2


def test_unknown_section_id():
    """Test that unknown section IDs raise DecodeError."""
    unknown_section = make_section(99, b"data")

    data = make_wasm(unknown_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "unknown_section_id"


# ----------------------------
# Validation tests
# ----------------------------

def test_validate_limits_min_gt_max():
    """Test validation of limits where min > max."""
    # Table with min > max
    table_entry = b"\x70\x01" + leb128_u32(10) + leb128_u32(5)
    table_section = make_section(4, make_vec([table_entry]))

    data = make_wasm(table_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert len(errors) == 1
    assert errors[0].code == "limits_min_gt_max"


def test_validate_duplicate_export_name():
    """Test validation of duplicate export names."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section with 2 functions
    func_section = make_section(3, make_vec([leb128_u32(0), leb128_u32(0)]))

    # Code section with 2 function bodies
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload, code_payload]))

    # Export section with duplicate names
    export1 = make_name("foo") + b"\x00" + leb128_u32(0)
    export2 = make_name("foo") + b"\x00" + leb128_u32(1)
    export_section = make_section(7, make_vec([export1, export2]))

    data = make_wasm(type_section + func_section + export_section + code_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "duplicate_export_name" for e in errors)


def test_validate_export_index_out_of_range():
    """Test validation of export with out-of-range index."""
    # Export func index 0 but no functions
    export_entry = make_name("foo") + b"\x00" + leb128_u32(0)
    export_section = make_section(7, make_vec([export_entry]))

    data = make_wasm(export_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_start_index_out_of_range():
    """Test validation of start function with out-of-range index."""
    # Start func index 0 but no functions
    start_section = make_section(8, leb128_u32(0))

    data = make_wasm(start_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_bad_start_signature():
    """Test validation of start function with bad signature."""
    # Type section with [i32] -> []
    functype = b"\x60" + make_vec([b"\x7F"]) + make_vec([])
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    # Start section
    start_section = make_section(8, leb128_u32(0))

    data = make_wasm(type_section + func_section + start_section + code_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "bad_start_signature" for e in errors)


def test_validate_func_code_count_mismatch():
    """Test validation of function/code count mismatch."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section with 2 functions
    func_section = make_section(3, make_vec([leb128_u32(0), leb128_u32(0)]))

    # Code section with only 1 function body
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "func_code_count_mismatch" for e in errors)


def test_validate_local_index_out_of_range():
    """Test validation of local index out of range."""
    # Type section: [] -> []
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section with local.get 0 (but no locals/params)
    code_instrs = b"\x20" + leb128_u32(0) + b"\x0B"  # local.get 0, end
    func_body = leb128_u32(0) + code_instrs
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "local_index_out_of_range" for e in errors)


def test_validate_call_index_out_of_range():
    """Test validation of call index out of range."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code section with call 5 (but only 1 function)
    code_instrs = b"\x10" + leb128_u32(5) + b"\x0B"  # call 5, end
    func_body = leb128_u32(0) + code_instrs
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_type_index_out_of_range():
    """Test validation of type index out of range."""
    # Function section with typeidx=5 but no types
    func_section = make_section(3, make_vec([leb128_u32(5)]))

    # Code section
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(func_section + code_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "type_index_out_of_range" for e in errors)


def test_validate_data_count_mismatch():
    """Test validation of data count mismatch."""
    # Data section has 0 segments
    data_section = make_section(11, make_vec([]))

    # Data count says 2
    datacount_section = make_section(12, leb128_u32(2))

    data = make_wasm(data_section + datacount_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "data_count_mismatch" for e in errors)


def test_validate_element_funcidx_out_of_range():
    """Test validation of element funcidx out of range."""
    # Element with funcidx=5 but no functions
    elem_entry = (
        leb128_u32(0) +
        b"\x41" + leb128_s32(0) + b"\x0B" +
        make_vec([leb128_u32(5)])
    )
    elem_section = make_section(9, make_vec([elem_entry]))

    data = make_wasm(elem_section)
    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "index_out_of_range" for e in errors)


# ----------------------------
# Limits tests
# ----------------------------

def test_module_size_limit():
    """Test that module size limit is enforced."""
    data = make_wasm(b"\x00" * 100)

    with pytest.raises(DecodeError) as exc_info:
        decode_module(data, limits=Limits(max_module_bytes=10))
    assert exc_info.value.code == "module_size_limit"


def test_vector_length_limit():
    """Test that vector length limit is enforced."""
    # Type section with huge count
    payload = leb128_u32(100000) + b""
    type_section = make_section(1, payload)

    data = make_wasm(type_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data, limits=Limits(max_vector_length=100))
    assert exc_info.value.code == "vector_length_limit"


# ----------------------------
# LEB128 tests
# ----------------------------

def test_leb128_overflow():
    """Test that overlong LEB128 raises DecodeError."""
    # 6-byte LEB128 for u32 (too long)
    bad_leb = b"\x80\x80\x80\x80\x80\x01"
    payload = bad_leb  # Will fail reading count
    type_section = make_section(1, payload)

    data = make_wasm(type_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert "leb128" in exc_info.value.code.lower()


# ----------------------------
# Integration tests
# ----------------------------

def test_complete_module():
    """Test a complete module with multiple sections."""
    # Type section: [i32] -> [i32]
    functype = b"\x60" + make_vec([b"\x7F"]) + make_vec([b"\x7F"])
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Export section
    export_entry = make_name("add_one") + b"\x00" + leb128_u32(0)
    export_section = make_section(7, make_vec([export_entry]))

    # Code section: local.get 0, i32.const 1, i32.add, end
    code_instrs = (
        b"\x20" + leb128_u32(0) +
        b"\x41" + leb128_s32(1) +
        b"\x6A" +
        b"\x0B"
    )
    func_body = leb128_u32(0) + code_instrs
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + export_section + code_section)
    module = decode_and_validate(data)

    assert module.raw_size == len(data)
    assert len(module.types) == 1
    assert len(module.funcs) == 1
    assert len(module.exports) == 1
    assert len(module.code) == 1


def test_decode_and_validate_raises_on_error():
    """Test that decode_and_validate raises on validation errors."""
    # Export with out-of-range index
    export_entry = make_name("foo") + b"\x00" + leb128_u32(0)
    export_section = make_section(7, make_vec([export_entry]))

    data = make_wasm(export_section)

    with pytest.raises(ValueError) as exc_info:
        decode_and_validate(data)
    assert "Validation failed" in str(exc_info.value)


# ----------------------------
# Edge case tests
# ----------------------------

def test_negative_i32_const():
    """Test that negative i32.const values are decoded correctly."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code with i32.const -1
    code_instrs = b"\x41" + leb128_s32(-1) + b"\x0B"
    func_body = leb128_u32(0) + code_instrs
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)

    assert isinstance(module.code[0].expr.instrs[0], I32Const)
    assert module.code[0].expr.instrs[0].value == -1


def test_large_positive_i32_const():
    """Test large positive i32.const values."""
    # Type section
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Function section
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Code with i32.const 2147483647 (max i32)
    code_instrs = b"\x41" + leb128_s32(2147483647) + b"\x0B"
    func_body = leb128_u32(0) + code_instrs
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + func_section + code_section)
    module = decode_module(data)

    assert isinstance(module.code[0].expr.instrs[0], I32Const)
    assert module.code[0].expr.instrs[0].value == 2147483647


def test_section_size_mismatch():
    """Test that section size mismatch is detected."""
    # Declare section payload as 10 bytes but only provide 5
    section_id = 1
    declared_len = 10
    actual_payload = b"\x00\x00\x00\x00\x00"

    data = make_wasm(bytes([section_id]) + leb128_u32(declared_len) + actual_payload)

    with pytest.raises(DecodeError) as exc_info:
        decode_module(data)
    assert exc_info.value.code == "truncated"


def test_import_then_defined_functions():
    """Test that import and defined function indices work correctly."""
    # Type section: [] -> []
    functype = b"\x60\x00\x00"
    type_section = make_section(1, make_vec([functype]))

    # Import 2 functions
    import1 = make_name("env") + make_name("f1") + b"\x00" + leb128_u32(0)
    import2 = make_name("env") + make_name("f2") + b"\x00" + leb128_u32(0)
    import_section = make_section(2, make_vec([import1, import2]))

    # Define 1 function
    func_section = make_section(3, make_vec([leb128_u32(0)]))

    # Export function 2 (the defined one)
    export_entry = make_name("foo") + b"\x00" + leb128_u32(2)
    export_section = make_section(7, make_vec([export_entry]))

    # Code section
    func_body = leb128_u32(0) + b"\x0B"
    code_payload = leb128_u32(len(func_body)) + func_body
    code_section = make_section(10, make_vec([code_payload]))

    data = make_wasm(type_section + import_section + func_section + export_section + code_section)
    module = decode_and_validate(data)

    assert len(module.imports) == 2
    assert len(module.funcs) == 1
    assert len(module.exports) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
