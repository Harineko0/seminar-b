"""
test.py - Comprehensive pytest test suite for wasm_sv parser and validator.
"""

import pytest
from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module, FuncType
)


# Helper to build minimal valid WASM bytes
def make_wasm(*sections):
    """Build a WASM module with magic+version and given section bytes."""
    return b'\x00asm\x01\x00\x00\x00' + b''.join(sections)


def make_section(section_id, payload):
    """Build a section with id and payload."""
    return bytes([section_id]) + encode_u32(len(payload)) + payload


def encode_u32(n):
    """Encode unsigned LEB128 u32."""
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n != 0:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def encode_s32(n):
    """Encode signed LEB128 s32."""
    result = []
    more = True
    while more:
        byte = n & 0x7F
        n >>= 7
        if (n == 0 and (byte & 0x40) == 0) or (n == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


def encode_vec(items):
    """Encode a vector."""
    return encode_u32(len(items)) + b''.join(items)


def encode_name(name):
    """Encode a name (byte string)."""
    if isinstance(name, str):
        name = name.encode('utf-8')
    return encode_u32(len(name)) + name


# ----------------------------
# Basic decoding tests
# ----------------------------

def test_minimal_module():
    """Test minimal valid module (magic + version only)."""
    wasm = make_wasm()
    module = decode_module(wasm)
    assert module.raw_size == 8
    assert len(module.types) == 0


def test_bad_magic():
    """Test invalid magic bytes."""
    wasm = b'\x00XXX\x01\x00\x00\x00'
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "bad_magic"


def test_bad_version():
    """Test invalid version."""
    wasm = b'\x00asm\x02\x00\x00\x00'
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "bad_version"


def test_module_size_limit():
    """Test module size exceeds limit."""
    wasm = b'\x00asm\x01\x00\x00\x00' + b'\x00' * 100
    with pytest.raises(DecodeError):
        decode_module(wasm, limits=Limits(max_module_bytes=10))


# ----------------------------
# LEB128 tests
# ----------------------------

def test_leb128_u32_valid():
    """Test valid LEB128 u32 decoding."""
    wasm = make_wasm(make_section(1, b'\x01\x60\x00\x00'))  # Type section with empty functype
    module = decode_module(wasm)
    assert len(module.types) == 1
    assert module.types[0].params == []
    assert module.types[0].results == []


def test_leb128_u32_overflow():
    """Test LEB128 u32 overflow."""
    # 6 bytes for u32 is too long
    wasm = make_wasm(make_section(1, b'\x80\x80\x80\x80\x80\x01'))
    with pytest.raises(DecodeError):
        decode_module(wasm)


# ----------------------------
# Section ordering tests
# ----------------------------

def test_section_order_violation():
    """Test sections out of order."""
    # Import (2) before Type (1)
    wasm = make_wasm(
        make_section(2, encode_vec([])),  # Import section
        make_section(1, encode_vec([]))   # Type section
    )
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "section_order"


def test_duplicate_section():
    """Test duplicate non-custom section."""
    wasm = make_wasm(
        make_section(1, encode_vec([])),
        make_section(1, encode_vec([]))
    )
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "section_order"


def test_custom_sections_anywhere():
    """Test custom sections can appear anywhere."""
    wasm = make_wasm(
        make_section(0, encode_name("pre") + b'data'),
        make_section(1, encode_vec([])),
        make_section(0, encode_name("mid") + b'data'),
        make_section(2, encode_vec([])),
        make_section(0, encode_name("post") + b'data')
    )
    module = decode_module(wasm)
    assert len(module.customs) == 3
    assert module.customs[0].name == b"pre"
    assert module.customs[1].name == b"mid"
    assert module.customs[2].name == b"post"


# ----------------------------
# Type section tests
# ----------------------------

def test_functype_basic():
    """Test basic function type."""
    payload = encode_vec([b'\x60' + encode_vec([b'\x7F', b'\x7E']) + encode_vec([b'\x7F'])])
    wasm = make_wasm(make_section(1, payload))
    module = decode_module(wasm)
    assert len(module.types) == 1
    assert module.types[0].params == [0x7F, 0x7E]  # i32, i64
    assert module.types[0].results == [0x7F]  # i32


def test_unsupported_valtype():
    """Test unsupported value type (f32)."""
    payload = encode_vec([b'\x60' + encode_vec([b'\x7D']) + encode_vec([])])  # f32
    wasm = make_wasm(make_section(1, payload))
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_valtype"


# ----------------------------
# Import section tests
# ----------------------------

def test_import_function():
    """Test function import."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    import_payload = encode_vec([
        encode_name("env") + encode_name("log") + b'\x00' + encode_u32(0)  # kind=func, typeidx=0
    ])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(2, import_payload)
    )
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].module == b"env"
    assert module.imports[0].name == b"log"
    assert module.imports[0].kind == 0
    assert module.imports[0].desc == 0


def test_import_table():
    """Test table import."""
    import_payload = encode_vec([
        encode_name("env") + encode_name("tbl") + b'\x01\x70\x00' + encode_u32(10)  # table, funcref, min=10
    ])
    wasm = make_wasm(make_section(2, import_payload))
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].kind == 1


def test_import_memory():
    """Test memory import."""
    import_payload = encode_vec([
        encode_name("env") + encode_name("mem") + b'\x02\x00' + encode_u32(1)  # mem, min=1
    ])
    wasm = make_wasm(make_section(2, import_payload))
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].kind == 2


def test_import_global():
    """Test global import."""
    import_payload = encode_vec([
        encode_name("env") + encode_name("g") + b'\x03\x7F\x00'  # global, i32, immutable
    ])
    wasm = make_wasm(make_section(2, import_payload))
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].kind == 3


# ----------------------------
# Function, Table, Memory, Global sections
# ----------------------------

def test_function_section():
    """Test function section."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0), encode_u32(0)])  # Two functions with typeidx=0
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload)
    )
    module = decode_module(wasm)
    assert len(module.function_types) == 2
    assert module.function_types[0] == 0
    assert module.function_types[1] == 0


def test_table_section():
    """Test table section."""
    table_payload = encode_vec([b'\x70\x00' + encode_u32(5)])  # funcref, min=5
    wasm = make_wasm(make_section(4, table_payload))
    module = decode_module(wasm)
    assert len(module.tables) == 1
    assert module.tables[0].limits.min == 5
    assert module.tables[0].limits.max is None


def test_memory_section():
    """Test memory section."""
    mem_payload = encode_vec([b'\x01' + encode_u32(1) + encode_u32(10)])  # min=1, max=10
    wasm = make_wasm(make_section(5, mem_payload))
    module = decode_module(wasm)
    assert len(module.memories) == 1
    assert module.memories[0].min == 1
    assert module.memories[0].max == 10


def test_global_section():
    """Test global section."""
    global_payload = encode_vec([b'\x7F\x00' + b'\x41\x2A' + b'\x0B'])  # i32, immutable, i32.const 42, end
    wasm = make_wasm(make_section(6, global_payload))
    module = decode_module(wasm)
    assert len(module.globals) == 1
    assert module.globals[0].type.valtype == 0x7F
    assert not module.globals[0].type.mutable


# ----------------------------
# Export section tests
# ----------------------------

def test_export_function():
    """Test function export."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    code_payload = encode_vec([encode_u32(2) + b'\x00\x0B'])  # body_size=2, no locals, end
    export_payload = encode_vec([encode_name("f") + b'\x00' + encode_u32(0)])  # kind=func, idx=0
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(7, export_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    assert len(module.exports) == 1
    assert module.exports[0].name == b"f"
    assert module.exports[0].kind == 0
    assert module.exports[0].index == 0


# ----------------------------
# Start section tests
# ----------------------------

def test_start_section():
    """Test start section."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    code_payload = encode_vec([encode_u32(2) + b'\x00\x0B'])
    start_payload = encode_u32(0)
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(8, start_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    assert module.start == 0


# ----------------------------
# Element section tests
# ----------------------------

def test_element_section():
    """Test element section."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    code_payload = encode_vec([encode_u32(2) + b'\x00\x0B'])
    elem_payload = encode_vec([
        encode_u32(0) +  # tableidx=0
        b'\x41\x00\x0B' +  # i32.const 0, end
        encode_vec([encode_u32(0)])  # init=[0]
    ])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(9, elem_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    assert len(module.elements) == 1
    assert module.elements[0].tableidx == 0
    assert module.elements[0].init == [0]


def test_element_unsupported_tableidx():
    """Test element with non-zero tableidx."""
    elem_payload = encode_vec([
        encode_u32(1) +  # tableidx=1 (unsupported)
        b'\x41\x00\x0B' +
        encode_vec([encode_u32(0)])
    ])
    wasm = make_wasm(make_section(9, elem_payload))
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_element_form"


# ----------------------------
# Code section tests
# ----------------------------

def test_code_section_basic():
    """Test basic code section."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    code_payload = encode_vec([
        encode_u32(2) + b'\x00\x0B'  # body_size=2, no locals, end
    ])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    assert len(module.code) == 1
    assert len(module.code[0].locals) == 0
    assert len(module.code[0].code.instructions) == 1  # just end


def test_code_with_locals():
    """Test code with local variables."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    # Build code body: locals vec + end
    code_body = encode_vec([encode_u32(2) + b'\x7F']) + b'\x0B'  # 2 i32 locals, end
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    assert len(module.code[0].locals) == 1
    assert module.code[0].locals[0].count == 2
    assert module.code[0].locals[0].valtype == 0x7F


def test_code_with_instructions():
    """Test code with various instructions."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    # i32.const 10, i32.const 20, i32.add, end
    code_body = b'\x00' + b'\x41\x0A\x41\x14\x6A\x0B'
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    instrs = module.code[0].code.instructions
    assert len(instrs) == 4  # const, const, add, end


def test_unsupported_opcode():
    """Test unsupported opcode."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    code_body = b'\x00' + b'\xFF\x0B'  # Invalid opcode 0xFF
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_opcode"


# ----------------------------
# Data section tests
# ----------------------------

def test_data_section():
    """Test data section."""
    data_payload = encode_vec([
        encode_u32(0) +  # memidx=0
        b'\x41\x00\x0B' +  # i32.const 0, end
        encode_name(b"hello")  # data bytes
    ])
    wasm = make_wasm(make_section(11, data_payload))
    module = decode_module(wasm)
    assert len(module.data) == 1
    assert module.data[0].memidx == 0
    assert module.data[0].data == b"hello"


def test_data_unsupported_memidx():
    """Test data with non-zero memidx."""
    data_payload = encode_vec([
        encode_u32(1) +  # memidx=1 (unsupported)
        b'\x41\x00\x0B' +
        encode_name(b"data")
    ])
    wasm = make_wasm(make_section(11, data_payload))
    with pytest.raises(DecodeError) as exc:
        decode_module(wasm)
    assert exc.value.code == "unsupported_data_form"


# ----------------------------
# Data count section tests
# ----------------------------

def test_data_count_section():
    """Test data count section."""
    data_payload = encode_vec([
        encode_u32(0) + b'\x41\x00\x0B' + encode_name(b"x")
    ])
    data_count_payload = encode_u32(1)
    wasm = make_wasm(
        make_section(11, data_payload),
        make_section(12, data_count_payload)
    )
    module = decode_module(wasm)
    assert module.data_count == 1


# ----------------------------
# Validation tests
# ----------------------------

def test_validate_limits_min_gt_max():
    """Test validation: limits min > max."""
    mem_payload = encode_vec([b'\x01' + encode_u32(10) + encode_u32(5)])  # min=10, max=5
    wasm = make_wasm(make_section(5, mem_payload))
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) == 1
    assert errors[0].code == "limits_min_gt_max"


def test_validate_duplicate_export_name():
    """Test validation: duplicate export names."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0), encode_u32(0)])
    code_payload = encode_vec([
        encode_u32(2) + b'\x00\x0B',
        encode_u32(2) + b'\x00\x0B'
    ])
    export_payload = encode_vec([
        encode_name("f") + b'\x00' + encode_u32(0),
        encode_name("f") + b'\x00' + encode_u32(1)  # Duplicate name
    ])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(7, export_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "duplicate_export_name" for e in errors)


def test_validate_export_index_out_of_range():
    """Test validation: export index out of range."""
    export_payload = encode_vec([
        encode_name("f") + b'\x00' + encode_u32(999)  # No such function
    ])
    wasm = make_wasm(make_section(7, export_payload))
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_start_index_out_of_range():
    """Test validation: start function index out of range."""
    start_payload = encode_u32(999)
    wasm = make_wasm(make_section(8, start_payload))
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_bad_start_signature():
    """Test validation: start function with wrong signature."""
    type_payload = encode_vec([b'\x60' + encode_vec([b'\x7F']) + encode_vec([])])  # [i32] -> []
    func_payload = encode_vec([encode_u32(0)])
    code_payload = encode_vec([encode_u32(2) + b'\x00\x0B'])
    start_payload = encode_u32(0)
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(8, start_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "bad_start_signature" for e in errors)


def test_validate_func_code_count_mismatch():
    """Test validation: function and code section count mismatch."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0), encode_u32(0)])  # 2 functions
    code_payload = encode_vec([encode_u32(2) + b'\x00\x0B'])  # 1 code body
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "func_code_count_mismatch" for e in errors)


def test_validate_local_index_out_of_range():
    """Test validation: local index out of range."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    # local.get 99, end (no such local)
    code_body = b'\x00' + b'\x20' + encode_u32(99) + b'\x0B'
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "local_index_out_of_range" for e in errors)


def test_validate_call_index_out_of_range():
    """Test validation: call function index out of range."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])
    # call 999, end
    code_body = b'\x00' + b'\x10' + encode_u32(999) + b'\x0B'
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])
    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


def test_validate_type_index_out_of_range():
    """Test validation: type index out of range."""
    func_payload = encode_vec([encode_u32(999)])  # No types defined
    code_payload = encode_vec([encode_u32(2) + b'\x00\x0B'])
    wasm = make_wasm(
        make_section(3, func_payload),
        make_section(10, code_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "type_index_out_of_range" for e in errors)


def test_validate_data_count_mismatch():
    """Test validation: data count mismatch."""
    data_payload = encode_vec([
        encode_u32(0) + b'\x41\x00\x0B' + encode_name(b"x")
    ])  # Actually 1
    data_count_payload = encode_u32(5)  # Says 5
    wasm = make_wasm(
        make_section(11, data_payload),
        make_section(12, data_count_payload)
    )
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "data_count_mismatch" for e in errors)


def test_validate_element_funcidx_out_of_range():
    """Test validation: element funcidx out of range."""
    elem_payload = encode_vec([
        encode_u32(0) +
        b'\x41\x00\x0B' +
        encode_vec([encode_u32(999)])  # No such function
    ])
    wasm = make_wasm(make_section(9, elem_payload))
    module = decode_module(wasm)
    errors = validate_module(module)
    assert any(e.code == "index_out_of_range" for e in errors)


# ----------------------------
# Integration tests
# ----------------------------

def test_decode_and_validate_success():
    """Test decode_and_validate with valid module."""
    wasm = make_wasm()
    module = decode_and_validate(wasm)
    assert module.raw_size == 8


def test_decode_and_validate_failure():
    """Test decode_and_validate with invalid module."""
    mem_payload = encode_vec([b'\x01' + encode_u32(10) + encode_u32(5)])  # min > max
    wasm = make_wasm(make_section(5, mem_payload))
    with pytest.raises(ValueError) as exc:
        decode_and_validate(wasm)
    assert "Validation failed" in str(exc.value)


def test_complex_module():
    """Test a more complex valid module."""
    # Type: [i32] -> [i32]
    type_payload = encode_vec([b'\x60' + encode_vec([b'\x7F']) + encode_vec([b'\x7F'])])

    # Function: one function with typeidx=0
    func_payload = encode_vec([encode_u32(0)])

    # Code: local.get 0, i32.const 1, i32.add, end
    code_body = b'\x00' + b'\x20\x00\x41\x01\x6A\x0B'
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])

    # Export: "inc"
    export_payload = encode_vec([encode_name("inc") + b'\x00' + encode_u32(0)])

    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(7, export_payload),
        make_section(10, code_payload)
    )

    module = decode_and_validate(wasm)
    assert len(module.types) == 1
    assert len(module.function_types) == 1
    assert len(module.code) == 1
    assert len(module.exports) == 1
    assert module.exports[0].name == b"inc"


def test_local_set_get():
    """Test local.set and local.get instructions."""
    # Type: [] -> []
    type_payload = encode_vec([b'\x60\x00\x00'])

    # Function with 1 local
    func_payload = encode_vec([encode_u32(0)])

    # Code: 1 i32 local, i32.const 42, local.set 0, local.get 0, end
    locals_decl = encode_vec([encode_u32(1) + b'\x7F'])
    code_instrs = b'\x41\x2A\x21\x00\x20\x00\x0B'
    code_body = locals_decl + code_instrs
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])

    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )

    module = decode_and_validate(wasm)
    assert len(module.code[0].locals) == 1
    # Should validate successfully (local index 0 is valid)
    errors = validate_module(module)
    assert len(errors) == 0


def test_call_instruction():
    """Test call instruction."""
    # Two functions, second calls first
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0), encode_u32(0)])

    # First function: just end
    code1 = b'\x00\x0B'

    # Second function: call 0, end
    code2 = b'\x00\x10\x00\x0B'

    code_payload = encode_vec([
        encode_u32(len(code1)) + code1,
        encode_u32(len(code2)) + code2
    ])

    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )

    module = decode_and_validate(wasm)
    assert len(module.code) == 2
    errors = validate_module(module)
    assert len(errors) == 0


def test_signed_i32_const():
    """Test negative i32.const values."""
    type_payload = encode_vec([b'\x60\x00\x00'])
    func_payload = encode_vec([encode_u32(0)])

    # i32.const -1, end
    code_body = b'\x00\x41' + encode_s32(-1) + b'\x0B'
    code_payload = encode_vec([encode_u32(len(code_body)) + code_body])

    wasm = make_wasm(
        make_section(1, type_payload),
        make_section(3, func_payload),
        make_section(10, code_payload)
    )

    module = decode_and_validate(wasm)
    # Should decode -1 correctly
    assert len(module.code[0].code.instructions) == 2


def test_limits_enforcement():
    """Test resource limits enforcement."""
    # Create a module with too many types
    large_type_vec = encode_vec([b'\x60\x00\x00'] * 100)
    wasm = make_wasm(make_section(1, large_type_vec))

    # Should fail with small vector limit
    with pytest.raises(DecodeError):
        decode_module(wasm, limits=Limits(max_vector_length=10))


def test_section_size_mismatch():
    """Test section payload size mismatch."""
    # Section claims 10 bytes but only provides 5
    wasm = b'\x00asm\x01\x00\x00\x00' + bytes([1, 10]) + b'\x00' * 5
    with pytest.raises(DecodeError):
        decode_module(wasm)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
