"""
Unit tests for WASM binary module parser and validator.
"""

import pytest
from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, ValType
)


# ===== Helper Functions =====

def make_wasm(*sections):
    """Construct a WASM module with magic + version + sections."""
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


def make_section(section_id: int, payload: bytes) -> bytes:
    """Construct a section with id and payload."""
    size = encode_u32(len(payload))
    return bytes([section_id]) + size + payload


def encode_u32(n: int) -> bytes:
    """Encode unsigned 32-bit as LEB128."""
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


def encode_s32(n: int) -> bytes:
    """Encode signed 32-bit as LEB128."""
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


def encode_vector(items: list) -> bytes:
    """Encode a vector (count + items)."""
    return encode_u32(len(items)) + b"".join(items)


def encode_name(name: str) -> bytes:
    """Encode a UTF-8 name."""
    name_bytes = name.encode('utf-8')
    return encode_u32(len(name_bytes)) + name_bytes


# ===== Basic Tests =====

def test_minimal_module():
    """Test minimal valid WASM module (just magic + version)."""
    wasm = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(wasm)
    assert module is not None
    assert len(module.types) == 0
    assert len(module.function_type_indices) == 0


def test_invalid_magic():
    """Test module with invalid magic number."""
    wasm = b"\x00bad\x01\x00\x00\x00"
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert "magic" in str(exc_info.value).lower()


def test_invalid_version():
    """Test module with invalid version."""
    wasm = b"\x00asm\x02\x00\x00\x00"
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert "version" in str(exc_info.value).lower()


def test_truncated_magic():
    """Test truncated magic number."""
    wasm = b"\x00as"
    with pytest.raises(DecodeError):
        decode_module(wasm)


# ===== Type Section Tests =====

def test_type_section_empty():
    """Test type section with no types."""
    type_section = make_section(1, encode_vector([]))
    wasm = make_wasm(type_section)
    module = decode_module(wasm)
    assert len(module.types) == 0


def test_type_section_single_functype():
    """Test type section with one function type."""
    # func type: 0x60, params: [i32], results: [i32]
    functype = b"\x60" + encode_vector([b"\x7f"]) + encode_vector([b"\x7f"])
    type_section = make_section(1, encode_vector([functype]))
    wasm = make_wasm(type_section)
    module = decode_module(wasm)
    assert len(module.types) == 1
    assert len(module.types[0].params) == 1
    assert module.types[0].params[0] == ValType.I32
    assert len(module.types[0].results) == 1
    assert module.types[0].results[0] == ValType.I32


def test_type_section_invalid_tag():
    """Test type section with invalid function type tag."""
    # Invalid tag 0x61 instead of 0x60
    functype = b"\x61" + encode_vector([b"\x7f"]) + encode_vector([b"\x7f"])
    type_section = make_section(1, encode_vector([functype]))
    wasm = make_wasm(type_section)
    with pytest.raises(DecodeError):
        decode_module(wasm)


def test_unsupported_valtype():
    """Test unsupported value type (f32)."""
    # func type with f32 (0x7D) which is not supported
    functype = b"\x60" + encode_vector([b"\x7d"]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))
    wasm = make_wasm(type_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert exc_info.value.code == "unsupported_valtype"


# ===== Function Section Tests =====

def test_function_section():
    """Test function section with type indices."""
    # Type section with one type
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function section with one function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    wasm = make_wasm(type_section, func_section)
    module = decode_module(wasm)
    assert len(module.function_type_indices) == 1
    assert module.function_type_indices[0] == 0


# ===== Code Section Tests =====

def test_code_section_simple():
    """Test code section with simple function."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: no locals, just 'end'
    func_body = encode_vector([]) + b"\x0b"  # empty locals, end
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm)
    assert len(module.code) == 1
    assert len(module.code[0].locals) == 0
    assert len(module.code[0].expr.instructions) == 1


def test_code_section_with_locals():
    """Test code section with local declarations."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: 2 i32 locals, just 'end'
    locals_decl = encode_u32(2) + b"\x7f"  # count=2, type=i32
    func_body = encode_vector([locals_decl]) + b"\x0b"  # locals, end
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm)
    assert len(module.code) == 1
    assert len(module.code[0].locals) == 1
    assert module.code[0].locals[0].count == 2
    assert module.code[0].locals[0].valtype == ValType.I32


def test_code_section_with_i32_const():
    """Test code section with i32.const instruction."""
    # Type: [] -> [i32]
    functype = b"\x60" + encode_vector([]) + encode_vector([b"\x7f"])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: no locals, i32.const 42, end
    func_body = encode_vector([]) + b"\x41" + encode_s32(42) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm)
    assert len(module.code[0].expr.instructions) == 2
    assert module.code[0].expr.instructions[0].opcode == 0x41
    assert module.code[0].expr.instructions[0].immediate == 42


def test_unsupported_opcode():
    """Test unsupported opcode."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: no locals, unsupported opcode 0xFF, end
    func_body = encode_vector([]) + b"\xFF" + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert exc_info.value.code == "unsupported_opcode"


def test_missing_end_opcode():
    """Test missing end opcode in expression."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: no locals, i32.const 42, but no end (body size says it ends)
    func_body = encode_vector([]) + b"\x41" + encode_s32(42)
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert exc_info.value.code == "missing_end"


# ===== Export Section Tests =====

def test_export_section():
    """Test export section."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    # Export "test" as function 0
    export = encode_name("test") + b"\x00" + encode_u32(0)
    export_section = make_section(7, encode_vector([export]))

    wasm = make_wasm(type_section, func_section, export_section, code_section)
    module = decode_module(wasm)
    assert len(module.exports) == 1
    assert module.exports[0].name == b"test"
    assert module.exports[0].index == 0


def test_export_duplicate_names():
    """Test validation catches duplicate export names."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Two functions
    func_section = make_section(3, encode_vector([encode_u32(0), encode_u32(0)]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([
        encode_u32(len(func_body)) + func_body,
        encode_u32(len(func_body)) + func_body
    ]))

    # Export both functions with same name
    export1 = encode_name("test") + b"\x00" + encode_u32(0)
    export2 = encode_name("test") + b"\x00" + encode_u32(1)
    export_section = make_section(7, encode_vector([export1, export2]))

    wasm = make_wasm(type_section, func_section, export_section, code_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "duplicate_export_name" for e in errors)


def test_export_index_out_of_range():
    """Test validation catches export index out of range."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # One function
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    # Export function with index 5 (out of range)
    export = encode_name("test") + b"\x00" + encode_u32(5)
    export_section = make_section(7, encode_vector([export]))

    wasm = make_wasm(type_section, func_section, export_section, code_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "index_out_of_range" for e in errors)


# ===== Import Section Tests =====

def test_import_function():
    """Test import section with function import."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Import function
    import_entry = encode_name("env") + encode_name("log") + b"\x00" + encode_u32(0)
    import_section = make_section(2, encode_vector([import_entry]))

    wasm = make_wasm(type_section, import_section)
    module = decode_module(wasm)
    assert len(module.imports) == 1
    assert module.imports[0].module == b"env"
    assert module.imports[0].name == b"log"


def test_import_with_invalid_typeidx():
    """Test import with invalid type index."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Import function with invalid type index 5
    import_entry = encode_name("env") + encode_name("log") + b"\x00" + encode_u32(5)
    import_section = make_section(2, encode_vector([import_entry]))

    wasm = make_wasm(type_section, import_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "type_index_out_of_range" for e in errors)


# ===== Memory Section Tests =====

def test_memory_section():
    """Test memory section."""
    # Memory with min=1, no max
    memory = b"\x00" + encode_u32(1)
    memory_section = make_section(5, encode_vector([memory]))

    wasm = make_wasm(memory_section)
    module = decode_module(wasm)
    assert len(module.memories) == 1
    assert module.memories[0].min == 1
    assert module.memories[0].max is None


def test_memory_with_max():
    """Test memory with max limit."""
    # Memory with min=1, max=10
    memory = b"\x01" + encode_u32(1) + encode_u32(10)
    memory_section = make_section(5, encode_vector([memory]))

    wasm = make_wasm(memory_section)
    module = decode_module(wasm)
    assert len(module.memories) == 1
    assert module.memories[0].min == 1
    assert module.memories[0].max == 10


def test_memory_invalid_limits():
    """Test validation catches min > max."""
    # Memory with min=10, max=1 (invalid)
    memory = b"\x01" + encode_u32(10) + encode_u32(1)
    memory_section = make_section(5, encode_vector([memory]))

    wasm = make_wasm(memory_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "limits_min_gt_max" for e in errors)


# ===== Table Section Tests =====

def test_table_section():
    """Test table section."""
    # Table: funcref, min=0, no max
    table = b"\x70\x00" + encode_u32(0)
    table_section = make_section(4, encode_vector([table]))

    wasm = make_wasm(table_section)
    module = decode_module(wasm)
    assert len(module.tables) == 1
    assert module.tables[0].min == 0


def test_table_invalid_elemtype():
    """Test table with invalid element type."""
    # Table with invalid elemtype 0x7F instead of 0x70
    table = b"\x7F\x00" + encode_u32(0)
    table_section = make_section(4, encode_vector([table]))

    wasm = make_wasm(table_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert exc_info.value.code == "unsupported_table_elemtype"


# ===== Global Section Tests =====

def test_global_section():
    """Test global section."""
    # Global: i32, immutable, init=i32.const 0
    global_entry = b"\x7f\x00" + b"\x41" + encode_s32(0) + b"\x0b"
    global_section = make_section(6, encode_vector([global_entry]))

    wasm = make_wasm(global_section)
    module = decode_module(wasm)
    assert len(module.globals) == 1
    assert module.globals[0].globaltype.valtype == ValType.I32
    assert not module.globals[0].globaltype.mutable


def test_global_mutable():
    """Test mutable global."""
    # Global: i64, mutable, init=i32.const 0 (actually should be i64.const for i64 global, but we test i32.const)
    global_entry = b"\x7e\x01" + b"\x41" + encode_s32(0) + b"\x0b"
    global_section = make_section(6, encode_vector([global_entry]))

    wasm = make_wasm(global_section)
    module = decode_module(wasm)
    assert len(module.globals) == 1
    assert module.globals[0].globaltype.valtype == ValType.I64
    assert module.globals[0].globaltype.mutable


# ===== Start Section Tests =====

def test_start_section():
    """Test start section."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    # Start section pointing to function 0
    start_section = make_section(8, encode_u32(0))

    wasm = make_wasm(type_section, func_section, start_section, code_section)
    module = decode_module(wasm)
    assert module.start == 0
    errors = validate_module(module)
    assert len(errors) == 0


def test_start_invalid_signature():
    """Test validation catches start function with wrong signature."""
    # Type: [i32] -> [] (invalid for start function)
    functype = b"\x60" + encode_vector([b"\x7f"]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    # Start section pointing to function 0
    start_section = make_section(8, encode_u32(0))

    wasm = make_wasm(type_section, func_section, start_section, code_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "bad_start_signature" for e in errors)


# ===== Element Section Tests =====

def test_element_section():
    """Test element section."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Table section
    table = b"\x70\x00" + encode_u32(10)
    table_section = make_section(4, encode_vector([table]))

    # Element section: tableidx=0, offset=i32.const 0, init=[0]
    elem_segment = encode_u32(0) + b"\x41" + encode_s32(0) + b"\x0b" + encode_vector([encode_u32(0)])
    element_section = make_section(9, encode_vector([elem_segment]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, table_section, element_section, code_section)
    module = decode_module(wasm)
    assert len(module.elements) == 1
    assert module.elements[0].tableidx == 0
    assert module.elements[0].offset == 0
    assert module.elements[0].init == [0]


# ===== Data Section Tests =====

def test_data_section():
    """Test data section."""
    # Memory section
    memory = b"\x00" + encode_u32(1)
    memory_section = make_section(5, encode_vector([memory]))

    # Data section: memidx=0, offset=i32.const 0, data="hello"
    data_segment = encode_u32(0) + b"\x41" + encode_s32(0) + b"\x0b" + encode_u32(5) + b"hello"
    data_section = make_section(11, encode_vector([data_segment]))

    wasm = make_wasm(memory_section, data_section)
    module = decode_module(wasm)
    assert len(module.datas) == 1
    assert module.datas[0].memidx == 0
    assert module.datas[0].offset == 0
    assert module.datas[0].data == b"hello"


# ===== Custom Section Tests =====

def test_custom_section():
    """Test custom section."""
    custom_payload = encode_name("name") + b"custom data"
    custom_section = make_section(0, custom_payload)

    wasm = make_wasm(custom_section)
    module = decode_module(wasm)
    assert len(module.customs) == 1
    assert module.customs[0].name == b"name"


# ===== Data Count Tests =====

def test_data_count_valid():
    """Test data count section matching data section."""
    # Memory section
    memory = b"\x00" + encode_u32(1)
    memory_section = make_section(5, encode_vector([memory]))

    # Data section: 1 active segment
    data_segment = encode_u32(0) + b"\x41" + encode_s32(0) + b"\x0b" + encode_u32(5) + b"hello"
    data_section = make_section(11, encode_vector([data_segment]))

    # Data count section: 1 segment
    data_count_section = make_section(12, encode_u32(1))

    wasm = make_wasm(memory_section, data_section, data_count_section)
    module = decode_module(wasm)
    assert module.datacount == 1
    assert len(module.datas) == 1
    errors = validate_module(module)
    assert len(errors) == 0


def test_data_count_mismatch():
    """Test validation catches data count mismatch."""
    # Memory section
    memory = b"\x00" + encode_u32(1)
    memory_section = make_section(5, encode_vector([memory]))

    # Data section: 1 active segment
    data_segment = encode_u32(0) + b"\x41" + encode_s32(0) + b"\x0b" + encode_u32(5) + b"hello"
    data_section = make_section(11, encode_vector([data_segment]))

    # Data count section: 2 segments (wrong)
    data_count_section = make_section(12, encode_u32(2))

    wasm = make_wasm(memory_section, data_section, data_count_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "data_count_mismatch" for e in errors)


# ===== Limit Tests =====

def test_module_size_limit():
    """Test module exceeding size limit."""
    wasm = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 100
    with pytest.raises(DecodeError):
        decode_module(wasm, limits=Limits(max_module_bytes=10))


# ===== Section Ordering Tests =====

def test_section_ordering_violation():
    """Test section ordering violation."""
    # Export section (7) before function section (3)
    export_section = make_section(7, encode_vector([]))
    func_section = make_section(3, encode_vector([]))

    wasm = make_wasm(export_section, func_section)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert exc_info.value.code == "section_order"


def test_duplicate_section():
    """Test duplicate section."""
    # Two type sections
    type_section1 = make_section(1, encode_vector([]))
    type_section2 = make_section(1, encode_vector([]))

    wasm = make_wasm(type_section1, type_section2)
    with pytest.raises(DecodeError) as exc_info:
        decode_module(wasm)
    assert exc_info.value.code == "section_order"


# ===== Validation Tests =====

def test_function_code_linkage():
    """Test validation catches function/code count mismatch."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # 2 functions
    func_section = make_section(3, encode_vector([encode_u32(0), encode_u32(0)]))

    # Only 1 code entry (mismatch)
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "func_code_count_mismatch" for e in errors)


def test_invalid_typeidx():
    """Test validation catches invalid type index."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing invalid type 5
    func_section = make_section(3, encode_vector([encode_u32(5)]))

    wasm = make_wasm(type_section, func_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "type_index_out_of_range" for e in errors)


def test_local_index_out_of_range():
    """Test validation catches local index out of range."""
    # Type: [i32] -> []
    functype = b"\x60" + encode_vector([b"\x7f"]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: no locals, local.get 5 (out of range), end
    # Function has 1 param, so valid indices are 0 only
    func_body = encode_vector([]) + b"\x20" + encode_u32(5) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "local_index_out_of_range" for e in errors)


def test_call_index_out_of_range():
    """Test validation catches call index out of range."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code: call 10 (out of range - only function 0 exists), end
    func_body = encode_vector([]) + b"\x10" + encode_u32(10) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any(e.code == "index_out_of_range" for e in errors)


# ===== Integration Tests =====

def test_decode_and_validate_success():
    """Test decode_and_validate with valid module."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # Function referencing type 0
    func_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code section
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_and_validate(wasm)
    assert module is not None


def test_decode_and_validate_failure():
    """Test decode_and_validate raises on validation errors."""
    # Type: [] -> []
    functype = b"\x60" + encode_vector([]) + encode_vector([])
    type_section = make_section(1, encode_vector([functype]))

    # 2 functions but only 1 code entry
    func_section = make_section(3, encode_vector([encode_u32(0), encode_u32(0)]))

    # Only 1 code entry (mismatch)
    func_body = encode_vector([]) + b"\x0b"
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    wasm = make_wasm(type_section, func_section, code_section)
    with pytest.raises(ValueError) as exc_info:
        decode_and_validate(wasm)
    assert "validation failed" in str(exc_info.value).lower()
