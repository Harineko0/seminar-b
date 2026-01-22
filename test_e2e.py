"""
E2E tests for wasm_sv public APIs.

Tests the three public APIs:
- decode_module(data: bytes, *, limits: Limits = Limits()) -> Module
- validate_module(module: Module) -> list[ValidationError]
- decode_and_validate(data: bytes, *, limits: Limits = Limits()) -> Module
"""

import pytest
from parser import decode_module, validate_module, decode_and_validate, DecodeError, ValidationError, Limits


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


def encode_functype(params: list, results: list) -> bytes:
    """Encode a function type."""
    return bytes([0x60]) + encode_vector(params) + encode_vector(results)


def encode_limits(min_val: int, max_val=None) -> bytes:
    """Encode limits."""
    if max_val is None:
        return bytes([0x00]) + encode_u32(min_val)
    else:
        return bytes([0x01]) + encode_u32(min_val) + encode_u32(max_val)


def encode_expr_i32_const(value: int) -> bytes:
    """Encode an i32.const expression."""
    return bytes([0x41]) + encode_s32(value) + bytes([0x0B])  # i32.const + value + end


def encode_expr_end_only() -> bytes:
    """Encode an expression with just end."""
    return bytes([0x0B])


# ===== A. Happy-path acceptance (must pass) =====

def test_decode_minimal_empty_module_ok():
    """Test 1: Decode minimal empty module (magic + version only)."""
    wasm_bytes_minimal = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(wasm_bytes_minimal)
    assert module is not None


def test_validate_minimal_empty_module_ok():
    """Test 2: Validate minimal empty module."""
    wasm_bytes_minimal = b"\x00asm\x01\x00\x00\x00"
    m = decode_module(wasm_bytes_minimal)
    errs = validate_module(m)
    assert errs == []


def test_decode_and_validate_minimal_empty_module_ok():
    """Test 3: decode_and_validate minimal empty module."""
    wasm_bytes_minimal = b"\x00asm\x01\x00\x00\x00"
    module = decode_and_validate(wasm_bytes_minimal)
    assert module is not None


def test_custom_section_only_ok_anywhere():
    """Test 4: Custom section only (id=0)."""
    custom_section = make_section(0, encode_name("test") + b"custom_data")
    wasm_bytes_custom_only = make_wasm(custom_section)
    module = decode_and_validate(wasm_bytes_custom_only)
    assert module is not None
    assert len(module.customs) == 1


def test_custom_section_interleaved_with_known_sections_ok():
    """Test 5: Custom sections interleaved with known sections."""
    custom1 = make_section(0, encode_name("before") + b"data1")
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    custom2 = make_section(0, encode_name("between") + b"data2")
    import_section = make_section(2, encode_vector([]))
    custom3 = make_section(0, encode_name("after") + b"data3")

    wasm_bytes_custom_interleaved = make_wasm(custom1, type_section, custom2, import_section, custom3)
    module = decode_and_validate(wasm_bytes_custom_interleaved)
    assert module is not None
    assert len(module.customs) == 3


# ===== B. Header / framing (decode must reject) =====

def test_decode_rejects_wrong_magic():
    """Test 6: Decode rejects wrong magic number."""
    wasm_bytes_wrong_magic = b"\x00bad\x01\x00\x00\x00"
    with pytest.raises(Exception):  # DecodeError or any exception
        decode_module(wasm_bytes_wrong_magic)


def test_decode_rejects_wrong_version():
    """Test 7: Decode rejects wrong version."""
    wasm_bytes_wrong_version = b"\x00asm\x02\x00\x00\x00"
    with pytest.raises(Exception):
        decode_module(wasm_bytes_wrong_version)


def test_decode_rejects_truncated_header():
    """Test 8: Decode rejects truncated header (< 8 bytes)."""
    wasm_bytes_truncated_header = b"\x00asm\x01\x00"  # Only 6 bytes
    with pytest.raises(Exception):
        decode_module(wasm_bytes_truncated_header)


def test_decode_rejects_trailing_garbage_after_last_section():
    """Test 9: Decode rejects trailing bytes after last section."""
    wasm_bytes_trailing_bytes = make_wasm() + b"\xFF\xFF"  # Extra bytes
    with pytest.raises(Exception):
        decode_module(wasm_bytes_trailing_bytes)


# ===== C. Section envelope correctness (decode must reject) =====

def test_decode_rejects_unknown_nonzero_section_id():
    """Test 10: Decode rejects unknown non-zero section id."""
    unknown_section = bytes([99]) + encode_u32(0)  # section id 99 with empty payload
    wasm_bytes_unknown_section_id = make_wasm(unknown_section)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_unknown_section_id)


def test_decode_rejects_section_payload_len_truncated():
    """Test 11: Decode rejects section payload length truncated."""
    # Section says it has 100 bytes but file ends early
    wasm_bytes_section_len_truncated = b"\x00asm\x01\x00\x00\x00" + bytes([1]) + encode_u32(100) + b"short"
    with pytest.raises(Exception):
        decode_module(wasm_bytes_section_len_truncated)


def test_decode_rejects_section_payload_len_overruns_module():
    """Test 12: Decode rejects section payload extends beyond module length."""
    # Same as test 11 - payload_len extends beyond available data
    wasm_bytes_section_len_overrun = b"\x00asm\x01\x00\x00\x00" + bytes([1]) + encode_u32(1000) + b"data"
    with pytest.raises(Exception):
        decode_module(wasm_bytes_section_len_overrun)


def test_decode_rejects_section_payload_has_unconsumed_bytes():
    """Test 13: Decode rejects section with unconsumed bytes in payload."""
    # Type section with valid content + junk at end
    valid_type = encode_functype([], [])
    payload = encode_vector([valid_type]) + b"\xFF\xFF"  # Extra junk
    type_section = make_section(1, payload)
    wasm_bytes_section_with_trailing_bytes = make_wasm(type_section)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_section_with_trailing_bytes)


# ===== D. Section ordering / uniqueness (decode must reject) =====

def test_decode_rejects_duplicate_type_section():
    """Test 14: Decode rejects duplicate type section."""
    type_section1 = make_section(1, encode_vector([]))
    type_section2 = make_section(1, encode_vector([]))
    wasm_bytes_duplicate_type_section = make_wasm(type_section1, type_section2)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_duplicate_type_section)


def test_decode_rejects_duplicate_import_section():
    """Test 15: Decode rejects duplicate import section."""
    import_section1 = make_section(2, encode_vector([]))
    import_section2 = make_section(2, encode_vector([]))
    wasm_bytes_duplicate_import_section = make_wasm(import_section1, import_section2)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_duplicate_import_section)


def test_decode_rejects_non_custom_section_out_of_order():
    """Test 16: Decode rejects non-custom sections out of order."""
    # Code (10) before function (3) is out of order
    code_section = make_section(10, encode_vector([]))
    function_section = make_section(3, encode_vector([]))
    wasm_bytes_out_of_order_sections = make_wasm(code_section, function_section)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_out_of_order_sections)


# ===== E. LEB128 & vector-length safety (decode must reject) =====

def test_decode_rejects_u32_leb128_overlong():
    """Test 17: Decode rejects overlong u32 LEB128 (> 5 bytes)."""
    # Create a 6-byte LEB128 encoding
    overlong_leb128 = bytes([0x80, 0x80, 0x80, 0x80, 0x80, 0x00])
    wasm_bytes_overlong_u32_leb128 = b"\x00asm\x01\x00\x00\x00" + bytes([1]) + overlong_leb128
    with pytest.raises(Exception):
        decode_module(wasm_bytes_overlong_u32_leb128)


def test_decode_rejects_leb128_truncated_mid_number():
    """Test 18: Decode rejects LEB128 truncated mid-number (continuation bit set but EOF)."""
    # LEB128 with continuation bit but no next byte
    truncated_leb128 = bytes([0x80])  # Continuation bit set, but no next byte
    wasm_bytes_truncated_leb128 = b"\x00asm\x01\x00\x00\x00" + bytes([1]) + truncated_leb128
    with pytest.raises(Exception):
        decode_module(wasm_bytes_truncated_leb128)


def test_decode_respects_limits_max_module_bytes():
    """Test 19: Decode respects max_module_bytes limit."""
    wasm_bytes = make_wasm()  # 8 bytes
    limits = Limits(max_module_bytes=5)  # Smaller than module
    with pytest.raises(Exception):
        decode_module(wasm_bytes, limits=limits)


def test_decode_respects_limits_max_vector_length():
    """Test 20: Decode respects max_vector_length limit."""
    # Create a type section that claims to have a huge vector count
    huge_count = encode_u32(100000)
    type_section_payload = huge_count  # Claims 100000 types but has no data
    type_section = make_section(1, type_section_payload)
    wasm_bytes_vector_len_exceeds_limit = make_wasm(type_section)

    limits = Limits(max_vector_length=10)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_vector_len_exceeds_limit, limits=limits)


def test_decode_respects_limits_max_section_bytes():
    """Test 21: Decode respects max_section_bytes limit."""
    # Create a section that's larger than the limit
    large_payload = b"x" * 1000
    type_section = make_section(1, large_payload)
    wasm_bytes_section_too_large = make_wasm(type_section)

    limits = Limits(max_section_bytes=100)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_section_too_large, limits=limits)


# ===== F. Cross-section structural constraints (validation must fail) =====

def test_validate_fails_typeidx_out_of_range_in_function_section():
    """Test 22: Validate fails when function section references invalid typeidx."""
    # Type section with 1 type
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    # Function section references typeidx=5 (out of range)
    function_section = make_section(3, encode_vector([encode_u32(5)]))
    wasm_bytes_func_typeidx_oob = make_wasm(type_section, function_section)

    # Decode should succeed
    module = decode_module(wasm_bytes_func_typeidx_oob)
    # Validate should fail
    errors = validate_module(module)
    assert len(errors) > 0
    # decode_and_validate should raise
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_func_typeidx_oob)


def test_validate_fails_imported_func_typeidx_out_of_range():
    """Test 23: Validate fails when import references invalid typeidx."""
    # Type section with 1 type
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    # Import function with typeidx=5 (out of range)
    import_entry = (
        encode_name("env") +
        encode_name("func") +
        bytes([0x00]) +  # Import kind: func
        encode_u32(5)  # typeidx out of range
    )
    import_section = make_section(2, encode_vector([import_entry]))
    wasm_bytes_import_func_typeidx_oob = make_wasm(type_section, import_section)

    module = decode_module(wasm_bytes_import_func_typeidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_import_func_typeidx_oob)


def test_validate_fails_export_func_index_out_of_range():
    """Test 24: Validate fails when export references invalid function index."""
    # Export function with index=10 (no functions exist)
    export_entry = encode_name("test") + bytes([0x00]) + encode_u32(10)
    export_section = make_section(7, encode_vector([export_entry]))
    wasm_bytes_export_funcidx_oob = make_wasm(export_section)

    module = decode_module(wasm_bytes_export_funcidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_export_funcidx_oob)


def test_validate_fails_export_table_index_out_of_range():
    """Test 25: Validate fails when export references invalid table index."""
    # Export table with index=1 (no tables exist)
    export_entry = encode_name("test") + bytes([0x01]) + encode_u32(1)
    export_section = make_section(7, encode_vector([export_entry]))
    wasm_bytes_export_tableidx_oob = make_wasm(export_section)

    module = decode_module(wasm_bytes_export_tableidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_export_tableidx_oob)


def test_validate_fails_export_mem_index_out_of_range():
    """Test 26: Validate fails when export references invalid memory index."""
    # Export memory with index=1 (no memories exist)
    export_entry = encode_name("test") + bytes([0x02]) + encode_u32(1)
    export_section = make_section(7, encode_vector([export_entry]))
    wasm_bytes_export_memidx_oob = make_wasm(export_section)

    module = decode_module(wasm_bytes_export_memidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_export_memidx_oob)


def test_validate_fails_export_global_index_out_of_range():
    """Test 27: Validate fails when export references invalid global index."""
    # Export global with index=5 (no globals exist)
    export_entry = encode_name("test") + bytes([0x03]) + encode_u32(5)
    export_section = make_section(7, encode_vector([export_entry]))
    wasm_bytes_export_globalidx_oob = make_wasm(export_section)

    module = decode_module(wasm_bytes_export_globalidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_export_globalidx_oob)


def test_validate_fails_export_name_not_unique():
    """Test 28: Validate fails when export names are not unique."""
    # Two exports with same name
    export1 = encode_name("duplicate") + bytes([0x00]) + encode_u32(0)
    export2 = encode_name("duplicate") + bytes([0x00]) + encode_u32(0)
    export_section = make_section(7, encode_vector([export1, export2]))

    # Need at least one function
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_export_duplicate_names = make_wasm(type_section, function_section, export_section, code_section)

    module = decode_module(wasm_bytes_export_duplicate_names)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_export_duplicate_names)


def test_validate_fails_start_func_index_out_of_range():
    """Test 29: Validate fails when start function index is out of range."""
    # Start section with funcidx=10 (no functions exist)
    start_section = make_section(8, encode_u32(10))
    wasm_bytes_start_funcidx_oob = make_wasm(start_section)

    module = decode_module(wasm_bytes_start_funcidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_start_funcidx_oob)


def test_validate_fails_start_func_signature_not_empty():
    """Test 30: Validate fails when start function has non-empty signature."""
    # Type with params
    type_with_params = encode_functype([bytes([0x7F])], [])  # i32 param
    type_section = make_section(1, encode_vector([type_with_params]))

    # Function using that type
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code section
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    # Start section pointing to function 0
    start_section = make_section(8, encode_u32(0))

    wasm_bytes_start_func_has_params_or_results = make_wasm(
        type_section, function_section, start_section, code_section
    )

    module = decode_module(wasm_bytes_start_func_has_params_or_results)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_start_func_has_params_or_results)


def test_validate_fails_limits_min_greater_than_max_in_memory_type():
    """Test 31: Validate fails when memory limits have min > max."""
    # Memory with min=10, max=5
    mem_type = encode_limits(10, 5)
    memory_section = make_section(5, encode_vector([mem_type]))
    wasm_bytes_mem_limits_min_gt_max = make_wasm(memory_section)

    module = decode_module(wasm_bytes_mem_limits_min_gt_max)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_mem_limits_min_gt_max)


def test_validate_fails_limits_min_greater_than_max_in_table_type():
    """Test 32: Validate fails when table limits have min > max."""
    # Table with funcref, min=10, max=5
    table_type = bytes([0x70]) + encode_limits(10, 5)  # 0x70 = funcref
    table_section = make_section(4, encode_vector([table_type]))
    wasm_bytes_table_limits_min_gt_max = make_wasm(table_section)

    module = decode_module(wasm_bytes_table_limits_min_gt_max)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_table_limits_min_gt_max)


# ===== G. Function/code linkage & DataCount =====

def test_validate_fails_function_and_code_count_mismatch():
    """Test 33: Validate fails when function and code section counts mismatch."""
    # Type section
    type_section = make_section(1, encode_vector([encode_functype([], [])]))

    # Function section with 2 functions
    function_section = make_section(3, encode_vector([encode_u32(0), encode_u32(0)]))

    # Code section with only 1 function body
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_func_code_count_mismatch = make_wasm(type_section, function_section, code_section)

    module = decode_module(wasm_bytes_func_code_count_mismatch)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_func_code_count_mismatch)


def test_decode_or_validate_rejects_missing_code_section_when_function_section_present():
    """Test 34: Reject when function section exists without code section."""
    # Type section
    type_section = make_section(1, encode_vector([encode_functype([], [])]))

    # Function section with 1 function
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # No code section
    wasm_bytes_function_section_without_code_section = make_wasm(type_section, function_section)

    # Either decode rejects or validate rejects
    try:
        module = decode_module(wasm_bytes_function_section_without_code_section)
        # If decode succeeded, validate should fail
        errors = validate_module(module)
        assert len(errors) > 0
    except Exception:
        # Decode rejected, which is also acceptable
        pass

    # decode_and_validate should definitely raise
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_function_section_without_code_section)


def test_decode_or_validate_rejects_missing_function_section_when_code_section_present():
    """Test 35: Reject when code section exists without function section."""
    # Code section with 1 function body
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    # No function section
    wasm_bytes_code_section_without_function_section = make_wasm(code_section)

    # Either decode rejects or validate rejects
    try:
        module = decode_module(wasm_bytes_code_section_without_function_section)
        # If decode succeeded, validate should fail
        errors = validate_module(module)
        assert len(errors) > 0
    except Exception:
        # Decode rejected, which is also acceptable
        pass

    # decode_and_validate should definitely raise
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_code_section_without_function_section)


def test_validate_fails_data_count_mismatch():
    """Test 36: Validate fails when data_count doesn't match data section length."""
    # Data section with only 1 segment
    # Format: flags(0x00) + offset_expr(i32.const 0; end) + byte_count + bytes
    data_segment = bytes([0x00]) + encode_expr_i32_const(0) + encode_u32(4) + b"data"
    data_section = make_section(11, encode_vector([data_segment]))

    # Data count section saying 2 segments (mismatch!)
    data_count_section = make_section(12, encode_u32(2))

    # Data (11) comes before data_count (12) in section ordering
    wasm_bytes_data_count_mismatch = make_wasm(data_section, data_count_section)

    module = decode_module(wasm_bytes_data_count_mismatch)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_data_count_mismatch)


# ===== H. Restricted Element/Data segment forms =====

def test_decode_rejects_element_segment_non_table0():
    """Test 37: Decode rejects element segment with non-zero table index."""
    # Element segment with flags != 0x00 (e.g., 0x02 for different table)
    elem_segment = bytes([0x02]) + b"..."  # flags=0x02 (not supported)
    elem_section = make_section(9, encode_vector([elem_segment]))
    wasm_bytes_elem_table_index_not_zero = make_wasm(elem_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_elem_table_index_not_zero)


def test_decode_rejects_element_segment_offset_expr_not_i32const_end():
    """Test 38: Decode rejects element segment with non-canonical offset expression."""
    # Element segment with non i32.const offset
    # flags=0x00, but offset is not i32.const
    elem_segment = (
        bytes([0x00]) +  # flags (active, table 0)
        bytes([0x0B]) +  # Just 'end' opcode (not i32.const + end)
        encode_vector([])  # Empty funcidx vector
    )
    elem_section = make_section(9, encode_vector([elem_segment]))
    wasm_bytes_elem_offset_expr_not_canonical = make_wasm(elem_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_elem_offset_expr_not_canonical)


def test_decode_rejects_data_segment_non_mem0():
    """Test 39: Decode rejects data segment with non-zero memory index."""
    # Data segment with flags != 0x00
    data_segment = bytes([0x02]) + b"..."  # flags=0x02 (not supported)
    data_section = make_section(11, encode_vector([data_segment]))
    wasm_bytes_data_mem_index_not_zero = make_wasm(data_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_data_mem_index_not_zero)


def test_decode_rejects_data_segment_offset_expr_not_i32const_end():
    """Test 40: Decode rejects data segment with non-canonical offset expression."""
    # Data segment with non i32.const offset
    data_segment = (
        bytes([0x00]) +  # flags (active, mem 0)
        bytes([0x0B]) +  # Just 'end' opcode (not i32.const + end)
        encode_vector([b"data"])  # Data bytes
    )
    data_section = make_section(11, encode_vector([data_segment]))
    wasm_bytes_data_offset_expr_not_canonical = make_wasm(data_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_data_offset_expr_not_canonical)


# ===== I. Restricted instruction subset =====

def test_decode_rejects_unknown_opcode_in_func_body():
    """Test 41: Decode rejects unknown/unsupported opcode in function body."""
    # Type and function sections
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with unsupported opcode (e.g., 0xFF)
    func_body = encode_vector([]) + bytes([0xFF, 0x0B])  # locals, unknown opcode, end
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_func_body_has_unsupported_opcode = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_func_body_has_unsupported_opcode)


def test_decode_rejects_expr_missing_end_opcode():
    """Test 42: Decode rejects expression missing end opcode."""
    # Type and function sections
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with expression that has no end opcode
    func_body = encode_vector([]) + bytes([0x41, 0x00])  # locals, i32.const 0, NO END
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_expr_missing_end = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_expr_missing_end)


def test_decode_rejects_expr_has_trailing_bytes_after_end():
    """Test 43: Decode rejects expression with trailing bytes after end."""
    # Type and function sections
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with expression: end + trailing bytes
    # The function body size is accurate, but after parsing the expression (which ends with END),
    # there are still bytes left in the function body
    func_body = encode_vector([]) + bytes([0x0B, 0xFF, 0xFF])  # locals, end, TRAILING BYTES
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_expr_trailing_bytes_after_end = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_expr_trailing_bytes_after_end)


# ===== J. Immediate bounds validation =====

def test_validate_fails_local_get_index_out_of_range():
    """Test 44: Validate fails when local.get index is out of range."""
    # Type: [] -> []
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with local.get 10 (no locals exist)
    func_body = encode_vector([]) + bytes([0x20]) + encode_u32(10) + bytes([0x0B])  # local.get 10, end
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_local_get_oob = make_wasm(type_section, function_section, code_section)

    module = decode_module(wasm_bytes_local_get_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_local_get_oob)


def test_validate_fails_local_set_index_out_of_range():
    """Test 45: Validate fails when local.set index is out of range."""
    # Type: [] -> []
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with i32.const 0, local.set 10 (no locals exist), end
    func_body = (
        encode_vector([]) +  # No locals
        bytes([0x41, 0x00]) +  # i32.const 0
        bytes([0x21]) + encode_u32(10) +  # local.set 10
        bytes([0x0B])  # end
    )
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_local_set_oob = make_wasm(type_section, function_section, code_section)

    module = decode_module(wasm_bytes_local_set_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_local_set_oob)


def test_validate_fails_call_func_index_out_of_range():
    """Test 46: Validate fails when call function index is out of range."""
    # Type: [] -> []
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with call 99 (function doesn't exist)
    func_body = (
        encode_vector([]) +  # No locals
        bytes([0x10]) + encode_u32(99) +  # call 99
        bytes([0x0B])  # end
    )
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_call_funcidx_oob = make_wasm(type_section, function_section, code_section)

    module = decode_module(wasm_bytes_call_funcidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_call_funcidx_oob)


# ===== K. LEB128 Signed Overlong Encoding (CRITICAL SECURITY BUG) =====

def test_decode_rejects_s32_leb128_overlong_zero():
    """Test 47: Decode rejects overlong s32 LEB128 encoding of zero (2 bytes instead of 1)."""
    # Canonical encoding of 0: [0x00]
    # Overlong encoding of 0: [0x80, 0x00] (continuation bit set but value is 0)
    # This test will FAIL - decoder currently accepts overlong encodings
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with i32.const using overlong encoding of 0
    func_body = (
        encode_vector([]) +  # No locals
        bytes([0x41]) +  # i32.const opcode
        bytes([0x80, 0x00]) +  # Overlong encoding of 0
        bytes([0x1A]) +  # drop
        bytes([0x0B])  # end
    )
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_overlong_s32_zero = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):  # Should raise DecodeError but currently doesn't
        decode_module(wasm_bytes_overlong_s32_zero)


def test_decode_rejects_s32_leb128_overlong_positive():
    """Test 48: Decode rejects overlong s32 LEB128 encoding of small positive value."""
    # Canonical encoding of 1: [0x01]
    # Overlong encoding of 1: [0x81, 0x00]
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with i32.const using overlong encoding of 1
    func_body = (
        encode_vector([]) +  # No locals
        bytes([0x41]) +  # i32.const opcode
        bytes([0x81, 0x00]) +  # Overlong encoding of 1
        bytes([0x1A]) +  # drop
        bytes([0x0B])  # end
    )
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_overlong_s32_positive = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_overlong_s32_positive)


def test_decode_rejects_s32_leb128_overlong_negative():
    """Test 49: Decode rejects overlong s32 LEB128 encoding of -1."""
    # Canonical encoding of -1: [0x7F]
    # Overlong encoding of -1: [0xFF, 0x7F]
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with i32.const using overlong encoding of -1
    func_body = (
        encode_vector([]) +  # No locals
        bytes([0x41]) +  # i32.const opcode
        bytes([0xFF, 0x7F]) +  # Overlong encoding of -1
        bytes([0x1A]) +  # drop
        bytes([0x0B])  # end
    )
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_overlong_s32_negative = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_overlong_s32_negative)


def test_decode_rejects_s32_leb128_exceeds_5_bytes():
    """Test 50: Decode rejects s32 LEB128 that exceeds 5 byte limit."""
    # s32 should not exceed 5 bytes (similar to u32)
    # Create a 6-byte LEB128 encoding
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Code with i32.const using 6-byte LEB128
    func_body = (
        encode_vector([]) +  # No locals
        bytes([0x41]) +  # i32.const opcode
        bytes([0x80, 0x80, 0x80, 0x80, 0x80, 0x00]) +  # 6 bytes
        bytes([0x1A]) +  # drop
        bytes([0x0B])  # end
    )
    code_entry = encode_u32(len(func_body)) + func_body
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_s32_exceeds_5_bytes = make_wasm(type_section, function_section, code_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_s32_exceeds_5_bytes)


# ===== L. Element Segment Function Index Validation (CRITICAL CORRECTNESS BUG) =====

def test_validate_fails_element_segment_funcidx_out_of_range():
    """Test 51: Validate fails when element segment references non-existent function."""
    # This test will FAIL - element segment function indices are never validated
    # Create table section (min=10)
    table_type = bytes([0x70]) + encode_limits(10)  # funcref, min=10
    table_section = make_section(4, encode_vector([table_type]))

    # Create element section with invalid function index 99 (no functions exist)
    elem_segment = (
        bytes([0x00]) +  # flags (active, table 0)
        encode_expr_i32_const(0) +  # offset expression
        encode_vector([encode_u32(99)])  # funcidx vector with index 99
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    wasm_bytes_elem_funcidx_oob = make_wasm(table_section, elem_section)

    module = decode_module(wasm_bytes_elem_funcidx_oob)
    errors = validate_module(module)
    assert len(errors) > 0  # Should fail validation but currently doesn't
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_elem_funcidx_oob)


def test_validate_fails_element_segment_funcidx_partially_invalid():
    """Test 52: Validate fails when element segment has mix of valid/invalid function indices."""
    # Create minimal function setup
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))  # 1 function at index 0
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    # Create table section
    table_type = bytes([0x70]) + encode_limits(10)
    table_section = make_section(4, encode_vector([table_type]))

    # Element segment with init=[0, 99, 0] where only index 99 is invalid
    elem_segment = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_vector([encode_u32(0), encode_u32(99), encode_u32(0)])  # Middle index is invalid
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    wasm_bytes_elem_partial_invalid = make_wasm(
        type_section, function_section, table_section, elem_section, code_section
    )

    module = decode_module(wasm_bytes_elem_partial_invalid)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_elem_partial_invalid)


def test_validate_succeeds_element_segment_funcidx_includes_imports():
    """Test 53: Validate succeeds when element segment references imported functions (positive test)."""
    # Import a function (becomes function index 0)
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    import_entry = (
        encode_name("env") +
        encode_name("imported_func") +
        bytes([0x00]) +  # Import kind: func
        encode_u32(0)  # typeidx
    )
    import_section = make_section(2, encode_vector([import_entry]))

    # Create table section
    table_type = bytes([0x70]) + encode_limits(10)
    table_section = make_section(4, encode_vector([table_type]))

    # Element segment referencing the imported function at index 0
    elem_segment = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_vector([encode_u32(0)])  # Reference imported function
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    wasm_bytes_elem_with_import = make_wasm(
        type_section, import_section, table_section, elem_section
    )

    # This should pass validation (positive test)
    module = decode_and_validate(wasm_bytes_elem_with_import)
    assert module is not None


# ===== M. Table/Memory Existence Validation (CRITICAL CORRECTNESS BUG) =====

def test_validate_fails_element_segment_without_table():
    """Test 54: Validate fails when element segment exists but no table is defined."""
    # This test will FAIL - no validation that table 0 exists
    # Element segment without any table section or import
    elem_segment = (
        bytes([0x00]) +  # flags (active, table 0)
        encode_expr_i32_const(0) +
        encode_vector([encode_u32(0)])  # Empty funcidx vector would also work
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    # Need at least one function for the element to reference
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_elem_without_table = make_wasm(
        type_section, function_section, elem_section, code_section
    )

    module = decode_module(wasm_bytes_elem_without_table)
    errors = validate_module(module)
    assert len(errors) > 0  # Should fail but currently doesn't
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_elem_without_table)


def test_validate_fails_data_segment_without_memory():
    """Test 55: Validate fails when data segment exists but no memory is defined."""
    # This test will FAIL - no validation that memory 0 exists
    # Data segment without any memory section or import
    data_segment = (
        bytes([0x00]) +  # flags (active, mem 0)
        encode_expr_i32_const(0) +
        encode_u32(4) + b"data"  # 4 bytes of data
    )
    data_section = make_section(11, encode_vector([data_segment]))

    wasm_bytes_data_without_memory = make_wasm(data_section)

    module = decode_module(wasm_bytes_data_without_memory)
    errors = validate_module(module)
    assert len(errors) > 0  # Should fail but currently doesn't
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_data_without_memory)


def test_validate_succeeds_element_segment_with_imported_table():
    """Test 56: Validate succeeds with element segment when table is imported (positive test)."""
    # Import a table
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    table_import = (
        encode_name("env") +
        encode_name("table") +
        bytes([0x01]) +  # Import kind: table
        bytes([0x70]) + encode_limits(10)  # funcref, min=10
    )
    import_section = make_section(2, encode_vector([table_import]))

    # Need a function for element to reference
    function_section = make_section(3, encode_vector([encode_u32(0)]))
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    # Element segment using the imported table
    elem_segment = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_vector([encode_u32(0)])
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    wasm_bytes_elem_with_imported_table = make_wasm(
        type_section, import_section, function_section, elem_section, code_section
    )

    # Should pass validation
    module = decode_and_validate(wasm_bytes_elem_with_imported_table)
    assert module is not None


def test_validate_succeeds_data_segment_with_imported_memory():
    """Test 57: Validate succeeds with data segment when memory is imported (positive test)."""
    # Import a memory
    mem_import = (
        encode_name("env") +
        encode_name("memory") +
        bytes([0x02]) +  # Import kind: memory
        encode_limits(1)  # min=1 page
    )
    import_section = make_section(2, encode_vector([mem_import]))

    # Data segment using the imported memory
    data_segment = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_u32(4) + b"data"
    )
    data_section = make_section(11, encode_vector([data_segment]))

    wasm_bytes_data_with_imported_memory = make_wasm(import_section, data_section)

    # Should pass validation
    module = decode_and_validate(wasm_bytes_data_with_imported_memory)
    assert module is not None


# ===== N. Import Limits Validation (TEST COVERAGE GAP) =====

def test_validate_fails_imported_table_limits_min_gt_max():
    """Test 58: Validate fails when imported table has min > max."""
    # Import table with min=10, max=5
    table_import = (
        encode_name("env") +
        encode_name("table") +
        bytes([0x01]) +  # Import kind: table
        bytes([0x70]) + encode_limits(10, 5)  # funcref, min=10, max=5 (invalid)
    )
    import_section = make_section(2, encode_vector([table_import]))

    wasm_bytes_imported_table_limits_invalid = make_wasm(import_section)

    module = decode_module(wasm_bytes_imported_table_limits_invalid)
    errors = validate_module(module)
    assert len(errors) > 0  # Validation code exists, confirming it works
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_imported_table_limits_invalid)


def test_validate_fails_imported_memory_limits_min_gt_max():
    """Test 59: Validate fails when imported memory has min > max."""
    # Import memory with min=10, max=5
    mem_import = (
        encode_name("env") +
        encode_name("memory") +
        bytes([0x02]) +  # Import kind: memory
        encode_limits(10, 5)  # min=10, max=5 (invalid)
    )
    import_section = make_section(2, encode_vector([mem_import]))

    wasm_bytes_imported_memory_limits_invalid = make_wasm(import_section)

    module = decode_module(wasm_bytes_imported_memory_limits_invalid)
    errors = validate_module(module)
    assert len(errors) > 0  # Validation code exists, confirming it works
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_imported_memory_limits_invalid)


# ===== O. Additional Edge Cases (UTF-8 and Data Count) =====

def test_decode_rejects_export_name_invalid_utf8():
    """Test 60: Decode rejects export with invalid UTF-8 sequence."""
    # Invalid UTF-8 sequence: [0xFF, 0xFE]
    invalid_utf8_name = encode_u32(2) + bytes([0xFF, 0xFE])
    export_entry = invalid_utf8_name + bytes([0x00]) + encode_u32(0)
    export_section = make_section(7, encode_vector([export_entry]))

    # Need a function for export to reference
    type_section = make_section(1, encode_vector([encode_functype([], [])]))
    function_section = make_section(3, encode_vector([encode_u32(0)]))
    code_entry = encode_u32(2) + encode_vector([]) + encode_expr_end_only()
    code_section = make_section(10, encode_vector([code_entry]))

    wasm_bytes_export_invalid_utf8 = make_wasm(
        type_section, function_section, export_section, code_section
    )

    with pytest.raises(Exception):  # Should raise DecodeError
        decode_module(wasm_bytes_export_invalid_utf8)


def test_decode_rejects_import_module_name_invalid_utf8():
    """Test 61: Decode rejects import with invalid UTF-8 module name."""
    # Invalid UTF-8 in module name
    type_section = make_section(1, encode_vector([encode_functype([], [])]))

    invalid_utf8_name = encode_u32(2) + bytes([0xFF, 0xFE])
    import_entry = (
        invalid_utf8_name +  # Invalid module name
        encode_name("func") +
        bytes([0x00]) +  # Import kind: func
        encode_u32(0)
    )
    import_section = make_section(2, encode_vector([import_entry]))

    wasm_bytes_import_invalid_utf8 = make_wasm(type_section, import_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_import_invalid_utf8)


def test_decode_rejects_custom_section_name_invalid_utf8():
    """Test 62: Decode rejects custom section with invalid UTF-8 name."""
    # Custom section with invalid UTF-8 name
    invalid_utf8_name = encode_u32(2) + bytes([0xFF, 0xFE])
    custom_section = make_section(0, invalid_utf8_name + b"custom_data")

    wasm_bytes_custom_invalid_utf8 = make_wasm(custom_section)

    with pytest.raises(Exception):
        decode_module(wasm_bytes_custom_invalid_utf8)


def test_validate_fails_data_count_zero_with_nonempty_data():
    """Test 63: Validate fails when data_count=0 but data section has segments."""
    # Data section with 1 segment
    data_segment = bytes([0x00]) + encode_expr_i32_const(0) + encode_u32(4) + b"data"
    data_section = make_section(11, encode_vector([data_segment]))

    # Data count section saying 0 segments (mismatch)
    data_count_section = make_section(12, encode_u32(0))

    # Need memory for the data segment
    memory_section = make_section(5, encode_vector([encode_limits(1)]))

    wasm_bytes_data_count_zero_mismatch = make_wasm(
        memory_section, data_section, data_count_section
    )

    module = decode_module(wasm_bytes_data_count_zero_mismatch)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_data_count_zero_mismatch)


def test_validate_succeeds_data_count_zero_with_empty_data():
    """Test 64: Validate succeeds when data_count=0 matches empty data section (positive test)."""
    # Data section with 0 segments
    data_section = make_section(11, encode_vector([]))

    # Data count section saying 0 segments (matches)
    data_count_section = make_section(12, encode_u32(0))

    wasm_bytes_data_count_zero_valid = make_wasm(data_section, data_count_section)

    # Should pass validation
    module = decode_and_validate(wasm_bytes_data_count_zero_valid)
    assert module is not None
