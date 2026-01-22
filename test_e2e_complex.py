"""
Complex E2E tests for wasm_sv public APIs.

Each test case combines multiple WASM features and validates various aspects
simultaneously with longer, more realistic byte data.
"""

import pytest
from parser import decode_module, validate_module, decode_and_validate, DecodeError, ValidationError, Limits


# ===== Helper Functions (same as test_e2e.py) =====

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


def encode_local_entry(count: int, valtype: bytes) -> bytes:
    """Encode a local entry (count + valtype)."""
    return encode_u32(count) + valtype


# ===== Complex Happy Path Tests =====

def test_complex_module_with_all_sections_valid():
    """
    Complex test 1: Module with imports, functions, tables, memory, globals,
    exports, start, elements, data, and custom sections all working together.
    Tests: imports, type system, function/code linkage, tables, memory,
    globals, exports, start function, element segments, data segments.
    """
    # Custom section before everything
    custom1 = make_section(0, encode_name("compiler_info") + b"wasm_sv v1.0")

    # Type section: multiple function types
    # Type 0: [] -> []
    # Type 1: [i32] -> [i32]
    # Type 2: [i32, i32] -> [i32]
    type_section = make_section(1, encode_vector([
        encode_functype([], []),
        encode_functype([bytes([0x7F])], [bytes([0x7F])]),  # i32 -> i32
        encode_functype([bytes([0x7F]), bytes([0x7F])], [bytes([0x7F])]),  # i32, i32 -> i32
    ]))

    # Import section: import function, table, memory, and global
    import_func = (
        encode_name("env") +
        encode_name("log") +
        bytes([0x00]) +  # func
        encode_u32(0)  # typeidx 0: [] -> []
    )
    import_table = (
        encode_name("env") +
        encode_name("table") +
        bytes([0x01]) +  # table
        bytes([0x70]) + encode_limits(5, 10)  # funcref, min=5, max=10
    )
    import_memory = (
        encode_name("env") +
        encode_name("memory") +
        bytes([0x02]) +  # memory
        encode_limits(1, 2)  # min=1, max=2 pages
    )
    import_global = (
        encode_name("env") +
        encode_name("global_i32") +
        bytes([0x03]) +  # global
        bytes([0x7F, 0x00])  # i32, immutable (no init expr for imports)
    )
    import_section = make_section(2, encode_vector([
        import_func, import_table, import_memory, import_global
    ]))

    custom2 = make_section(0, encode_name("debug") + b"debug_info_123")

    # Function section: 3 local functions (indices 1, 2, 3 since 0 is imported)
    # Func 1: type 0 ([] -> [])
    # Func 2: type 1 (i32 -> i32)
    # Func 3: type 2 (i32, i32 -> i32)
    function_section = make_section(3, encode_vector([
        encode_u32(0),  # typeidx 0
        encode_u32(1),  # typeidx 1
        encode_u32(2),  # typeidx 2
    ]))

    # Global section: add a mutable i32 global
    global_entry = bytes([0x7F, 0x01]) + encode_expr_i32_const(42)  # i32, mutable, init=42
    global_section = make_section(6, encode_vector([global_entry]))

    # Export section: export functions, table, memory, and global
    export_func = encode_name("main") + bytes([0x00]) + encode_u32(1)  # func 1
    export_func2 = encode_name("add") + bytes([0x00]) + encode_u32(3)  # func 3
    export_table = encode_name("tbl") + bytes([0x01]) + encode_u32(0)  # table 0
    export_mem = encode_name("mem") + bytes([0x02]) + encode_u32(0)  # memory 0
    export_global = encode_name("counter") + bytes([0x03]) + encode_u32(1)  # global 1 (local global)
    export_section = make_section(7, encode_vector([
        export_func, export_func2, export_table, export_mem, export_global
    ]))

    # Start section: start with function 1
    start_section = make_section(8, encode_u32(1))

    # Element section: initialize table with function references
    elem_segment = (
        bytes([0x00]) +  # flags (active, table 0)
        encode_expr_i32_const(0) +  # offset = 0
        encode_vector([encode_u32(1), encode_u32(2), encode_u32(3)])  # funcidx 1, 2, 3
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    # Code section: 3 function bodies
    # Function 1: [] -> [] - calls imported function
    func1_body = (
        encode_vector([]) +  # no locals
        bytes([0x10]) + encode_u32(0) +  # call 0 (imported func)
        bytes([0x0B])  # end
    )
    code1 = encode_u32(len(func1_body)) + func1_body

    # Function 2: i32 -> i32 - identity function with local
    func2_body = (
        encode_vector([encode_local_entry(1, bytes([0x7F]))]) +  # 1 local i32
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (param)
        bytes([0x41, 0x01]) +  # i32.const 1
        bytes([0x6A]) +  # i32.add
        bytes([0x21]) + encode_u32(1) +  # local.set 1
        bytes([0x20]) + encode_u32(1) +  # local.get 1
        bytes([0x0B])  # end
    )
    code2 = encode_u32(len(func2_body)) + func2_body

    # Function 3: i32, i32 -> i32 - add two params
    func3_body = (
        encode_vector([]) +  # no locals
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (first param)
        bytes([0x20]) + encode_u32(1) +  # local.get 1 (second param)
        bytes([0x6A]) +  # i32.add
        bytes([0x0B])  # end
    )
    code3 = encode_u32(len(func3_body)) + func3_body

    code_section = make_section(10, encode_vector([code1, code2, code3]))

    # Data section: initialize memory
    data_segment = (
        bytes([0x00]) +  # flags (active, mem 0)
        encode_expr_i32_const(0) +  # offset = 0
        encode_u32(13) + b"Hello, WASM!\n"  # 13 bytes
    )
    data_section = make_section(11, encode_vector([data_segment]))

    # Data count section
    data_count_section = make_section(12, encode_u32(1))

    custom3 = make_section(0, encode_name("metadata") + b"end_marker")

    # Build complete module
    wasm_bytes = make_wasm(
        custom1, type_section, import_section, custom2, function_section,
        global_section, export_section, start_section, elem_section,
        code_section, data_section, data_count_section, custom3
    )

    # Should decode and validate successfully
    module = decode_and_validate(wasm_bytes)
    assert module is not None
    assert len(module.types) == 3
    assert len(module.imports) == 4
    assert len(module.functions) == 3
    assert len(module.globals) == 1
    assert len(module.exports) == 5
    assert module.start is not None
    assert len(module.elements) == 1
    assert len(module.data) == 1
    assert len(module.customs) == 3


def test_complex_function_chain_with_locals_and_calls():
    """
    Complex test 2: Multiple functions with various local variables calling
    each other, testing local variable management and function call validation.
    Tests: multiple function types, local variables (params + locals), call instructions,
    type checking across function boundaries.
    """
    # Type section: various function signatures
    # Type 0: [] -> []
    # Type 1: [i32] -> []
    # Type 2: [i32] -> [i32]
    # Type 3: [i32, i32, i32] -> [i32]
    type_section = make_section(1, encode_vector([
        encode_functype([], []),
        encode_functype([bytes([0x7F])], []),
        encode_functype([bytes([0x7F])], [bytes([0x7F])]),
        encode_functype([bytes([0x7F]), bytes([0x7F]), bytes([0x7F])], [bytes([0x7F])]),
    ]))

    # Function section: 5 functions with different types
    function_section = make_section(3, encode_vector([
        encode_u32(0),  # func 0: [] -> []
        encode_u32(1),  # func 1: [i32] -> []
        encode_u32(2),  # func 2: [i32] -> [i32]
        encode_u32(2),  # func 3: [i32] -> [i32]
        encode_u32(3),  # func 4: [i32, i32, i32] -> [i32]
    ]))

    # Code section with complex function bodies
    # Function 0: calls function 1 with a constant
    func0_locals = encode_vector([encode_local_entry(2, bytes([0x7F]))])  # 2 i32 locals
    func0_code = (
        bytes([0x41, 0x2A]) +  # i32.const 42
        bytes([0x21]) + encode_u32(0) +  # local.set 0
        bytes([0x20]) + encode_u32(0) +  # local.get 0
        bytes([0x10]) + encode_u32(1) +  # call 1 (pass 42)
        bytes([0x0B])  # end
    )
    func0_body = func0_locals + func0_code
    code0 = encode_u32(len(func0_body)) + func0_body

    # Function 1: [i32] -> [], calls function 2
    func1_locals = encode_vector([encode_local_entry(3, bytes([0x7F]))])  # 3 i32 locals
    func1_code = (
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (param)
        bytes([0x41, 0x01]) +  # i32.const 1
        bytes([0x6A]) +  # i32.add
        bytes([0x21]) + encode_u32(1) +  # local.set 1
        bytes([0x20]) + encode_u32(1) +  # local.get 1
        bytes([0x10]) + encode_u32(2) +  # call 2
        bytes([0x21]) + encode_u32(2) +  # local.set 2
        bytes([0x0B])  # end
    )
    func1_body = func1_locals + func1_code
    code1 = encode_u32(len(func1_body)) + func1_body

    # Function 2: [i32] -> [i32], calls function 3
    func2_locals = encode_vector([encode_local_entry(5, bytes([0x7F]))])  # 5 i32 locals
    func2_code = (
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (param)
        bytes([0x41, 0x0A]) +  # i32.const 10
        bytes([0x6A]) +  # i32.add
        bytes([0x21]) + encode_u32(1) +  # local.set 1
        bytes([0x20]) + encode_u32(1) +  # local.get 1
        bytes([0x10]) + encode_u32(3) +  # call 3
        bytes([0x0B])  # end (return result from call 3)
    )
    func2_body = func2_locals + func2_code
    code2 = encode_u32(len(func2_body)) + func2_body

    # Function 3: [i32] -> [i32], calls function 4
    func3_locals = encode_vector([encode_local_entry(4, bytes([0x7F]))])  # 4 i32 locals
    func3_code = (
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (param)
        bytes([0x21]) + encode_u32(1) +  # local.set 1
        bytes([0x20]) + encode_u32(1) +  # local.get 1
        bytes([0x41, 0x05]) +  # i32.const 5
        bytes([0x41, 0x03]) +  # i32.const 3
        bytes([0x10]) + encode_u32(4) +  # call 4 (three args)
        bytes([0x0B])  # end
    )
    func3_body = func3_locals + func3_code
    code3 = encode_u32(len(func3_body)) + func3_body

    # Function 4: [i32, i32, i32] -> [i32], performs operations
    func4_locals = encode_vector([encode_local_entry(10, bytes([0x7F]))])  # 10 i32 locals
    func4_code = (
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (param 0)
        bytes([0x20]) + encode_u32(1) +  # local.get 1 (param 1)
        bytes([0x6A]) +  # i32.add
        bytes([0x21]) + encode_u32(3) +  # local.set 3
        bytes([0x20]) + encode_u32(3) +  # local.get 3
        bytes([0x20]) + encode_u32(2) +  # local.get 2 (param 2)
        bytes([0x6A]) +  # i32.add
        bytes([0x21]) + encode_u32(4) +  # local.set 4
        bytes([0x20]) + encode_u32(4) +  # local.get 4
        bytes([0x41, 0x64]) +  # i32.const 100
        bytes([0x6A]) +  # i32.add
        bytes([0x0B])  # end (return)
    )
    func4_body = func4_locals + func4_code
    code4 = encode_u32(len(func4_body)) + func4_body

    code_section = make_section(10, encode_vector([code0, code1, code2, code3, code4]))

    # Export section
    export_section = make_section(7, encode_vector([
        encode_name("start") + bytes([0x00]) + encode_u32(0),
        encode_name("helper") + bytes([0x00]) + encode_u32(2),
        encode_name("compute") + bytes([0x00]) + encode_u32(4),
    ]))

    wasm_bytes = make_wasm(type_section, function_section, export_section, code_section)

    # Should decode and validate successfully
    module = decode_and_validate(wasm_bytes)
    assert module is not None
    assert len(module.types) == 4
    assert len(module.functions) == 5
    assert len(module.exports) == 3


def test_complex_large_element_and_data_segments():
    """
    Complex test 3: Large element and data segments with many entries,
    testing vector handling, memory/table initialization, and bounds.
    Tests: large vectors, element segment validation, data segment validation,
    table/memory presence, offset expressions.
    """
    # Type section with one function type
    type_section = make_section(1, encode_vector([encode_functype([], [])]))

    # Function section: 50 functions all of same type
    function_entries = [encode_u32(0) for _ in range(50)]
    function_section = make_section(3, encode_vector(function_entries))

    # Table section: large table
    table_type = bytes([0x70]) + encode_limits(100, 200)  # funcref, min=100, max=200
    table_section = make_section(4, encode_vector([table_type]))

    # Memory section: large memory
    memory_type = encode_limits(10, 20)  # min=10, max=20 pages
    memory_section = make_section(5, encode_vector([memory_type]))

    # Element section: multiple segments filling table
    elem_segment1 = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_vector([encode_u32(i) for i in range(25)])  # 25 function indices
    )
    elem_segment2 = (
        bytes([0x00]) +
        encode_expr_i32_const(25) +
        encode_vector([encode_u32(i) for i in range(25, 50)])  # next 25 indices
    )
    elem_section = make_section(9, encode_vector([elem_segment1, elem_segment2]))

    # Code section: 50 simple function bodies
    code_entries = []
    for i in range(50):
        func_body = encode_vector([]) + bytes([0x0B])  # no locals, just end
        code_entries.append(encode_u32(len(func_body)) + func_body)
    code_section = make_section(10, encode_vector(code_entries))

    # Data section: multiple segments with various data
    data_segment1 = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_u32(256) + (b"A" * 256)  # 256 bytes of 'A'
    )
    data_segment2 = (
        bytes([0x00]) +
        encode_expr_i32_const(256) +
        encode_u32(512) + (b"B" * 512)  # 512 bytes of 'B'
    )
    data_segment3 = (
        bytes([0x00]) +
        encode_expr_i32_const(768) +
        encode_u32(1024) + (bytes(range(256)) * 4)  # 1024 bytes of pattern
    )
    data_section = make_section(11, encode_vector([data_segment1, data_segment2, data_segment3]))

    # Data count section
    data_count_section = make_section(12, encode_u32(3))

    # Export section
    export_section = make_section(7, encode_vector([
        encode_name("func_0") + bytes([0x00]) + encode_u32(0),
        encode_name("func_25") + bytes([0x00]) + encode_u32(25),
        encode_name("func_49") + bytes([0x00]) + encode_u32(49),
        encode_name("table") + bytes([0x01]) + encode_u32(0),
        encode_name("memory") + bytes([0x02]) + encode_u32(0),
    ]))

    wasm_bytes = make_wasm(
        type_section, function_section, table_section, memory_section,
        export_section, elem_section, code_section, data_section, data_count_section
    )

    # Should decode and validate successfully
    module = decode_and_validate(wasm_bytes)
    assert module is not None
    assert len(module.functions) == 50
    assert len(module.tables) == 1
    assert len(module.memories) == 1
    assert len(module.elements) == 2
    assert len(module.data) == 3
    assert len(module.exports) == 5


def test_complex_many_custom_sections_interleaved():
    """
    Complex test 4: Many custom sections interleaved with standard sections,
    testing custom section handling, section ordering, and payload parsing.
    Tests: custom section parsing, section ordering rules, UTF-8 names,
    custom section size limits.
    """
    sections = []

    # Add 10 custom sections before type
    for i in range(10):
        custom = make_section(0, encode_name(f"pre_{i}") + f"data_{i}".encode())
        sections.append(custom)

    # Type section
    sections.append(make_section(1, encode_vector([encode_functype([], [])])))

    # Add 5 custom sections after type
    for i in range(5):
        custom = make_section(0, encode_name(f"post_type_{i}") + f"data_{i}".encode())
        sections.append(custom)

    # Import section (empty)
    sections.append(make_section(2, encode_vector([])))

    # Add 3 custom sections
    for i in range(3):
        custom = make_section(0, encode_name(f"post_import_{i}") + f"data_{i}".encode())
        sections.append(custom)

    # Function section
    sections.append(make_section(3, encode_vector([encode_u32(0)])))

    # Add 2 custom sections
    for i in range(2):
        custom = make_section(0, encode_name(f"post_func_{i}") + f"data_{i}".encode())
        sections.append(custom)

    # Table section
    table_type = bytes([0x70]) + encode_limits(1)
    sections.append(make_section(4, encode_vector([table_type])))

    # Memory section
    sections.append(make_section(5, encode_vector([encode_limits(1)])))

    # Add 7 custom sections
    for i in range(7):
        custom = make_section(0, encode_name(f"mid_{i}") + f"data_{i}".encode())
        sections.append(custom)

    # Global section
    global_entry = bytes([0x7F, 0x00]) + encode_expr_i32_const(0)
    sections.append(make_section(6, encode_vector([global_entry])))

    # Export section
    sections.append(make_section(7, encode_vector([
        encode_name("func") + bytes([0x00]) + encode_u32(0)
    ])))

    # Add 4 custom sections
    for i in range(4):
        custom = make_section(0, encode_name(f"post_export_{i}") + f"data_{i}".encode())
        sections.append(custom)

    # Element section
    elem_segment = bytes([0x00]) + encode_expr_i32_const(0) + encode_vector([encode_u32(0)])
    sections.append(make_section(9, encode_vector([elem_segment])))

    # Code section
    func_body = encode_vector([]) + bytes([0x0B])
    sections.append(make_section(10, encode_vector([encode_u32(len(func_body)) + func_body])))

    # Data section
    data_segment = bytes([0x00]) + encode_expr_i32_const(0) + encode_u32(5) + b"hello"
    sections.append(make_section(11, encode_vector([data_segment])))

    # Data count
    sections.append(make_section(12, encode_u32(1)))

    # Add 15 custom sections at end
    for i in range(15):
        custom = make_section(0, encode_name(f"end_{i}") + f"data_{i}".encode())
        sections.append(custom)

    wasm_bytes = make_wasm(*sections)

    # Should decode and validate successfully
    module = decode_and_validate(wasm_bytes)
    assert module is not None
    # Total: 10 + 5 + 3 + 2 + 7 + 4 + 15 = 46 custom sections
    assert len(module.customs) == 46


# ===== Complex Failure Tests =====

def test_complex_multiple_validation_errors():
    """
    Complex test 5: Module with multiple validation errors across different
    categories (bad indices, duplicate exports, mismatched counts).
    Tests: comprehensive validation, multiple error reporting.
    """
    # Type section with 2 types
    type_section = make_section(1, encode_vector([
        encode_functype([], []),
        encode_functype([bytes([0x7F])], []),
    ]))

    # Function section: 2 functions, one references invalid typeidx
    function_section = make_section(3, encode_vector([
        encode_u32(0),  # valid
        encode_u32(10),  # INVALID: typeidx out of range
    ]))

    # Export section: duplicate names and invalid indices
    export_section = make_section(7, encode_vector([
        encode_name("dup") + bytes([0x00]) + encode_u32(0),  # func 0
        encode_name("dup") + bytes([0x00]) + encode_u32(1),  # INVALID: duplicate name
        encode_name("bad") + bytes([0x01]) + encode_u32(5),  # INVALID: table doesn't exist
        encode_name("worse") + bytes([0x02]) + encode_u32(2),  # INVALID: memory doesn't exist
    ]))

    # Code section: 1 function body (mismatch with 2 functions declared)
    func_body = encode_vector([]) + bytes([0x0B])
    code_section = make_section(10, encode_vector([
        encode_u32(len(func_body)) + func_body
    ]))
    # INVALID: function count (2) != code count (1)

    wasm_bytes = make_wasm(type_section, function_section, export_section, code_section)

    # Decode should succeed
    module = decode_module(wasm_bytes)
    assert module is not None

    # Validate should find multiple errors
    errors = validate_module(module)
    assert len(errors) >= 4  # At least 4 distinct validation errors

    # decode_and_validate should raise
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes)


def test_complex_element_data_without_table_memory():
    """
    Complex test 6: Element and data segments without corresponding table/memory.
    Tests: element/data validation, table/memory existence checking.
    """
    # Type section
    type_section = make_section(1, encode_vector([encode_functype([], [])]))

    # Function section
    function_section = make_section(3, encode_vector([encode_u32(0)]))

    # Element section WITHOUT table section
    elem_segment = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_vector([encode_u32(0)])
    )
    elem_section = make_section(9, encode_vector([elem_segment]))

    # Code section
    func_body = encode_vector([]) + bytes([0x0B])
    code_section = make_section(10, encode_vector([encode_u32(len(func_body)) + func_body]))

    # Data section WITHOUT memory section
    data_segment = (
        bytes([0x00]) +
        encode_expr_i32_const(0) +
        encode_u32(10) + b"0123456789"
    )
    data_section = make_section(11, encode_vector([data_segment]))

    # Data count
    data_count_section = make_section(12, encode_u32(1))

    wasm_bytes = make_wasm(
        type_section, function_section, elem_section,
        code_section, data_section, data_count_section
    )

    # Decode should succeed
    module = decode_module(wasm_bytes)
    assert module is not None

    # Validate should find errors
    errors = validate_module(module)
    assert len(errors) >= 2  # Element without table, data without memory

    # decode_and_validate should raise
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes)


def test_complex_invalid_function_bodies_with_bad_indices():
    """
    Complex test 7: Multiple functions with various invalid local/call indices.
    Tests: local variable bounds, function call bounds, type checking.
    """
    # Type section
    type_section = make_section(1, encode_vector([
        encode_functype([], []),
        encode_functype([bytes([0x7F])], [bytes([0x7F])]),
    ]))

    # Function section: 3 functions
    function_section = make_section(3, encode_vector([
        encode_u32(0),
        encode_u32(1),
        encode_u32(0),
    ]))

    # Code section with invalid operations
    # Function 0: invalid local.get
    func0_body = (
        encode_vector([encode_local_entry(1, bytes([0x7F]))]) +  # 1 local
        bytes([0x20]) + encode_u32(99) +  # INVALID: local.get 99 (doesn't exist)
        bytes([0x21]) + encode_u32(0) +  # local.set 0 (to consume the value)
        bytes([0x0B])
    )
    code0 = encode_u32(len(func0_body)) + func0_body

    # Function 1: invalid call
    func1_body = (
        encode_vector([]) +
        bytes([0x20]) + encode_u32(0) +  # local.get 0 (param)
        bytes([0x10]) + encode_u32(50) +  # INVALID: call 50 (doesn't exist)
        bytes([0x0B])
    )
    code1 = encode_u32(len(func1_body)) + func1_body

    # Function 2: invalid local.set
    func2_body = (
        encode_vector([encode_local_entry(2, bytes([0x7F]))]) +  # 2 locals
        bytes([0x41, 0x0A]) +  # i32.const 10
        bytes([0x21]) + encode_u32(10) +  # INVALID: local.set 10 (only 0-1 exist)
        bytes([0x0B])
    )
    code2 = encode_u32(len(func2_body)) + func2_body

    code_section = make_section(10, encode_vector([code0, code1, code2]))

    wasm_bytes = make_wasm(type_section, function_section, code_section)

    # Decode should succeed
    module = decode_module(wasm_bytes)
    assert module is not None

    # Validate should find multiple errors
    errors = validate_module(module)
    assert len(errors) >= 3  # At least 3 errors (one per function)

    # decode_and_validate should raise
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes)


def test_complex_limits_and_resource_constraints():
    """
    Complex test 8: Test resource limits with large module that pushes boundaries.
    Tests: max_module_bytes, max_section_bytes, max_vector_length, max_function_body_bytes.
    """
    # Create a module that exceeds various limits

    # Test 1: Exceed max_vector_length with many types
    type_entries = [encode_functype([], []) for _ in range(100)]
    type_section = make_section(1, encode_vector(type_entries))

    wasm_bytes = make_wasm(type_section)

    # With small limit, should fail
    limits_small_vector = Limits(max_vector_length=50)
    with pytest.raises(Exception):
        decode_module(wasm_bytes, limits=limits_small_vector)

    # With sufficient limit, should succeed
    limits_ok = Limits(max_vector_length=150)
    module = decode_module(wasm_bytes, limits=limits_ok)
    assert module is not None

    # Test 2: Exceed max_custom_section_bytes (custom sections have their own limit)
    large_custom_payload = encode_name("big") + (b"X" * 10000)
    custom_section = make_section(0, large_custom_payload)
    wasm_bytes_large_section = make_wasm(custom_section)

    limits_small_custom = Limits(max_custom_section_bytes=5000)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_large_section, limits=limits_small_custom)

    # Test 3: Exceed max_module_bytes
    limits_small_module = Limits(max_module_bytes=100)
    with pytest.raises(Exception):
        decode_module(wasm_bytes_large_section, limits=limits_small_module)


def test_complex_start_function_with_invalid_signature():
    """
    Complex test 9: Start function with various invalid signatures in complex module.
    Tests: start function validation, type system integration.
    """
    # Type section with various signatures
    type_section = make_section(1, encode_vector([
        encode_functype([], []),  # type 0: valid for start
        encode_functype([bytes([0x7F])], []),  # type 1: has param (invalid for start)
        encode_functype([], [bytes([0x7F])]),  # type 2: has result (invalid for start)
    ]))

    # Function section: 3 functions
    function_section = make_section(3, encode_vector([
        encode_u32(0),  # func 0: valid signature for start
        encode_u32(1),  # func 1: has param (invalid for start)
        encode_u32(2),  # func 2: has result (invalid for start)
    ]))

    # Code section
    func0_body = encode_vector([]) + bytes([0x0B])
    func1_body = encode_vector([]) + bytes([0x0B])
    func2_body = encode_vector([]) + bytes([0x41, 0x00, 0x0B])  # i32.const 0, end

    code_section = make_section(10, encode_vector([
        encode_u32(len(func0_body)) + func0_body,
        encode_u32(len(func1_body)) + func1_body,
        encode_u32(len(func2_body)) + func2_body,
    ]))

    # Test with func 1 as start (has param - invalid)
    start_section_invalid1 = make_section(8, encode_u32(1))
    wasm_bytes_invalid1 = make_wasm(
        type_section, function_section, start_section_invalid1, code_section
    )

    module = decode_module(wasm_bytes_invalid1)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_invalid1)

    # Test with func 2 as start (has result - invalid)
    start_section_invalid2 = make_section(8, encode_u32(2))
    wasm_bytes_invalid2 = make_wasm(
        type_section, function_section, start_section_invalid2, code_section
    )

    module = decode_module(wasm_bytes_invalid2)
    errors = validate_module(module)
    assert len(errors) > 0
    with pytest.raises(Exception):
        decode_and_validate(wasm_bytes_invalid2)

    # Test with func 0 as start (valid)
    start_section_valid = make_section(8, encode_u32(0))
    wasm_bytes_valid = make_wasm(
        type_section, function_section, start_section_valid, code_section
    )

    module = decode_and_validate(wasm_bytes_valid)
    assert module is not None


def test_complex_mixed_imports_and_locals_with_exports():
    """
    Complex test 10: Mix of imported and local functions/tables/memories/globals
    with complex export relationships.
    Tests: import counting, index space management, export validation.
    """
    # Type section
    type_section = make_section(1, encode_vector([
        encode_functype([], []),
        encode_functype([bytes([0x7F])], [bytes([0x7F])]),
    ]))

    # Import section: 2 functions, 1 table, 1 memory, 2 globals
    import_func1 = encode_name("env") + encode_name("f1") + bytes([0x00]) + encode_u32(0)
    import_func2 = encode_name("env") + encode_name("f2") + bytes([0x00]) + encode_u32(1)
    import_table = encode_name("env") + encode_name("t") + bytes([0x01]) + bytes([0x70]) + encode_limits(5)
    import_mem = encode_name("env") + encode_name("m") + bytes([0x02]) + encode_limits(1)
    import_global1 = encode_name("env") + encode_name("g1") + bytes([0x03]) + bytes([0x7F, 0x00])  # i32, immutable
    import_global2 = encode_name("env") + encode_name("g2") + bytes([0x03]) + bytes([0x7E, 0x00])  # i64, immutable

    import_section = make_section(2, encode_vector([
        import_func1, import_func2, import_table, import_mem, import_global1, import_global2
    ]))

    # Function section: 3 local functions (indices 2, 3, 4)
    function_section = make_section(3, encode_vector([
        encode_u32(0),
        encode_u32(1),
        encode_u32(0),
    ]))

    # Table section: 1 local table (index 1)
    table_section = make_section(4, encode_vector([
        bytes([0x70]) + encode_limits(10, 20)
    ]))

    # Memory section: 1 local memory (index 1)
    memory_section = make_section(5, encode_vector([encode_limits(2, 4)]))

    # Global section: 2 local globals (indices 2, 3)
    global_section = make_section(6, encode_vector([
        bytes([0x7F, 0x01]) + encode_expr_i32_const(100),  # i32, mutable
        bytes([0x7E, 0x00]) + encode_expr_i32_const(200),  # i64, immutable
    ]))

    # Export section: export various combinations
    export_section = make_section(7, encode_vector([
        encode_name("imported_func") + bytes([0x00]) + encode_u32(0),  # import func 0
        encode_name("local_func") + bytes([0x00]) + encode_u32(2),  # local func (index 2)
        encode_name("imported_table") + bytes([0x01]) + encode_u32(0),  # import table
        encode_name("local_table") + bytes([0x01]) + encode_u32(1),  # local table
        encode_name("imported_mem") + bytes([0x02]) + encode_u32(0),  # import memory
        encode_name("local_mem") + bytes([0x02]) + encode_u32(1),  # local memory
        encode_name("imported_global") + bytes([0x03]) + encode_u32(1),  # import global 1
        encode_name("local_global") + bytes([0x03]) + encode_u32(2),  # local global (index 2)
    ]))

    # Code section: 3 function bodies
    code_entries = []
    for i in range(3):
        func_body = encode_vector([]) + bytes([0x0B])
        code_entries.append(encode_u32(len(func_body)) + func_body)
    code_section = make_section(10, encode_vector(code_entries))

    wasm_bytes = make_wasm(
        type_section, import_section, function_section, table_section,
        memory_section, global_section, export_section, code_section
    )

    # Should decode and validate successfully
    module = decode_and_validate(wasm_bytes)
    assert module is not None
    assert len(module.imports) == 6
    assert len(module.functions) == 3
    assert len(module.tables) == 1
    assert len(module.memories) == 1
    assert len(module.globals) == 2
    assert len(module.exports) == 8
