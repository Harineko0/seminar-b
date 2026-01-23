"""
test_complex.py - More complex WASM module tests.

Tests for advanced features like imports, tables, memory, globals, etc.
"""

from parser import decode_module, validate_module, DecodeError


def build_section(section_id: int, payload: bytes) -> bytes:
    """Helper to build a section with proper length encoding."""
    return bytes([section_id, len(payload)]) + payload


def test_module_with_imports():
    """Test module with function import."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Type section: [i32] -> [i32]
    type_payload = b"\x01"  # 1 type
    type_payload += b"\x60"  # functype
    type_payload += b"\x01\x7F"  # params: [i32]
    type_payload += b"\x01\x7F"  # results: [i32]
    data += build_section(1, type_payload)

    # Import section: import "env"."add" as function type 0
    import_payload = b"\x01"  # 1 import
    import_payload += b"\x03env"  # module name
    import_payload += b"\x03add"  # field name
    import_payload += b"\x00"  # import kind: func
    import_payload += b"\x00"  # typeidx 0
    data += build_section(2, import_payload)

    module = decode_module(data)
    assert len(module.imports) == 1
    assert module.imports[0].module == b"env"
    assert module.imports[0].name == b"add"
    assert module.imports[0].desc.kind == 0
    assert module.imports[0].desc.typeidx == 0

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with imports test passed")


def test_module_with_table():
    """Test module with table definition."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Table section: funcref, min=1, max=10
    table_payload = b"\x01"  # 1 table
    table_payload += b"\x70"  # funcref
    table_payload += b"\x01"  # limits flag (has max)
    table_payload += b"\x01"  # min = 1
    table_payload += b"\x0A"  # max = 10
    data += build_section(4, table_payload)

    module = decode_module(data)
    assert len(module.tables) == 1
    assert module.tables[0].limits.min == 1
    assert module.tables[0].limits.max == 10

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with table test passed")


def test_module_with_memory():
    """Test module with memory definition."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Memory section: min=1, max=5
    memory_payload = b"\x01"  # 1 memory
    memory_payload += b"\x01"  # limits flag (has max)
    memory_payload += b"\x01"  # min = 1
    memory_payload += b"\x05"  # max = 5
    data += build_section(5, memory_payload)

    module = decode_module(data)
    assert len(module.memories) == 1
    assert module.memories[0].limits.min == 1
    assert module.memories[0].limits.max == 5

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with memory test passed")


def test_module_with_global():
    """Test module with global definition."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Global section: i32, mutable, init with i32.const 42
    global_payload = b"\x01"  # 1 global
    global_payload += b"\x7F"  # valtype: i32
    global_payload += b"\x01"  # mutable
    global_payload += b"\x41"  # i32.const
    global_payload += b"\x2A"  # 42
    global_payload += b"\x0B"  # end
    data += build_section(6, global_payload)

    module = decode_module(data)
    assert len(module.globals) == 1
    assert module.globals[0].type.valtype == 0x7F
    assert module.globals[0].type.mutable == True
    assert len(module.globals[0].init.instructions) == 1
    assert module.globals[0].init.instructions[0].opcode == 0x41
    assert module.globals[0].init.instructions[0].immediate == 42

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with global test passed")


def test_module_with_start_function():
    """Test module with start function."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Type section: [] -> []
    data += build_section(1, b"\x01\x60\x00\x00")

    # Function section: 1 function
    data += build_section(3, b"\x01\x00")

    # Start section: function 0
    data += build_section(8, b"\x00")

    # Code section: empty function
    code_payload = b"\x01"  # 1 code entry
    code_payload += b"\x02"  # body size
    code_payload += b"\x00"  # 0 locals
    code_payload += b"\x0B"  # end
    data += build_section(10, code_payload)

    module = decode_module(data)
    assert module.start == 0

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with start function test passed")


def test_module_with_element_segment():
    """Test module with element segment."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Type section
    data += build_section(1, b"\x01\x60\x00\x00")

    # Function section: 2 functions (must come before table!)
    data += build_section(3, b"\x02\x00\x00")

    # Table section
    table_payload = b"\x01\x70\x00\x0A"  # 1 table, funcref, min=10
    data += build_section(4, table_payload)

    # Element section: init table 0 at offset 0 with [0, 1]
    elem_payload = b"\x01"  # 1 element
    elem_payload += b"\x00"  # tableidx 0
    elem_payload += b"\x41\x00\x0B"  # offset: i32.const 0, end
    elem_payload += b"\x02"  # 2 funcidx
    elem_payload += b"\x00\x01"  # funcidx 0, 1
    data += build_section(9, elem_payload)

    # Code section: 2 empty functions
    code_payload = b"\x02"  # 2 code entries
    code_payload += b"\x02\x00\x0B"  # body 1
    code_payload += b"\x02\x00\x0B"  # body 2
    data += build_section(10, code_payload)

    module = decode_module(data)
    assert len(module.elements) == 1
    assert module.elements[0].tableidx == 0
    assert len(module.elements[0].init) == 2
    assert module.elements[0].init == [0, 1]

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with element segment test passed")


def test_module_with_data_segment():
    """Test module with data segment."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Memory section
    memory_payload = b"\x01\x00\x01"  # 1 memory, min=1
    data += build_section(5, memory_payload)

    # Data section: init memory 0 at offset 0 with "hello"
    data_payload = b"\x01"  # 1 data segment
    data_payload += b"\x00"  # memidx 0
    data_payload += b"\x41\x00\x0B"  # offset: i32.const 0, end
    data_payload += b"\x05hello"  # 5 bytes: "hello"
    data += build_section(11, data_payload)

    module = decode_module(data)
    assert len(module.data) == 1
    assert module.data[0].memidx == 0
    assert module.data[0].init == b"hello"

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with data segment test passed")


def test_module_with_data_count():
    """Test module with data count section."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Memory section
    data += build_section(5, b"\x01\x00\x01")

    # Data section: 1 segment (comes before data count!)
    data_payload = b"\x01\x00\x41\x00\x0B\x03foo"
    data += build_section(11, data_payload)

    # Data count section: 1 data segment
    data += build_section(12, b"\x01")

    module = decode_module(data)
    assert module.data_count == 1
    assert len(module.data) == 1

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with data count test passed")


def test_module_with_custom_section():
    """Test module with custom section."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Custom section: name="test", data="custom data"
    custom_payload = b"\x04test"  # name length + name
    custom_payload += b"custom data"  # arbitrary data
    data += build_section(0, custom_payload)

    module = decode_module(data)
    assert len(module.customs) == 1
    assert module.customs[0].name == b"test"
    assert module.customs[0].data == b"custom data"

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Module with custom section test passed")


def test_complex_function_with_locals():
    """Test function with local variables and instructions."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Type section: [i32, i32] -> [i32]
    type_payload = b"\x01\x60\x02\x7F\x7F\x01\x7F"
    data += build_section(1, type_payload)

    # Function section
    data += build_section(3, b"\x01\x00")

    # Code section: function with locals and instructions
    code_payload = b"\x01"  # 1 code entry
    # Function body:
    # - 2 locals of type i32
    # - local.get 0
    # - local.get 1
    # - i32.add
    # - local.set 2
    # - local.get 2
    # - end
    body = b"\x01"  # 1 local declaration
    body += b"\x02"  # count: 2
    body += b"\x7F"  # type: i32
    body += b"\x20\x00"  # local.get 0
    body += b"\x20\x01"  # local.get 1
    body += b"\x6A"      # i32.add
    body += b"\x21\x02"  # local.set 2
    body += b"\x20\x02"  # local.get 2
    body += b"\x0B"      # end

    code_payload += bytes([len(body)])  # body size
    code_payload += body
    data += build_section(10, code_payload)

    module = decode_module(data)
    assert len(module.code) == 1
    assert len(module.code[0].locals) == 1
    assert module.code[0].locals[0] == (2, 0x7F)
    # Instructions: local.get 0, local.get 1, i32.add, local.set 2, local.get 2
    # (end is not included in the instructions list)
    assert len(module.code[0].body.instructions) == 5

    errors = validate_module(module)
    assert len(errors) == 0
    print("✓ Complex function with locals test passed")


def test_invalid_table_limits():
    """Test that invalid table limits are caught."""
    data = b"\x00asm\x01\x00\x00\x00"

    # Table with min > max
    table_payload = b"\x01\x70\x01\x0A\x05"  # min=10, max=5
    data += build_section(4, table_payload)

    module = decode_module(data)
    errors = validate_module(module)

    assert any(e.code == "limits_min_gt_max" for e in errors)
    print("✓ Invalid table limits test passed")


if __name__ == "__main__":
    test_module_with_imports()
    test_module_with_table()
    test_module_with_memory()
    test_module_with_global()
    test_module_with_start_function()
    test_module_with_element_segment()
    test_module_with_data_segment()
    test_module_with_data_count()
    test_module_with_custom_section()
    test_complex_function_with_locals()
    test_invalid_table_limits()
    print("\n✅ All complex tests passed!")
