"""Integration tests for wasm_sv implementation."""

from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module, ValType
)


def encode_u32_leb128(value: int) -> bytes:
    """Encode u32 as unsigned LEB128."""
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def encode_s32_leb128(value: int) -> bytes:
    """Encode s32 as signed LEB128."""
    result = []
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7

        # Sign extend
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80

        result.append(byte)

    return bytes(result)


WASM_MAGIC = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'


def test_complex_valid_module():
    """Test a complex but valid WASM module with multiple sections."""

    # Type section: [(i32) -> (i32), () -> ()]
    type_payload = encode_u32_leb128(2)
    # Type 0: (i32) -> (i32)
    type_payload += b'\x60' + encode_u32_leb128(1) + b'\x7F' + encode_u32_leb128(1) + b'\x7F'
    # Type 1: () -> ()
    type_payload += b'\x60' + encode_u32_leb128(0) + encode_u32_leb128(0)

    # Import section: import one function "env.log" with type 1
    import_payload = encode_u32_leb128(1)
    import_payload += encode_u32_leb128(3) + b'env'
    import_payload += encode_u32_leb128(3) + b'log'
    import_payload += b'\x00'  # func kind
    import_payload += encode_u32_leb128(1)  # typeidx

    # Function section: 2 functions with types [0, 1]
    func_payload = encode_u32_leb128(2)
    func_payload += encode_u32_leb128(0)  # func 0 has type 0
    func_payload += encode_u32_leb128(1)  # func 1 has type 1

    # Export section: export func 1 (imported) and func 2 (defined index 1)
    export_payload = encode_u32_leb128(2)
    # Export "log"
    export_payload += encode_u32_leb128(3) + b'log'
    export_payload += b'\x00' + encode_u32_leb128(0)  # func 0 (imported)
    # Export "add"
    export_payload += encode_u32_leb128(3) + b'add'
    export_payload += b'\x00' + encode_u32_leb128(1)  # func 1 (defined)

    # Code section: 2 function bodies
    code_payload = encode_u32_leb128(2)

    # Function 0 (type 0: i32 -> i32): local.get 0, i32.const 1, i32.add, end
    code_body_0 = encode_u32_leb128(0)  # no locals
    code_body_0 += b'\x20' + encode_u32_leb128(0)  # local.get 0
    code_body_0 += b'\x41' + encode_s32_leb128(1)  # i32.const 1
    code_body_0 += b'\x6A'  # i32.add
    code_body_0 += b'\x0B'  # end
    code_payload += encode_u32_leb128(len(code_body_0)) + code_body_0

    # Function 1 (type 1: () -> ()): just end
    code_body_1 = encode_u32_leb128(0)  # no locals
    code_body_1 += b'\x0B'  # end
    code_payload += encode_u32_leb128(len(code_body_1)) + code_body_1

    # Build module
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x02' + encode_u32_leb128(len(import_payload)) + import_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload
    module_bytes += b'\x07' + encode_u32_leb128(len(export_payload)) + export_payload
    module_bytes += b'\x0A' + encode_u32_leb128(len(code_payload)) + code_payload

    # Decode and validate
    module = decode_and_validate(module_bytes)

    # Verify structure
    assert len(module.types) == 2
    assert module.types[0].params == [ValType.I32]
    assert module.types[0].results == [ValType.I32]
    assert module.types[1].params == []
    assert module.types[1].results == []

    assert len(module.imports) == 1
    assert len(module.function_typeidxs) == 2
    assert len(module.exports) == 2
    assert len(module.code) == 2

    # Check code
    assert len(module.code[0].expr) == 4  # local.get, i32.const, i32.add, end
    assert module.code[0].expr[0].opcode == 0x20  # local.get
    assert module.code[0].expr[1].opcode == 0x41  # i32.const
    assert module.code[0].expr[2].opcode == 0x6A  # i32.add

    print("Complex module test passed!")


def test_validation_errors():
    """Test that validation errors are properly detected."""

    # Build a module with an out-of-range export
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Export function 99 (doesn't exist)
    export_payload = encode_u32_leb128(1)
    export_payload += encode_u32_leb128(4) + b'test'
    export_payload += b'\x00' + encode_u32_leb128(99)

    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x07' + encode_u32_leb128(len(export_payload)) + export_payload

    module = decode_module(module_bytes)
    errors = validate_module(module)

    assert len(errors) > 0
    assert any(e.code == "index_out_of_range" for e in errors)

    print("Validation error test passed!")


def test_decode_errors():
    """Test that decode errors are properly raised."""

    # Bad magic
    try:
        decode_module(b'\x00BAD\x01\x00\x00\x00')
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "bad_magic"

    # Bad version
    try:
        decode_module(b'\x00asm\x02\x00\x00\x00')
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "bad_version"

    # Section out of order
    module_bytes = WASM_MAGIC + WASM_VERSION
    # Export (7) before Function (3)
    export_payload = encode_u32_leb128(0)  # empty export section
    func_payload = encode_u32_leb128(0)    # empty function section

    module_bytes += b'\x07' + encode_u32_leb128(len(export_payload)) + export_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload

    try:
        decode_module(module_bytes)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert e.code == "section_order"

    print("Decode error test passed!")


def test_resource_limits():
    """Test that resource limits are enforced."""

    # Try to create a module larger than limit
    limits = Limits(max_module_bytes=16)

    # Valid module structure but too large
    large_section = b'\x00' * 100  # Custom section
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x00' + encode_u32_leb128(len(large_section)) + large_section

    try:
        decode_module(module_bytes, limits=limits)
        assert False, "Should have raised DecodeError for size limit"
    except DecodeError:
        pass  # Expected

    print("Resource limits test passed!")


if __name__ == "__main__":
    test_complex_valid_module()
    test_validation_errors()
    test_decode_errors()
    test_resource_limits()
    print("\nAll integration tests passed!")
