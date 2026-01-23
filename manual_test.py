"""Manual test script to verify wasm_sv implementation."""

from parser import decode_module, validate_module, decode_and_validate, DecodeError, Limits

def test_minimal_module():
    """Test minimal valid WASM module."""
    print("Test 1: Minimal module...")
    wasm_bytes = b"\x00asm\x01\x00\x00\x00"
    module = decode_and_validate(wasm_bytes)
    assert module.raw_size == 8
    assert len(module.types) == 0
    print("  ✓ Minimal module passed")

def test_invalid_magic():
    """Test invalid magic bytes."""
    print("Test 2: Invalid magic...")
    wasm_bytes = b"\x00bad\x01\x00\x00\x00"
    try:
        decode_module(wasm_bytes)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert "magic" in e.message.lower()
        print("  ✓ Invalid magic rejected")

def test_invalid_version():
    """Test invalid version."""
    print("Test 3: Invalid version...")
    wasm_bytes = b"\x00asm\x02\x00\x00\x00"
    try:
        decode_module(wasm_bytes)
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert "version" in e.message.lower()
        print("  ✓ Invalid version rejected")

def test_type_section():
    """Test type section decoding."""
    print("Test 4: Type section...")
    # Magic + Version
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Section 1 (Type)
    wasm.append(0x01)  # section id
    # Payload: vec<functype> with 1 entry: [] -> []
    payload = bytearray()
    payload.append(0x01)  # vector length = 1
    payload.append(0x60)  # functype tag
    payload.append(0x00)  # params length = 0
    payload.append(0x00)  # results length = 0

    wasm.append(len(payload))  # payload length
    wasm.extend(payload)

    module = decode_and_validate(bytes(wasm))
    assert len(module.types) == 1
    assert len(module.types[0].params) == 0
    assert len(module.types[0].results) == 0
    print("  ✓ Type section passed")

def test_function_and_code():
    """Test function and code sections."""
    print("Test 5: Function and code sections...")
    # Magic + Version
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Section 1 (Type): one function type [] -> []
    wasm.append(0x01)
    payload = bytearray([0x01, 0x60, 0x00, 0x00])
    wasm.append(len(payload))
    wasm.extend(payload)

    # Section 3 (Function): one function with typeidx=0
    wasm.append(0x03)
    payload = bytearray([0x01, 0x00])  # vec with 1 entry, typeidx=0
    wasm.append(len(payload))
    wasm.extend(payload)

    # Section 10 (Code): one empty function body
    wasm.append(0x0A)
    body = bytearray()
    body.append(0x00)  # locals vec length = 0
    body.append(0x0B)  # end instruction

    payload = bytearray()
    payload.append(len(body))  # body size
    payload.extend(body)
    payload = bytearray([0x01]) + payload  # vec with 1 entry

    wasm.append(len(payload))
    wasm.extend(payload)

    module = decode_and_validate(bytes(wasm))
    assert len(module.function_types) == 1
    assert len(module.code) == 1
    print("  ✓ Function and code sections passed")

def test_validation_errors():
    """Test validation error detection."""
    print("Test 6: Validation errors...")
    # Magic + Version
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Section 1 (Type): one function type
    wasm.append(0x01)
    payload = bytearray([0x01, 0x60, 0x00, 0x00])
    wasm.append(len(payload))
    wasm.extend(payload)

    # Section 3 (Function): one function with INVALID typeidx=5
    wasm.append(0x03)
    payload = bytearray([0x01, 0x05])
    wasm.append(len(payload))
    wasm.extend(payload)

    module = decode_module(bytes(wasm))
    errors = validate_module(module)
    assert len(errors) > 0
    assert any("type_index_out_of_range" in e.code for e in errors)
    print("  ✓ Validation errors detected")

def test_duplicate_export_names():
    """Test duplicate export name detection."""
    print("Test 7: Duplicate export names...")
    # Magic + Version
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Section 1 (Type)
    wasm.append(0x01)
    payload = bytearray([0x01, 0x60, 0x00, 0x00])
    wasm.append(len(payload))
    wasm.extend(payload)

    # Section 3 (Function)
    wasm.append(0x03)
    payload = bytearray([0x01, 0x00])
    wasm.append(len(payload))
    wasm.extend(payload)

    # Section 7 (Export): two exports with same name
    wasm.append(0x07)
    payload = bytearray()
    payload.append(0x02)  # 2 exports
    # Export 1
    name = b"test"
    payload.append(len(name))
    payload.extend(name)
    payload.append(0x00)  # func kind
    payload.append(0x00)  # index 0
    # Export 2 (same name)
    payload.append(len(name))
    payload.extend(name)
    payload.append(0x00)  # func kind
    payload.append(0x00)  # index 0

    wasm.append(len(payload))
    wasm.extend(payload)

    # Section 10 (Code)
    wasm.append(0x0A)
    body = bytearray([0x00, 0x0B])
    payload = bytearray([0x01, len(body)]) + body
    wasm.append(len(payload))
    wasm.extend(payload)

    module = decode_module(bytes(wasm))
    errors = validate_module(module)
    assert any("duplicate_export_name" in e.code for e in errors)
    print("  ✓ Duplicate export names detected")

def test_limits_enforcement():
    """Test resource limits."""
    print("Test 8: Resource limits...")
    wasm_bytes = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 100

    try:
        decode_module(wasm_bytes, limits=Limits(max_module_bytes=10))
        assert False, "Should have raised DecodeError"
    except DecodeError as e:
        assert "limit" in e.message.lower()
        print("  ✓ Module size limit enforced")

def main():
    print("Running manual tests for wasm_sv...\n")

    test_minimal_module()
    test_invalid_magic()
    test_invalid_version()
    test_type_section()
    test_function_and_code()
    test_validation_errors()
    test_duplicate_export_names()
    test_limits_enforcement()

    print("\n✅ All tests passed!")

if __name__ == "__main__":
    main()
