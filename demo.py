"""Demo script showing wasm_sv capabilities."""

from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits
)


def demo_minimal_module():
    """Decode a minimal valid WASM module."""
    print("=" * 60)
    print("Demo 1: Minimal Valid Module")
    print("=" * 60)

    # Minimal module: just magic + version
    minimal = b'\x00asm\x01\x00\x00\x00'

    module = decode_and_validate(minimal)
    print(f"✓ Decoded minimal module: {module.raw_size} bytes")
    print(f"  - Types: {len(module.types)}")
    print(f"  - Functions: {len(module.function_typeidxs)}")
    print(f"  - Exports: {len(module.exports)}")
    print()


def demo_invalid_magic():
    """Show decode error for invalid magic."""
    print("=" * 60)
    print("Demo 2: Invalid Magic Detection")
    print("=" * 60)

    bad_magic = b'\x00BAD\x01\x00\x00\x00'

    try:
        decode_module(bad_magic)
        print("✗ Should have raised DecodeError")
    except DecodeError as e:
        print(f"✓ Caught DecodeError: {e.message}")
        print(f"  - Error code: {e.code}")
        print(f"  - Offset: {e.offset}")
    print()


def demo_validation_error():
    """Show validation error for duplicate exports."""
    print("=" * 60)
    print("Demo 3: Validation Error Detection")
    print("=" * 60)

    # Module with duplicate export names
    # (using raw bytes for simplicity)
    def encode_u32(v):
        """Simple LEB128 encoding for demo."""
        result = []
        while True:
            byte = v & 0x7F
            v >>= 7
            if v != 0:
                result.append(byte | 0x80)
            else:
                result.append(byte)
                break
        return bytes(result)

    # Type section: () -> ()
    type_payload = encode_u32(1) + b'\x60\x00\x00'

    # Function section: 2 functions
    func_payload = encode_u32(2) + encode_u32(0) + encode_u32(0)

    # Export section: both named "test"
    export1 = encode_u32(4) + b'test' + b'\x00' + encode_u32(0)
    export2 = encode_u32(4) + b'test' + b'\x00' + encode_u32(1)
    export_payload = encode_u32(2) + export1 + export2

    # Code section: 2 empty functions
    code_body = encode_u32(0) + b'\x0B'
    code_payload = encode_u32(2)
    code_payload += encode_u32(len(code_body)) + code_body
    code_payload += encode_u32(len(code_body)) + code_body

    module_bytes = b'\x00asm\x01\x00\x00\x00'
    module_bytes += b'\x01' + encode_u32(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32(len(func_payload)) + func_payload
    module_bytes += b'\x07' + encode_u32(len(export_payload)) + export_payload
    module_bytes += b'\x0A' + encode_u32(len(code_payload)) + code_payload

    module = decode_module(module_bytes)
    errors = validate_module(module)

    print(f"✓ Found {len(errors)} validation error(s):")
    for err in errors:
        print(f"  - {err.code}: {err.message}")
    print()


def demo_resource_limits():
    """Show resource limit enforcement."""
    print("=" * 60)
    print("Demo 4: Resource Limits")
    print("=" * 60)

    # Try with very small limit
    small_limits = Limits(max_module_bytes=16)

    # Create a module that exceeds the limit
    large_module = b'\x00asm\x01\x00\x00\x00' + b'\x00' * 100

    try:
        decode_module(large_module, limits=small_limits)
        print("✗ Should have raised DecodeError")
    except DecodeError as e:
        print(f"✓ Resource limit enforced: {e.message}")
    print()


def demo_complex_module():
    """Decode a more complex module."""
    print("=" * 60)
    print("Demo 5: Complex Module")
    print("=" * 60)

    def encode_u32(v):
        result = []
        while True:
            byte = v & 0x7F
            v >>= 7
            if v != 0:
                result.append(byte | 0x80)
            else:
                result.append(byte)
                break
        return bytes(result)

    def encode_s32(v):
        result = []
        more = True
        while more:
            byte = v & 0x7F
            v >>= 7
            if (v == 0 and (byte & 0x40) == 0) or (v == -1 and (byte & 0x40) != 0):
                more = False
            else:
                byte |= 0x80
            result.append(byte)
        return bytes(result)

    # Type section: (i32) -> (i32)
    type_payload = encode_u32(1)
    type_payload += b'\x60' + encode_u32(1) + b'\x7F' + encode_u32(1) + b'\x7F'

    # Function section: 1 function with type 0
    func_payload = encode_u32(1) + encode_u32(0)

    # Export section: export as "increment"
    export_payload = encode_u32(1)
    export_payload += encode_u32(9) + b'increment'
    export_payload += b'\x00' + encode_u32(0)

    # Code section: local.get 0, i32.const 1, i32.add, end
    code_body = encode_u32(0)  # no locals
    code_body += b'\x20' + encode_u32(0)  # local.get 0
    code_body += b'\x41' + encode_s32(1)  # i32.const 1
    code_body += b'\x6A'  # i32.add
    code_body += b'\x0B'  # end

    code_payload = encode_u32(1) + encode_u32(len(code_body)) + code_body

    # Build module
    module_bytes = b'\x00asm\x01\x00\x00\x00'
    module_bytes += b'\x01' + encode_u32(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32(len(func_payload)) + func_payload
    module_bytes += b'\x07' + encode_u32(len(export_payload)) + export_payload
    module_bytes += b'\x0A' + encode_u32(len(code_payload)) + code_payload

    module = decode_and_validate(module_bytes)

    print(f"✓ Decoded complex module ({module.raw_size} bytes)")
    print(f"  - Types: {len(module.types)}")
    print(f"    - Type 0: {module.types[0].params} -> {module.types[0].results}")
    print(f"  - Functions: {len(module.function_typeidxs)}")
    print(f"  - Exports: {len(module.exports)}")
    print(f"    - Export 0: '{module.exports[0].name.decode()}' (kind={module.exports[0].kind}, idx={module.exports[0].index})")
    print(f"  - Code:")
    print(f"    - Function 0: {len(module.code[0].expr)} instructions")
    for i, instr in enumerate(module.code[0].expr):
        opcode_names = {0x20: 'local.get', 0x41: 'i32.const', 0x6A: 'i32.add', 0x0B: 'end'}
        name = opcode_names.get(instr.opcode, f'0x{instr.opcode:02x}')
        if instr.immediate is not None:
            print(f"      [{i}] {name} {instr.immediate}")
        else:
            print(f"      [{i}] {name}")
    print()


if __name__ == "__main__":
    print()
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + " " * 15 + "WASM_SV DEMO" + " " * 31 + "║")
    print("║" + " " * 10 + "WebAssembly Parser & Validator" + " " * 18 + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "═" * 58 + "╝")
    print()

    demo_minimal_module()
    demo_invalid_magic()
    demo_validation_error()
    demo_resource_limits()
    demo_complex_module()

    print("=" * 60)
    print("All demos completed successfully!")
    print("=" * 60)
    print()
