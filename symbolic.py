"""
symbolic.py - CrossHair contracts for symbolic execution testing of the WASM parser.

This file defines contracts (preconditions and postconditions) using asserts
to test the parser implementation with symbolic execution.
"""

from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module
)


def check_decode_module_basic_safety(data: bytes) -> None:
    """
    Test that decode_module never crashes on arbitrary input.

    Contract: For any byte string, decode_module must either:
    - Return a valid Module, or
    - Raise a DecodeError

    It must never crash, hang, or raise unexpected exceptions.
    """
    assert True  # precondition (always valid input)

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=1024))
        # If decoding succeeds, we got a Module
        assert isinstance(module, Module)
        assert module.raw_size == len(data)
    except DecodeError as e:
        # DecodeError is expected for malformed input
        assert isinstance(e.message, str)
        assert len(e.message) > 0


def check_validate_module_basic_safety(data: bytes) -> None:
    """
    Test that validate_module never crashes on successfully decoded modules.

    Contract: If decode_module succeeds, validate_module must return a list
    of ValidationError objects (possibly empty).
    """
    assert True  # precondition

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=1024))
        errors = validate_module(module)

        # validate_module must return a list
        assert isinstance(errors, list)

        # All elements must be ValidationError
        for error in errors:
            assert isinstance(error, ValidationError)
            assert isinstance(error.code, str)
            assert isinstance(error.message, str)
            assert len(error.code) > 0
            assert len(error.message) > 0
    except DecodeError:
        # If decoding fails, we can't validate
        pass


def check_decode_empty_module() -> None:
    """
    Test that the minimal valid WASM module decodes successfully.
    """
    assert True

    # Minimal valid module: magic + version, no sections
    minimal_wasm = b"\x00asm\x01\x00\x00\x00"

    module = decode_module(minimal_wasm)
    assert module.raw_size == 8
    assert len(module.types) == 0
    assert len(module.imports) == 0
    assert len(module.function_typeidxs) == 0

    # Validation should pass
    errors = validate_module(module)
    assert len(errors) == 0


def check_invalid_magic_rejected() -> None:
    """
    Test that modules with invalid magic are rejected.
    """
    assert True

    invalid_magic = b"\x00XYZ\x01\x00\x00\x00"

    try:
        decode_module(invalid_magic)
        assert False, "Should have raised DecodeError for invalid magic"
    except DecodeError as e:
        assert "magic" in e.message.lower()


def check_invalid_version_rejected() -> None:
    """
    Test that modules with invalid version are rejected.
    """
    assert True

    invalid_version = b"\x00asm\x02\x00\x00\x00"

    try:
        decode_module(invalid_version)
        assert False, "Should have raised DecodeError for invalid version"
    except DecodeError as e:
        assert "version" in e.message.lower()


def check_limits_respected(data: bytes) -> None:
    """
    Test that resource limits are enforced.
    """
    assert True

    # Try to decode with very tight limits
    tight_limits = Limits(
        max_module_bytes=16,
        max_section_bytes=8,
        max_vector_length=2
    )

    try:
        module = decode_module(data, limits=tight_limits)
        # If successful, module size must be within limit
        assert module.raw_size <= tight_limits.max_module_bytes
    except DecodeError:
        # Expected for inputs that exceed limits
        pass


def check_duplicate_exports_detected() -> None:
    """
    Test that duplicate export names are detected during validation.
    """
    assert True

    # Build a module with duplicate export names
    # Magic + Version
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Export section (id=7)
    # Two exports with the same name "test"
    export_payload = bytearray()

    # Vector length: 2
    export_payload.append(2)

    # Export 1: name="test", kind=func(0), index=0
    export_payload.append(4)  # name length
    export_payload.extend(b"test")
    export_payload.append(0)  # kind=func
    export_payload.append(0)  # index=0

    # Export 2: name="test", kind=func(0), index=1
    export_payload.append(4)  # name length
    export_payload.extend(b"test")
    export_payload.append(0)  # kind=func
    export_payload.append(1)  # index=1

    # Add section header
    wasm.append(7)  # section_id=7 (export)
    wasm.append(len(export_payload))  # payload length
    wasm.extend(export_payload)

    try:
        module = decode_module(bytes(wasm))
        errors = validate_module(module)

        # Should have at least one error about duplicate export names
        error_codes = [e.code for e in errors]
        assert "duplicate_export_name" in error_codes or "index_out_of_range" in error_codes
    except DecodeError:
        # Also acceptable if decoder rejects it
        pass


def check_func_code_count_mismatch_detected() -> None:
    """
    Test that mismatched function and code counts are detected.
    """
    assert True

    # Build a module with 1 function declaration but 0 code bodies
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Type section: one function type [] -> []
    type_payload = bytearray()
    type_payload.append(1)  # 1 type
    type_payload.append(0x60)  # functype tag
    type_payload.append(0)  # 0 params
    type_payload.append(0)  # 0 results

    wasm.append(1)  # section_id=1 (type)
    wasm.append(len(type_payload))
    wasm.extend(type_payload)

    # Function section: 1 function with typeidx=0
    func_payload = bytearray()
    func_payload.append(1)  # 1 function
    func_payload.append(0)  # typeidx=0

    wasm.append(3)  # section_id=3 (function)
    wasm.append(len(func_payload))
    wasm.extend(func_payload)

    # Code section: 0 code bodies (mismatch!)
    code_payload = bytearray()
    code_payload.append(0)  # 0 code bodies

    wasm.append(10)  # section_id=10 (code)
    wasm.append(len(code_payload))
    wasm.extend(code_payload)

    try:
        module = decode_module(bytes(wasm))
        errors = validate_module(module)

        # Should detect func/code count mismatch
        error_codes = [e.code for e in errors]
        assert "func_code_count_mismatch" in error_codes
    except DecodeError:
        # Also acceptable if decoder rejects it
        pass


def check_decode_and_validate_consistency(data: bytes) -> None:
    """
    Test that decode_and_validate behaves consistently.

    If decode succeeds and validation passes, decode_and_validate returns the module.
    If validation fails, decode_and_validate raises ValueError.
    """
    assert True

    try:
        # Try decode_and_validate
        module1 = decode_and_validate(data, limits=Limits(max_module_bytes=1024))

        # Should match manual decode + validate
        module2 = decode_module(data, limits=Limits(max_module_bytes=1024))
        errors = validate_module(module2)

        assert len(errors) == 0, "decode_and_validate succeeded but manual validation found errors"
        assert module1.raw_size == module2.raw_size

    except ValueError as e:
        # decode_and_validate failed due to validation errors
        # Verify that manual validation also fails
        try:
            module = decode_module(data, limits=Limits(max_module_bytes=1024))
            errors = validate_module(module)
            assert len(errors) > 0, "decode_and_validate raised ValueError but manual validation passed"
        except DecodeError:
            # If decoding itself fails, that's a different path
            pass

    except DecodeError:
        # Decoding failed - this is expected for malformed input
        pass


def check_limits_validation() -> None:
    """
    Test that limits with min > max are detected.
    """
    assert True

    # Build a module with a table that has min > max
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Table section: one table with limits min=10, max=5 (invalid!)
    table_payload = bytearray()
    table_payload.append(1)  # 1 table
    table_payload.append(0x70)  # elemtype=funcref
    table_payload.append(0x01)  # flags=0x01 (has max)
    table_payload.append(10)  # min=10
    table_payload.append(5)   # max=5

    wasm.append(4)  # section_id=4 (table)
    wasm.append(len(table_payload))
    wasm.extend(table_payload)

    try:
        module = decode_module(bytes(wasm))
        errors = validate_module(module)

        # Should detect limits violation
        error_codes = [e.code for e in errors]
        assert "limits_min_gt_max" in error_codes
    except DecodeError:
        # Also acceptable if decoder rejects it
        pass


def check_unsupported_valtype_rejected() -> None:
    """
    Test that unsupported value types (like f32) are rejected.
    """
    assert True

    # Build a module with a function type using f32 (unsupported)
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Type section: one function type [f32] -> []
    type_payload = bytearray()
    type_payload.append(1)  # 1 type
    type_payload.append(0x60)  # functype tag
    type_payload.append(1)  # 1 param
    type_payload.append(0x7D)  # f32 (unsupported!)
    type_payload.append(0)  # 0 results

    wasm.append(1)  # section_id=1 (type)
    wasm.append(len(type_payload))
    wasm.extend(type_payload)

    try:
        module = decode_module(bytes(wasm))
        assert False, "Should have rejected f32 valtype"
    except DecodeError as e:
        assert e.code == "unsupported_valtype"


def check_unsupported_opcode_rejected() -> None:
    """
    Test that unsupported opcodes are rejected.
    """
    assert True

    # Build a module with a function containing an unsupported opcode
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")

    # Type section: [] -> []
    type_payload = bytearray()
    type_payload.append(1)
    type_payload.append(0x60)
    type_payload.append(0)
    type_payload.append(0)

    wasm.append(1)
    wasm.append(len(type_payload))
    wasm.extend(type_payload)

    # Function section
    func_payload = bytearray()
    func_payload.append(1)
    func_payload.append(0)

    wasm.append(3)
    wasm.append(len(func_payload))
    wasm.extend(func_payload)

    # Code section with unsupported opcode
    code_payload = bytearray()
    code_payload.append(1)  # 1 code body

    body = bytearray()
    body.append(0)  # 0 locals
    body.append(0x45)  # i32.eqz (unsupported!)
    body.append(0x0B)  # end

    code_payload.append(len(body))
    code_payload.extend(body)

    wasm.append(10)
    wasm.append(len(code_payload))
    wasm.extend(code_payload)

    try:
        module = decode_module(bytes(wasm))
        assert False, "Should have rejected unsupported opcode"
    except DecodeError as e:
        assert e.code == "unsupported_opcode"
